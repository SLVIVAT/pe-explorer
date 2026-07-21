from __future__ import annotations

from dataclasses import FrozenInstanceError
import struct
import unittest
from unittest.mock import patch

from pe.file_analysis import FileAnalyzer, FileHashes
from pe.models import DataDirectory, OptionalHeader, SectionHeader


def _win_certificate(
    payload: bytes = b"",
    *,
    revision: int = 0x0200,
    certificate_type: int = 0x0002,
) -> bytes:
    length = 8 + len(payload)
    record = struct.pack("<IHH", length, revision, certificate_type) + payload
    return record + bytes((-length) % 8)


def _optional_header(
    *,
    pe32_plus: bool = True,
    size_of_headers: int = 0x200,
    certificate_offset: int = 0,
    certificate_size: int = 0,
) -> OptionalHeader:
    directories = tuple(
        DataDirectory(
            index=index,
            name=f"Directory {index}",
            virtual_address=certificate_offset if index == 4 else 0,
            size=certificate_size if index == 4 else 0,
        )
        for index in range(16)
    )
    return OptionalHeader(
        magic=0x20B if pe32_plus else 0x10B,
        format="PE32+" if pe32_plus else "PE32",
        major_linker_version=0,
        minor_linker_version=0,
        size_of_code=0,
        size_of_initialized_data=0,
        size_of_uninitialized_data=0,
        address_of_entry_point=0,
        base_of_code=0,
        base_of_data=None if pe32_plus else 0,
        image_base=0x140000000 if pe32_plus else 0x400000,
        section_alignment=0x1000,
        file_alignment=0x200,
        major_operating_system_version=0,
        minor_operating_system_version=0,
        major_image_version=0,
        minor_image_version=0,
        major_subsystem_version=0,
        minor_subsystem_version=0,
        win32_version_value=0,
        size_of_image=0x2000,
        size_of_headers=size_of_headers,
        checksum=0,
        subsystem=0,
        dll_characteristics=0,
        size_of_stack_reserve=0,
        size_of_stack_commit=0,
        size_of_heap_reserve=0,
        size_of_heap_commit=0,
        loader_flags=0,
        number_of_rva_and_sizes=16,
        data_directories=directories,
    )


def _section(
    *,
    index: int = 1,
    name: str = ".text",
    pointer: int = 0x200,
    raw_size: int = 0x200,
) -> SectionHeader:
    return SectionHeader(
        index=index,
        name=name,
        raw_name=name.encode("ascii")[:8].ljust(8, b"\x00"),
        virtual_size=raw_size,
        virtual_address=0x1000 * index,
        size_of_raw_data=raw_size,
        pointer_to_raw_data=pointer,
        pointer_to_relocations=0,
        pointer_to_linenumbers=0,
        number_of_relocations=0,
        number_of_linenumbers=0,
        characteristics=0x40000040,
    )


class FileAnalyzerTests(unittest.TestCase):
    def test_calculates_all_requested_whole_file_hashes(self) -> None:
        hashes = FileAnalyzer(
            b"abc",
            _optional_header(size_of_headers=3),
            (),
        ).calculate_hashes()

        self.assertEqual(hashes.md5, "900150983cd24fb0d6963f7d28e17f72")
        self.assertEqual(hashes.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d")
        self.assertEqual(
            hashes.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        self.assertEqual(
            hashes.sha512,
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        )

    def test_entropy_labels_low_high_empty_and_truncated_sections(self) -> None:
        data = bytearray(0x610)
        data[0x200:0x300] = bytes(0x100)
        data[0x400:0x500] = bytes(range(256))
        data[0x600:0x610] = b"A" * 0x10
        sections = (
            _section(index=1, name=".low", pointer=0x200, raw_size=0x100),
            _section(index=2, name=".high", pointer=0x400, raw_size=0x100),
            _section(index=3, name=".bss", pointer=0, raw_size=0),
            _section(index=4, name=".short", pointer=0x600, raw_size=0x40),
        )

        results = FileAnalyzer(
            bytes(data),
            _optional_header(),
            sections,
        ).analyze_section_entropy()

        self.assertEqual(results[0].entropy, 0.0)
        self.assertEqual(results[0].color, "green")
        self.assertFalse(results[0].suspicious)
        self.assertEqual(results[1].entropy, 8.0)
        self.assertEqual(results[1].color, "red")
        self.assertTrue(results[1].suspicious)
        self.assertIn("packing", results[1].explanation)
        self.assertIsNone(results[2].entropy)
        self.assertEqual(results[2].color, "gray")
        self.assertEqual(results[3].analyzed_size, 0x10)
        self.assertIn("Only 16 of 64", results[3].explanation)

    def test_entropy_uses_deterministic_aggregate_budget_for_overlaps(self) -> None:
        data = bytes(range(32))
        sections = (
            _section(index=1, pointer=0, raw_size=20),
            _section(index=2, pointer=0, raw_size=20),
            _section(index=3, pointer=0, raw_size=20),
        )
        analyzer = FileAnalyzer(data, _optional_header(size_of_headers=0), sections)

        first_results = analyzer.analyze_section_entropy()
        second_results = analyzer.analyze_section_entropy()

        self.assertEqual(first_results, second_results)
        self.assertEqual(len(first_results), len(sections))
        self.assertEqual(
            tuple(result.analyzed_size for result in first_results),
            (20, 12, 0),
        )
        self.assertEqual(sum(result.analyzed_size for result in first_results), 32)
        self.assertIn("Only 12 of 20 available", first_results[1].explanation)
        self.assertIn("aggregate budget of 32", first_results[1].explanation)
        self.assertIsNone(first_results[2].entropy)
        self.assertEqual(first_results[2].color, "gray")
        self.assertIn("analysis was skipped", first_results[2].explanation.lower())
        self.assertIn("overlapping or duplicated", first_results[2].explanation)

    def test_detects_plain_overlay_and_no_overlay(self) -> None:
        section = _section()
        absent = FileAnalyzer(
            bytes(0x400),
            _optional_header(),
            (section,),
        ).detect_overlay()
        present = FileAnalyzer(
            bytes(0x425),
            _optional_header(),
            (section,),
        ).detect_overlay()

        self.assertFalse(absent.present)
        self.assertFalse(absent.suspicious)
        self.assertEqual(absent.suspicion_level, "None")
        self.assertIsNone(absent.entropy)
        self.assertEqual(absent.total_size, 0)
        self.assertTrue(present.present)
        self.assertTrue(present.suspicious)
        self.assertEqual(present.suspicion_level, "Review")
        self.assertEqual(present.entropy, 0.0)
        self.assertEqual(present.start_offset, 0x400)
        self.assertEqual(present.total_size, 0x25)
        self.assertEqual(present.regions[0].end_offset, 0x425)

    def test_valid_certificate_tail_is_not_overlay_for_both_formats(
        self,
    ) -> None:
        certificate = _win_certificate(bytes(0x38))
        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus):
                result = FileAnalyzer(
                    bytes(0x400) + certificate,
                    _optional_header(
                        pe32_plus=pe32_plus,
                        certificate_offset=0x400,
                        certificate_size=len(certificate),
                    ),
                    (_section(),),
                ).detect_overlay()

                self.assertFalse(result.present)
                self.assertEqual(result.suspicion_level, "None")
                self.assertTrue(result.certificate_valid)
                self.assertEqual(result.certificate_offset, 0x400)
                self.assertIn("Certificate Table", result.explanation)

    def test_preserves_overlay_regions_before_and_after_certificate(self) -> None:
        certificate = _win_certificate(bytes(0x38))
        result = FileAnalyzer(
            bytes(0x420) + certificate + bytes(0x10),
            _optional_header(
                certificate_offset=0x420,
                certificate_size=len(certificate),
            ),
            (_section(),),
        ).detect_overlay()

        self.assertTrue(result.present)
        self.assertEqual(result.suspicion_level, "Review")
        self.assertTrue(result.certificate_valid)
        self.assertEqual(result.total_size, 0x30)
        self.assertEqual(
            tuple((region.file_offset, region.size) for region in result.regions),
            ((0x400, 0x20), (0x460, 0x10)),
        )

    def test_invalid_certificate_range_is_counted_as_overlay(self) -> None:
        result = FileAnalyzer(
            bytes(0x450),
            _optional_header(
                certificate_offset=0x430,
                certificate_size=0x80,
            ),
            (_section(),),
        ).detect_overlay()

        self.assertTrue(result.present)
        self.assertFalse(result.certificate_valid)
        self.assertEqual(result.total_size, 0x50)
        self.assertIn("was not excluded", result.explanation)

    def test_accepts_complete_aligned_certificate_record_sequence(self) -> None:
        certificate = _win_certificate(
            b"A",
            revision=0x0100,
            certificate_type=0x0001,
        ) + _win_certificate(b"B" * 8)
        result = FileAnalyzer(
            bytes(0x400) + certificate,
            _optional_header(
                certificate_offset=0x400,
                certificate_size=len(certificate),
            ),
            (_section(),),
        ).detect_overlay()

        self.assertTrue(result.certificate_valid)
        self.assertFalse(result.present)

    def test_malformed_certificate_tables_remain_overlay(self) -> None:
        malformed_tables = {
            "length below header": struct.pack("<IHH", 7, 0x0200, 0x0002),
            "implausible revision": struct.pack("<IHH", 8, 0x0300, 0x0002),
            "implausible type": struct.pack("<IHH", 8, 0x0200, 0),
            "record exceeds range": struct.pack("<IHH", 24, 0x0200, 0x0002)
            + bytes(8),
            "missing alignment padding": struct.pack(
                "<IHH", 9, 0x0200, 0x0002
            )
            + b"A",
            "invalid trailing record": _win_certificate() + bytes(8),
        }

        for label, certificate in malformed_tables.items():
            with self.subTest(label=label):
                result = FileAnalyzer(
                    bytes(0x400) + certificate,
                    _optional_header(
                        certificate_offset=0x400,
                        certificate_size=len(certificate),
                    ),
                    (_section(),),
                ).detect_overlay()

                self.assertFalse(result.certificate_valid)
                self.assertTrue(result.present)
                self.assertEqual(result.total_size, len(certificate))
                self.assertIn("structurally valid", result.explanation)

    def test_unaligned_certificate_table_remains_overlay(self) -> None:
        certificate = _win_certificate(bytes(8))
        result = FileAnalyzer(
            bytes(0x404) + certificate,
            _optional_header(
                certificate_offset=0x404,
                certificate_size=len(certificate),
            ),
            (_section(),),
        ).detect_overlay()

        self.assertFalse(result.certificate_valid)
        self.assertTrue(result.present)
        self.assertEqual(result.total_size, 4 + len(certificate))

    def test_certificate_record_sequence_is_bounded(self) -> None:
        certificate = _win_certificate() + _win_certificate()
        analyzer = FileAnalyzer(
            bytes(0x400) + certificate,
            _optional_header(
                certificate_offset=0x400,
                certificate_size=len(certificate),
            ),
            (_section(),),
        )

        with patch("pe.file_analysis._MAX_CERTIFICATE_RECORDS", 1):
            result = analyzer.detect_overlay()

        self.assertFalse(result.certificate_valid)
        self.assertTrue(result.present)

    def test_high_entropy_overlay_is_high_suspicion(self) -> None:
        data = bytearray(0x500)
        data[0x400:0x500] = bytes(range(256))

        result = FileAnalyzer(
            bytes(data),
            _optional_header(),
            (_section(),),
        ).detect_overlay()

        self.assertTrue(result.suspicious)
        self.assertEqual(result.suspicion_level, "High")
        self.assertEqual(result.entropy, 8.0)
        self.assertIn("entropy is 8.000", result.explanation)

    def test_composite_models_are_immutable_and_convert_to_dicts(self) -> None:
        analysis = FileAnalyzer(
            bytes(0x400),
            _optional_header(),
            (_section(),),
        ).analyze()

        result = analysis.to_dict()
        self.assertEqual(set(result), {"hashes", "sections", "overlay"})
        self.assertEqual(set(result["hashes"]), {"md5", "sha1", "sha256", "sha512"})
        with self.assertRaises(FrozenInstanceError):
            analysis.hashes = FileHashes("", "", "", "")  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
