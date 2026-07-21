from __future__ import annotations

from collections.abc import Iterator
from dataclasses import FrozenInstanceError
import unittest

from pe.addressing import AddressingService
from pe.models import OptionalHeader, SectionHeader
from pe.strings import (
    ExtractedString,
    StringExtractionResult,
    StringExtractor,
    extract_strings,
)


def _mapper(file_size: int) -> AddressingService:
    header = OptionalHeader(
        magic=0x10B,
        format="PE32",
        major_linker_version=0,
        minor_linker_version=0,
        size_of_code=0,
        size_of_initialized_data=0,
        size_of_uninitialized_data=0,
        address_of_entry_point=0,
        base_of_code=0,
        base_of_data=0,
        image_base=0x400000,
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
        size_of_headers=0x10,
        checksum=0,
        subsystem=0,
        dll_characteristics=0,
        size_of_stack_reserve=0,
        size_of_stack_commit=0,
        size_of_heap_reserve=0,
        size_of_heap_commit=0,
        loader_flags=0,
        number_of_rva_and_sizes=0,
        data_directories=(),
    )
    section = SectionHeader(
        index=1,
        name=".rdata",
        raw_name=b".rdata\x00\x00",
        virtual_size=max(file_size - 0x10, 1),
        virtual_address=0x1000,
        size_of_raw_data=max(file_size - 0x10, 1),
        pointer_to_raw_data=0x10,
        pointer_to_relocations=0,
        pointer_to_linenumbers=0,
        number_of_relocations=0,
        number_of_linenumbers=0,
        characteristics=0x40000040,
    )
    return AddressingService(header, (section,), file_size=file_size)


class StringExtractorTests(unittest.TestCase):
    def test_extracts_ascii_and_utf16le_with_exact_offsets(self) -> None:
        data = b"\x00Hello.exe\x00--\x00W\x00o\x00r\x00l\x00d\x00\x00"

        strings = StringExtractor(data, minimum_length=5).extract()

        self.assertEqual(
            strings,
            (
                ExtractedString(1, None, 9, "ASCII", "Hello.exe", None, 9),
                ExtractedString(14, None, 5, "UTF-16LE", "World", None, 10),
            ),
        )

    def test_minimum_length_and_encoding_filters_are_honored(self) -> None:
        data = b"abc\x00abcd\x00A\x00B\x00C\x00\x00D\x00E\x00F\x00G\x00"
        extractor = StringExtractor(data, minimum_length=4)

        self.assertEqual(
            tuple(item.value for item in extractor.extract_ascii()),
            ("abcd",),
        )
        self.assertEqual(
            tuple(item.value for item in extractor.extract_utf16le()),
            ("DEFG",),
        )
        self.assertEqual(
            extractor.extract(include_ascii=False, include_utf16le=False),
            (),
        )

    def test_limited_extraction_keeps_global_order_and_exact_metadata(
        self,
    ) -> None:
        values = (
            ("WideFirst", "UTF-16LE"),
            ("AsciiMiddle", "ASCII"),
            ("WideLater", "UTF-16LE"),
            ("AsciiLast", "ASCII"),
        )
        data = (
            "WideFirst".encode("utf-16le")
            + b"\x00\x00AsciiMiddle\x00"
            + "WideLater".encode("utf-16le")
            + b"\x00\x00AsciiLast\x00"
        )
        extractor = StringExtractor(data, minimum_length=5)

        unlimited = extractor.extract_result()
        self.assertEqual(
            tuple((item.value, item.encoding) for item in unlimited.strings),
            values,
        )
        self.assertFalse(unlimited.truncated)
        self.assertIsNone(unlimited.limit)

        limited = extractor.extract_result(maximum_strings=3)
        self.assertEqual(limited.strings, unlimited.strings[:3])
        self.assertTrue(limited.truncated)
        self.assertEqual(limited.limit, 3)
        self.assertEqual(
            extractor.extract(maximum_strings=3),
            limited.strings,
        )

        exact = extractor.extract_result(maximum_strings=4)
        self.assertEqual(exact.strings, unlimited.strings)
        self.assertFalse(exact.truncated)
        self.assertEqual(exact.limit, 4)

        empty = extractor.extract_result(maximum_strings=0)
        self.assertEqual(empty.strings, ())
        self.assertTrue(empty.truncated)
        self.assertEqual(empty.limit, 0)

    def test_limited_merge_does_not_materialize_complete_scanner_results(
        self,
    ) -> None:
        class ProbeExtractor(StringExtractor):
            def __init__(self) -> None:
                super().__init__(b"", minimum_length=1)
                self.ascii_offsets: list[int] = []
                self.utf16_offsets: list[int] = []

            def _iter_ascii(self) -> Iterator[ExtractedString]:
                for offset in range(0, 10_000, 2):
                    self.ascii_offsets.append(offset)
                    yield ExtractedString(
                        offset,
                        None,
                        1,
                        "ASCII",
                        "A",
                        None,
                        1,
                    )

            def _iter_utf16le(self) -> Iterator[ExtractedString]:
                for offset in range(1, 10_000, 2):
                    self.utf16_offsets.append(offset)
                    yield ExtractedString(
                        offset,
                        None,
                        1,
                        "UTF-16LE",
                        "W",
                        None,
                        2,
                    )

        extractor = ProbeExtractor()
        result = extractor.extract_result(maximum_strings=3)

        self.assertEqual(tuple(item.offset for item in result.strings), (0, 1, 2))
        self.assertTrue(result.truncated)
        # The merge reads only enough candidates to return three and prove a
        # fourth exists; neither 5,000-element source is materialized.
        self.assertLessEqual(len(extractor.ascii_offsets), 3)
        self.assertLessEqual(len(extractor.utf16_offsets), 2)

    def test_unlimited_api_and_convenience_wrapper_remain_compatible(self) -> None:
        data = b"FirstAscii\x00" + "WideValue".encode("utf-16le") + b"\x00\x00"
        extractor = StringExtractor(data, minimum_length=5)
        expected = tuple(
            sorted(
                extractor.extract_ascii() + extractor.extract_utf16le(),
                key=lambda item: (item.offset, item.encoding),
            )
        )

        self.assertEqual(extractor.extract(), expected)
        self.assertEqual(extract_strings(data, minimum_length=5), expected)
        self.assertEqual(
            extract_strings(data, minimum_length=5, maximum_strings=1),
            expected[:1],
        )

    def test_utf16le_matches_at_odd_file_offsets(self) -> None:
        data = b"\x01" + "OddOffset".encode("utf-16le") + b"\x00\x00"

        strings = extract_strings(
            data,
            minimum_length=9,
            include_ascii=False,
        )

        self.assertEqual(len(strings), 1)
        self.assertEqual(strings[0].offset, 1)
        self.assertEqual(strings[0].value, "OddOffset")

    def test_optional_mapper_adds_rva_and_section_context(self) -> None:
        data = bytes(0x12) + b"MappedString\x00"

        result = StringExtractor(
            data,
            minimum_length=6,
            mapper=_mapper(len(data)),
        ).extract_ascii()[0]

        self.assertEqual(result.offset, 0x12)
        self.assertEqual(result.rva, 0x1002)
        self.assertEqual(result.section, ".rdata")

    def test_results_are_immutable_and_convert_to_plain_dictionaries(self) -> None:
        result = ExtractedString(
            offset=0x120,
            rva=0x1020,
            length=12,
            encoding="ASCII",
            value="kernel32.dll",
            section=".rdata",
            byte_length=12,
        )

        self.assertEqual(
            result.to_dict(),
            {
                "offset": 0x120,
                "rva": 0x1020,
                "length": 12,
                "encoding": "ASCII",
                "value": "kernel32.dll",
                "section": ".rdata",
                "byte_length": 12,
            },
        )
        with self.assertRaises(FrozenInstanceError):
            result.value = "changed"  # type: ignore[misc]

    def test_rejects_invalid_minimum_lengths(self) -> None:
        for value in (0, -1):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "positive"):
                    StringExtractor(b"data", value)

        for value in (True, 3.5, "4"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(TypeError, "integer"):
                    StringExtractor(b"data", value)  # type: ignore[arg-type]

    def test_rejects_invalid_maximum_string_limits(self) -> None:
        extractor = StringExtractor(b"One\x00Two\x00", minimum_length=3)

        with self.assertRaisesRegex(ValueError, "cannot be negative"):
            extractor.extract(maximum_strings=-1)
        for value in (True, 1.5, "2"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(TypeError, "integer or None"):
                    extractor.extract_result(
                        maximum_strings=value,  # type: ignore[arg-type]
                    )

        result = extractor.extract_result(
            include_ascii=False,
            include_utf16le=False,
            maximum_strings=0,
        )
        self.assertEqual(
            result,
            StringExtractionResult((), False, 0),
        )

    def test_pathological_runs_are_split_into_bounded_contiguous_records(
        self,
    ) -> None:
        ascii_data = b"A" * 101
        ascii_results = StringExtractor(
            ascii_data,
            minimum_length=4,
            maximum_string_bytes=32,
        ).extract_ascii()
        self.assertGreater(len(ascii_results), 1)
        self.assertTrue(all(item.byte_length <= 32 for item in ascii_results))
        self.assertEqual("".join(item.value for item in ascii_results), "A" * 101)
        self.assertEqual(
            tuple(item.offset for item in ascii_results),
            tuple(
                sum(item.byte_length for item in ascii_results[:index])
                for index in range(len(ascii_results))
            ),
        )

        wide_text = "W" * 53
        wide_results = StringExtractor(
            wide_text.encode("utf-16le"),
            minimum_length=4,
            maximum_string_bytes=32,
        ).extract_utf16le()
        self.assertGreater(len(wide_results), 1)
        self.assertTrue(all(item.byte_length <= 32 for item in wide_results))
        self.assertEqual("".join(item.value for item in wide_results), wide_text)
        self.assertTrue(
            all(item.length >= 4 for item in (*ascii_results, *wide_results))
        )

    def test_string_byte_limit_can_be_disabled_and_is_validated(self) -> None:
        data = b"Z" * 100
        unlimited = StringExtractor(
            data,
            maximum_string_bytes=None,
        )
        self.assertIsNone(unlimited.maximum_string_bytes)
        self.assertEqual(len(unlimited.extract_ascii()), 1)

        with self.assertRaisesRegex(ValueError, "four times"):
            StringExtractor(data, minimum_length=4, maximum_string_bytes=15)
        for value in (True, 1.5, "64"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(TypeError, "integer or None"):
                    StringExtractor(
                        data,
                        maximum_string_bytes=value,  # type: ignore[arg-type]
                    )


if __name__ == "__main__":
    unittest.main()
