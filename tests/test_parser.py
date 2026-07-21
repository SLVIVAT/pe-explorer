from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from typing import Any

from pe.constants import DATA_DIRECTORY_NAMES
from pe.parser import PEFormatError, PEParser


PE_OFFSET = 0x80
COFF_OFFSET = PE_OFFSET + 4
OPTIONAL_HEADER_OFFSET = COFF_OFFSET + 20
PE32_FIXED_SIZE = 96
PE32_PLUS_FIXED_SIZE = 112
DATA_DIRECTORY_COUNT = 16
PE32_OPTIONAL_HEADER_SIZE = PE32_FIXED_SIZE + DATA_DIRECTORY_COUNT * 8
PE32_PLUS_OPTIONAL_HEADER_SIZE = PE32_PLUS_FIXED_SIZE + DATA_DIRECTORY_COUNT * 8
FIXTURE_FILE_SIZE = 0x1000

DIRECTORY_VALUES = tuple(
    (0, 0) if index in {0, 2} else (0x1100 + index * 0x40, 0x20 + index)
    for index in range(DATA_DIRECTORY_COUNT)
)

COMMON_OPTIONAL_VALUES: dict[str, int] = {
    "major_linker_version": 14,
    "minor_linker_version": 37,
    "size_of_code": 0x600,
    "size_of_initialized_data": 0x200,
    "size_of_uninitialized_data": 0x100,
    "address_of_entry_point": 0x1010,
    "base_of_code": 0x1000,
    "section_alignment": 0x1000,
    "file_alignment": 0x200,
    "major_operating_system_version": 6,
    "minor_operating_system_version": 1,
    "major_image_version": 2,
    "minor_image_version": 3,
    "major_subsystem_version": 6,
    "minor_subsystem_version": 2,
    "win32_version_value": 0,
    "size_of_image": 0x3000,
    "size_of_headers": 0x400,
    "checksum": 0x89ABCDEF,
    "subsystem": 3,
    "dll_characteristics": 0x8160,
    "loader_flags": 0x10203040,
    "number_of_rva_and_sizes": DATA_DIRECTORY_COUNT,
}

PE32_SPECIFIC_VALUES: dict[str, int | None | str] = {
    "magic": 0x10B,
    "format": "PE32",
    "base_of_data": 0x2000,
    "image_base": 0x00400000,
    "size_of_stack_reserve": 0x00100000,
    "size_of_stack_commit": 0x00001000,
    "size_of_heap_reserve": 0x00200000,
    "size_of_heap_commit": 0x00002000,
}

PE32_PLUS_SPECIFIC_VALUES: dict[str, int | None | str] = {
    "magic": 0x20B,
    "format": "PE32+",
    "base_of_data": None,
    "image_base": 0x0000000140000000,
    "size_of_stack_reserve": 0x0000000200000001,
    "size_of_stack_commit": 0x0000000300000002,
    "size_of_heap_reserve": 0x0000000400000003,
    "size_of_heap_commit": 0x0000000500000004,
}

SECTION_VALUES: tuple[dict[str, int | str | bytes], ...] = (
    {
        "name": ".text",
        "raw_name": b".text\x00\x00\x00",
        "virtual_size": 0x580,
        "virtual_address": 0x1000,
        "size_of_raw_data": 0x600,
        "pointer_to_raw_data": 0x400,
        "pointer_to_relocations": 0xC00,
        "pointer_to_linenumbers": 0xC40,
        "number_of_relocations": 3,
        "number_of_linenumbers": 4,
        "characteristics": 0x60000020,
    },
    {
        "name": "DATASECT",
        "raw_name": b"DATASECT",
        "virtual_size": 0x180,
        "virtual_address": 0x2000,
        "size_of_raw_data": 0x200,
        "pointer_to_raw_data": 0xA00,
        "pointer_to_relocations": 0xC80,
        "pointer_to_linenumbers": 0xCC0,
        "number_of_relocations": 5,
        "number_of_linenumbers": 6,
        "characteristics": 0xC0000040,
    },
)


def _optional_header_size(pe32_plus: bool, extra_size: int = 0) -> int:
    standard_size = (
        PE32_PLUS_OPTIONAL_HEADER_SIZE
        if pe32_plus
        else PE32_OPTIONAL_HEADER_SIZE
    )
    return standard_size + extra_size


def _section_table_offset(pe32_plus: bool, extra_size: int = 0) -> int:
    return OPTIONAL_HEADER_OFFSET + _optional_header_size(
        pe32_plus,
        extra_size,
    )


def _pack_common_optional_fields(image: bytearray, offset: int) -> None:
    struct.pack_into("<BB", image, offset + 2, 14, 37)
    struct.pack_into("<I", image, offset + 4, 0x600)
    struct.pack_into("<I", image, offset + 8, 0x200)
    struct.pack_into("<I", image, offset + 12, 0x100)
    struct.pack_into("<I", image, offset + 16, 0x1010)
    struct.pack_into("<I", image, offset + 20, 0x1000)
    struct.pack_into("<I", image, offset + 32, 0x1000)
    struct.pack_into("<I", image, offset + 36, 0x200)
    struct.pack_into("<HHHHHH", image, offset + 40, 6, 1, 2, 3, 6, 2)
    struct.pack_into("<I", image, offset + 52, 0)
    struct.pack_into("<I", image, offset + 56, 0x3000)
    struct.pack_into("<I", image, offset + 60, 0x400)
    struct.pack_into("<I", image, offset + 64, 0x89ABCDEF)
    struct.pack_into("<H", image, offset + 68, 3)
    struct.pack_into("<H", image, offset + 70, 0x8160)


def _pack_pe32_optional_header(
    image: bytearray,
    directory_count: int,
) -> None:
    offset = OPTIONAL_HEADER_OFFSET
    struct.pack_into("<H", image, offset, 0x10B)
    _pack_common_optional_fields(image, offset)
    struct.pack_into("<I", image, offset + 24, 0x2000)
    struct.pack_into("<I", image, offset + 28, 0x00400000)
    struct.pack_into("<I", image, offset + 72, 0x00100000)
    struct.pack_into("<I", image, offset + 76, 0x00001000)
    struct.pack_into("<I", image, offset + 80, 0x00200000)
    struct.pack_into("<I", image, offset + 84, 0x00002000)
    struct.pack_into("<I", image, offset + 88, 0x10203040)
    struct.pack_into("<I", image, offset + 92, directory_count)

    for index, (virtual_address, size) in enumerate(DIRECTORY_VALUES):
        struct.pack_into(
            "<II",
            image,
            offset + PE32_FIXED_SIZE + index * 8,
            virtual_address,
            size,
        )


def _pack_pe32_plus_optional_header(
    image: bytearray,
    directory_count: int,
) -> None:
    offset = OPTIONAL_HEADER_OFFSET
    struct.pack_into("<H", image, offset, 0x20B)
    _pack_common_optional_fields(image, offset)
    struct.pack_into("<Q", image, offset + 24, 0x0000000140000000)
    struct.pack_into("<Q", image, offset + 72, 0x0000000200000001)
    struct.pack_into("<Q", image, offset + 80, 0x0000000300000002)
    struct.pack_into("<Q", image, offset + 88, 0x0000000400000003)
    struct.pack_into("<Q", image, offset + 96, 0x0000000500000004)
    struct.pack_into("<I", image, offset + 104, 0x10203040)
    struct.pack_into("<I", image, offset + 108, directory_count)

    for index, (virtual_address, size) in enumerate(DIRECTORY_VALUES):
        struct.pack_into(
            "<II",
            image,
            offset + PE32_PLUS_FIXED_SIZE + index * 8,
            virtual_address,
            size,
        )


def build_pe_fixture(
    *,
    pe32_plus: bool,
    directory_count: int = DATA_DIRECTORY_COUNT,
    optional_header_extra_size: int = 0,
) -> bytes:
    """Build a deterministic, self-contained PE image for parser tests."""
    image = bytearray(FIXTURE_FILE_SIZE)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, PE_OFFSET)
    image[PE_OFFSET:PE_OFFSET + 4] = b"PE\x00\x00"

    machine = 0x8664 if pe32_plus else 0x014C
    characteristics = 0x0022 if pe32_plus else 0x010F
    struct.pack_into(
        "<HHIIIHH",
        image,
        COFF_OFFSET,
        machine,
        len(SECTION_VALUES),
        0x5E2A5C00,
        0xE00,
        2,
        _optional_header_size(pe32_plus, optional_header_extra_size),
        characteristics,
    )

    if pe32_plus:
        _pack_pe32_plus_optional_header(image, directory_count)
    else:
        _pack_pe32_optional_header(image, directory_count)

    section_offset = _section_table_offset(
        pe32_plus,
        optional_header_extra_size,
    )
    for index, section in enumerate(SECTION_VALUES):
        struct.pack_into(
            "<8sIIIIIIHHI",
            image,
            section_offset + index * 40,
            section["raw_name"],
            section["virtual_size"],
            section["virtual_address"],
            section["size_of_raw_data"],
            section["pointer_to_raw_data"],
            section["pointer_to_relocations"],
            section["pointer_to_linenumbers"],
            section["number_of_relocations"],
            section["number_of_linenumbers"],
            section["characteristics"],
        )

    return bytes(image)


class PEParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self._file_index = 0

    def _write_fixture(
        self,
        data: bytes | bytearray,
        file_name: str | None = None,
    ) -> Path:
        self._file_index += 1
        name = file_name or f"fixture-{self._file_index}.exe"
        path = Path(self._temporary_directory.name) / name
        path.write_bytes(data)
        return path

    def _parse(
        self,
        data: bytes | bytearray,
        file_name: str | None = None,
    ) -> dict[str, Any]:
        path = self._write_fixture(data, file_name)
        return PEParser(str(path)).parse()

    def _assert_mapping_contains(
        self,
        actual: dict[str, Any],
        expected: dict[str, Any],
    ) -> None:
        for key, value in expected.items():
            with self.subTest(field=key):
                self.assertIn(key, actual)
                self.assertEqual(actual[key], value)

    def _assert_data_directories(
        self,
        optional_header: dict[str, Any],
        count: int,
    ) -> None:
        directories = optional_header["data_directories"]
        self.assertEqual(len(directories), count)

        for index, directory in enumerate(directories):
            virtual_address, size = DIRECTORY_VALUES[index]
            with self.subTest(directory=index):
                self.assertEqual(directory["index"], index)
                self.assertEqual(directory["name"], DATA_DIRECTORY_NAMES[index])
                self.assertEqual(directory["virtual_address"], virtual_address)
                self.assertEqual(directory["size"], size)

    def _assert_sections(self, sections: list[dict[str, Any]]) -> None:
        self.assertEqual(len(sections), len(SECTION_VALUES))
        for index, expected in enumerate(SECTION_VALUES):
            with self.subTest(section=index):
                self.assertEqual(sections[index]["index"], index + 1)
                self._assert_mapping_contains(sections[index], expected)

    def _assert_common_result(
        self,
        result: dict[str, Any],
        *,
        file_name: str,
        pe32_plus: bool,
        optional_header_extra_size: int = 0,
    ) -> None:
        optional_size = _optional_header_size(
            pe32_plus,
            optional_header_extra_size,
        )
        machine_value = 0x8664 if pe32_plus else 0x014C
        machine_name = "x64" if pe32_plus else "Intel 386"
        characteristics = 0x0022 if pe32_plus else 0x010F

        self._assert_mapping_contains(
            result,
            {
                "file_name": file_name,
                "file_path": str(
                    Path(self._temporary_directory.name) / file_name
                ),
                "file_size": FIXTURE_FILE_SIZE,
                "mz_signature": "MZ",
                "pe_offset": PE_OFFSET,
                "pe_signature": "PE",
                "machine": machine_name,
                "number_of_sections": len(SECTION_VALUES),
                "timestamp": 0x5E2A5C00,
                "pointer_to_symbol_table": 0xE00,
                "number_of_symbols": 2,
                "optional_header_size": optional_size,
                "characteristics": characteristics,
            },
        )
        self._assert_mapping_contains(
            result["coff_header"],
            {
                "machine": machine_value,
                "number_of_sections": len(SECTION_VALUES),
                "timestamp": 0x5E2A5C00,
                "pointer_to_symbol_table": 0xE00,
                "number_of_symbols": 2,
                "optional_header_size": optional_size,
                "characteristics": characteristics,
            },
        )

    def test_parses_every_pe32_optional_header_and_section_field(self) -> None:
        file_name = "complete-pe32.exe"
        result = self._parse(
            build_pe_fixture(pe32_plus=False),
            file_name,
        )

        self._assert_common_result(
            result,
            file_name=file_name,
            pe32_plus=False,
        )
        expected_optional = {
            **COMMON_OPTIONAL_VALUES,
            **PE32_SPECIFIC_VALUES,
        }
        self._assert_mapping_contains(result["optional_header"], expected_optional)
        self._assert_data_directories(
            result["optional_header"],
            DATA_DIRECTORY_COUNT,
        )
        self._assert_sections(result["sections"])

    def test_parses_every_pe32_plus_optional_header_and_section_field(self) -> None:
        file_name = "complete-pe32-plus.exe"
        result = self._parse(
            build_pe_fixture(pe32_plus=True),
            file_name,
        )

        self._assert_common_result(
            result,
            file_name=file_name,
            pe32_plus=True,
        )
        expected_optional = {
            **COMMON_OPTIONAL_VALUES,
            **PE32_PLUS_SPECIFIC_VALUES,
        }
        self._assert_mapping_contains(result["optional_header"], expected_optional)
        self._assert_data_directories(
            result["optional_header"],
            DATA_DIRECTORY_COUNT,
        )
        self._assert_sections(result["sections"])

    def test_honors_number_of_rva_and_sizes(self) -> None:
        for pe32_plus in (False, True):
            for count in (0, 2):
                with self.subTest(pe32_plus=pe32_plus, count=count):
                    result = self._parse(
                        build_pe_fixture(
                            pe32_plus=pe32_plus,
                            directory_count=count,
                        )
                    )
                    optional_header = result["optional_header"]
                    self.assertEqual(
                        optional_header["number_of_rva_and_sizes"],
                        count,
                    )
                    self._assert_data_directories(optional_header, count)

    def test_section_table_starts_after_declared_optional_header_size(self) -> None:
        extra_size = 16
        result = self._parse(
            build_pe_fixture(
                pe32_plus=False,
                optional_header_extra_size=extra_size,
            ),
            "extended-optional-header.exe",
        )

        self._assert_common_result(
            result,
            file_name="extended-optional-header.exe",
            pe32_plus=False,
            optional_header_extra_size=extra_size,
        )
        self._assert_sections(result["sections"])

    def test_accepts_compact_optional_headers(self) -> None:
        for pe32_plus in (False, True):
            fixed_size = PE32_PLUS_FIXED_SIZE if pe32_plus else PE32_FIXED_SIZE
            standard_size = _optional_header_size(pe32_plus)
            for directory_count in (0, 2):
                compact_size = fixed_size + directory_count * 8
                with self.subTest(
                    pe32_plus=pe32_plus,
                    directory_count=directory_count,
                ):
                    result = self._parse(
                        build_pe_fixture(
                            pe32_plus=pe32_plus,
                            directory_count=directory_count,
                            optional_header_extra_size=(
                                compact_size - standard_size
                            ),
                        )
                    )
                    self.assertEqual(
                        result["optional_header_size"],
                        compact_size,
                    )
                    self._assert_data_directories(
                        result["optional_header"],
                        directory_count,
                    )
                    self._assert_sections(result["sections"])

    def test_decodes_utf8_section_names_without_losing_raw_bytes(self) -> None:
        image = bytearray(build_pe_fixture(pe32_plus=False))
        raw_name = "séct".encode("utf-8").ljust(8, b"\x00")
        section_offset = _section_table_offset(False)
        image[section_offset:section_offset + 8] = raw_name

        section = self._parse(image)["sections"][0]

        self.assertEqual(section["name"], "séct")
        self.assertEqual(section["raw_name"], raw_name)

    def test_unknown_machine_keeps_numeric_coff_value_and_fallback_name(self) -> None:
        image = bytearray(build_pe_fixture(pe32_plus=False))
        struct.pack_into("<H", image, COFF_OFFSET, 0x9999)

        result = self._parse(image)

        self.assertEqual(result["coff_header"]["machine"], 0x9999)
        self.assertEqual(result["machine"], "Unknown (0x9999)")

    def test_missing_file_raises_file_not_found_error(self) -> None:
        missing_path = Path(self._temporary_directory.name) / "missing.exe"

        with self.assertRaises(FileNotFoundError):
            PEParser(str(missing_path)).parse()

    def test_rejects_file_smaller_than_dos_header(self) -> None:
        with self.assertRaises(PEFormatError):
            self._parse(b"MZ" + bytes(61))

    def test_rejects_invalid_dos_signature(self) -> None:
        image = bytearray(build_pe_fixture(pe32_plus=False))
        image[:2] = b"NZ"

        with self.assertRaises(PEFormatError):
            self._parse(image)

    def test_rejects_pe_offset_at_or_beyond_end_of_file(self) -> None:
        for pe_offset in (FIXTURE_FILE_SIZE, FIXTURE_FILE_SIZE + 1):
            with self.subTest(pe_offset=pe_offset):
                image = bytearray(build_pe_fixture(pe32_plus=False))
                struct.pack_into("<I", image, 0x3C, pe_offset)

                with self.assertRaises(PEFormatError):
                    self._parse(image)

    def test_rejects_truncated_pe_signature(self) -> None:
        image = build_pe_fixture(pe32_plus=False)[:PE_OFFSET + 3]

        with self.assertRaises(PEFormatError):
            self._parse(image)

    def test_rejects_invalid_pe_signature(self) -> None:
        image = bytearray(build_pe_fixture(pe32_plus=False))
        image[PE_OFFSET:PE_OFFSET + 4] = b"PX\x00\x00"

        with self.assertRaises(PEFormatError):
            self._parse(image)

    def test_rejects_truncated_coff_header_without_leaking_struct_error(self) -> None:
        image = build_pe_fixture(pe32_plus=False)[:COFF_OFFSET + 19]

        with self.assertRaises(PEFormatError):
            self._parse(image)

    def test_rejects_optional_header_without_complete_magic(self) -> None:
        image = bytearray(build_pe_fixture(pe32_plus=False))
        struct.pack_into("<H", image, COFF_OFFSET + 16, 1)

        with self.assertRaises(PEFormatError):
            self._parse(image)

    def test_rejects_unsupported_optional_header_magic(self) -> None:
        image = bytearray(build_pe_fixture(pe32_plus=False))
        struct.pack_into("<H", image, OPTIONAL_HEADER_OFFSET, 0x107)

        with self.assertRaises(PEFormatError):
            self._parse(image)

    def test_rejects_declared_optional_header_smaller_than_fixed_fields(self) -> None:
        cases = (
            (False, PE32_FIXED_SIZE - 1),
            (True, PE32_PLUS_FIXED_SIZE - 1),
        )
        for pe32_plus, declared_size in cases:
            with self.subTest(
                pe32_plus=pe32_plus,
                declared_size=declared_size,
            ):
                image = bytearray(build_pe_fixture(pe32_plus=pe32_plus))
                struct.pack_into("<H", image, COFF_OFFSET + 16, declared_size)

                with self.assertRaises(PEFormatError):
                    self._parse(image)

    def test_rejects_file_truncated_inside_declared_optional_header(self) -> None:
        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus):
                end = OPTIONAL_HEADER_OFFSET + _optional_header_size(pe32_plus) - 1
                image = build_pe_fixture(pe32_plus=pe32_plus)[:end]

                with self.assertRaises(PEFormatError):
                    self._parse(image)

    def test_rejects_directory_count_exceeding_declared_optional_header(self) -> None:
        cases = (
            (False, PE32_FIXED_SIZE),
            (True, PE32_PLUS_FIXED_SIZE),
        )
        for pe32_plus, fixed_size in cases:
            with self.subTest(pe32_plus=pe32_plus):
                image = bytearray(build_pe_fixture(pe32_plus=pe32_plus))
                struct.pack_into("<H", image, COFF_OFFSET + 16, fixed_size + 8)

                with self.assertRaises(PEFormatError):
                    self._parse(image)

    def test_rejects_more_than_sixteen_directories_in_standard_header(self) -> None:
        for pe32_plus, count_offset in (
            (False, OPTIONAL_HEADER_OFFSET + 92),
            (True, OPTIONAL_HEADER_OFFSET + 108),
        ):
            with self.subTest(pe32_plus=pe32_plus):
                image = bytearray(build_pe_fixture(pe32_plus=pe32_plus))
                struct.pack_into("<I", image, count_offset, 17)

                with self.assertRaises(PEFormatError):
                    self._parse(image)

    def test_rejects_optional_header_size_extending_beyond_file(self) -> None:
        image = bytearray(build_pe_fixture(pe32_plus=False))
        struct.pack_into("<H", image, COFF_OFFSET + 16, 0xFFFF)

        with self.assertRaises(PEFormatError):
            self._parse(image)

    def test_rejects_truncated_section_table(self) -> None:
        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus):
                section_end = (
                    _section_table_offset(pe32_plus)
                    + len(SECTION_VALUES) * 40
                    - 1
                )
                image = build_pe_fixture(pe32_plus=pe32_plus)[:section_end]

                with self.assertRaises(PEFormatError):
                    self._parse(image)

    def test_rejects_section_count_exceeding_available_table_entries(self) -> None:
        image = bytearray(build_pe_fixture(pe32_plus=False))
        struct.pack_into("<H", image, COFF_OFFSET + 2, 3)
        table_end = _section_table_offset(False) + len(SECTION_VALUES) * 40

        with self.assertRaises(PEFormatError):
            self._parse(image[:table_end])


if __name__ == "__main__":
    unittest.main()
