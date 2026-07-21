from __future__ import annotations

from dataclasses import replace
import struct
import tempfile
import unittest
from pathlib import Path

from pe.constants import DATA_DIRECTORY_NAMES
from pe.directories import resolve_data_directory_statuses
from pe.models import DataDirectory, OptionalHeader, PEImage
from pe.parser import PEParser
from tests.test_parser import (
    OPTIONAL_HEADER_OFFSET,
    PE32_FIXED_SIZE,
    PE32_PLUS_FIXED_SIZE,
    build_pe_fixture,
)


CERTIFICATE_DIRECTORY_INDEX = 4
ARCHITECTURE_DIRECTORY_INDEX = 7
GLOBAL_POINTER_DIRECTORY_INDEX = 8


def _directory_entry_offset(pe32_plus: bool, index: int) -> int:
    fixed_size = PE32_PLUS_FIXED_SIZE if pe32_plus else PE32_FIXED_SIZE
    return OPTIONAL_HEADER_OFFSET + fixed_size + index * 8


def _set_directory(
    image: bytearray,
    *,
    pe32_plus: bool,
    index: int,
    address: int,
    size: int,
) -> None:
    struct.pack_into(
        "<II",
        image,
        _directory_entry_offset(pe32_plus, index),
        address,
        size,
    )


def _replace_directory(
    optional_header: OptionalHeader,
    *,
    index: int,
    address: int,
    size: int,
) -> OptionalHeader:
    directories = list(optional_header.data_directories)
    directories[index] = DataDirectory(
        index=index,
        name=DATA_DIRECTORY_NAMES[index],
        virtual_address=address,
        size=size,
    )
    return replace(optional_header, data_directories=tuple(directories))


class DataDirectoryStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self._file_index = 0

    def _parse_image(self, data: bytes, *, pe32_plus: bool) -> PEImage:
        self._file_index += 1
        format_name = "pe32-plus" if pe32_plus else "pe32"
        path = (
            Path(self._temporary_directory.name)
            / f"directories-{format_name}-{self._file_index}.exe"
        )
        path.write_bytes(data)
        return PEParser(path).parse_image()

    def _metadata(
        self,
        *,
        pe32_plus: bool,
    ) -> tuple[bytes, OptionalHeader, PEImage]:
        data = build_pe_fixture(pe32_plus=pe32_plus)
        image = self._parse_image(data, pe32_plus=pe32_plus)
        unresolved = replace(
            image.optional_header,
            data_directories=tuple(
                replace(directory, status="Unresolved")
                for directory in image.optional_header.data_directories
            ),
        )
        return data, unresolved, image

    def test_resolves_absent_and_mapped_rva_directories(self) -> None:
        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus):
                data, optional_header, image = self._metadata(
                    pe32_plus=pe32_plus
                )
                optional_header = _replace_directory(
                    optional_header,
                    index=5,
                    address=0,
                    size=0,
                )
                optional_header = _replace_directory(
                    optional_header,
                    index=3,
                    address=0x1010,
                    size=0x20,
                )

                resolved = resolve_data_directory_statuses(
                    data,
                    optional_header,
                    image.sections,
                )

                self.assertEqual(
                    resolved.data_directories[5].status,
                    "Absent",
                )
                self.assertEqual(
                    resolved.data_directories[3].status,
                    "Present - RVA range is file-backed",
                )
                self.assertEqual(
                    optional_header.data_directories[3].status,
                    "Unresolved",
                )

    def test_certificate_directory_uses_a_file_offset(self) -> None:
        for pe32_plus in (False, True):
            data, optional_header, image = self._metadata(
                pe32_plus=pe32_plus
            )

            with self.subTest(pe32_plus=pe32_plus, case="present"):
                present_header = _replace_directory(
                    optional_header,
                    index=CERTIFICATE_DIRECTORY_INDEX,
                    address=0xE00,
                    size=0x40,
                )
                resolved = resolve_data_directory_statuses(
                    data,
                    present_header,
                    image.sections,
                )
                self.assertEqual(
                    resolved.data_directories[
                        CERTIFICATE_DIRECTORY_INDEX
                    ].status,
                    "Present - file offset range is valid",
                )

            with self.subTest(pe32_plus=pe32_plus, case="invalid"):
                invalid_header = _replace_directory(
                    optional_header,
                    index=CERTIFICATE_DIRECTORY_INDEX,
                    address=len(data) - 8,
                    size=16,
                )
                resolved = resolve_data_directory_statuses(
                    data,
                    invalid_header,
                    image.sections,
                )
                self.assertEqual(
                    resolved.data_directories[
                        CERTIFICATE_DIRECTORY_INDEX
                    ].status,
                    "Invalid - certificate file range is out of bounds",
                )

    def test_global_pointer_requires_zero_size_and_a_mapped_rva(self) -> None:
        for pe32_plus in (False, True):
            data, optional_header, image = self._metadata(
                pe32_plus=pe32_plus
            )

            with self.subTest(pe32_plus=pe32_plus, case="present"):
                present_header = _replace_directory(
                    optional_header,
                    index=GLOBAL_POINTER_DIRECTORY_INDEX,
                    address=0x1010,
                    size=0,
                )
                resolved = resolve_data_directory_statuses(
                    data,
                    present_header,
                    image.sections,
                )
                self.assertEqual(
                    resolved.data_directories[
                        GLOBAL_POINTER_DIRECTORY_INDEX
                    ].status,
                    "Present - Global Pointer RVA is file-backed",
                )

            with self.subTest(pe32_plus=pe32_plus, case="nonzero-size"):
                nonzero_size_header = _replace_directory(
                    optional_header,
                    index=GLOBAL_POINTER_DIRECTORY_INDEX,
                    address=0x1010,
                    size=1,
                )
                resolved = resolve_data_directory_statuses(
                    data,
                    nonzero_size_header,
                    image.sections,
                )
                self.assertEqual(
                    resolved.data_directories[
                        GLOBAL_POINTER_DIRECTORY_INDEX
                    ].status,
                    "Invalid - Global Pointer size must be zero",
                )

            with self.subTest(pe32_plus=pe32_plus, case="zero-rva"):
                zero_rva_header = _replace_directory(
                    optional_header,
                    index=GLOBAL_POINTER_DIRECTORY_INDEX,
                    address=0,
                    size=1,
                )
                resolved = resolve_data_directory_statuses(
                    data,
                    zero_rva_header,
                    image.sections,
                )
                self.assertEqual(
                    resolved.data_directories[
                        GLOBAL_POINTER_DIRECTORY_INDEX
                    ].status,
                    "Invalid - Global Pointer RVA is zero",
                )

            with self.subTest(pe32_plus=pe32_plus, case="unmapped-rva"):
                unmapped_header = _replace_directory(
                    optional_header,
                    index=GLOBAL_POINTER_DIRECTORY_INDEX,
                    address=0x3000,
                    size=0,
                )
                resolved = resolve_data_directory_statuses(
                    data,
                    unmapped_header,
                    image.sections,
                )
                self.assertTrue(
                    resolved.data_directories[
                        GLOBAL_POINTER_DIRECTORY_INDEX
                    ].status.startswith("Invalid - ")
                )

    def test_malformed_ordinary_directory_pairs_are_invalid(self) -> None:
        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus):
                data, optional_header, image = self._metadata(
                    pe32_plus=pe32_plus
                )
                optional_header = _replace_directory(
                    optional_header,
                    index=6,
                    address=0,
                    size=0x20,
                )
                optional_header = _replace_directory(
                    optional_header,
                    index=10,
                    address=0x1010,
                    size=0,
                )

                resolved = resolve_data_directory_statuses(
                    data,
                    optional_header,
                    image.sections,
                )

                expected = "Invalid - RVA and size must both be nonzero"
                self.assertEqual(resolved.data_directories[6].status, expected)
                self.assertEqual(resolved.data_directories[10].status, expected)

    def test_reserved_directories_are_always_unexpected_when_nonzero(self) -> None:
        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus):
                data, optional_header, image = self._metadata(
                    pe32_plus=pe32_plus
                )
                for index, address, size in (
                    (ARCHITECTURE_DIRECTORY_INDEX, 0x1010, 0x20),
                    (15, 0, 1),
                ):
                    optional_header = _replace_directory(
                        optional_header,
                        index=index,
                        address=address,
                        size=size,
                    )

                resolved = resolve_data_directory_statuses(
                    data,
                    optional_header,
                    image.sections,
                )
                expected = "Unexpected - reserved directory must be zero"
                self.assertEqual(
                    resolved.data_directories[
                        ARCHITECTURE_DIRECTORY_INDEX
                    ].status,
                    expected,
                )
                self.assertEqual(
                    resolved.data_directories[15].status,
                    expected,
                )

    def test_parser_exposes_statuses_in_both_public_directory_views(self) -> None:
        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus):
                fixture = bytearray(build_pe_fixture(pe32_plus=pe32_plus))
                values = {
                    3: (0x1010, 0x20),
                    CERTIFICATE_DIRECTORY_INDEX: (0xE00, 0x40),
                    5: (0, 0),
                    6: (0, 0x20),
                    7: (0x1010, 0),
                    GLOBAL_POINTER_DIRECTORY_INDEX: (0x1010, 0),
                }
                for index, (address, size) in values.items():
                    _set_directory(
                        fixture,
                        pe32_plus=pe32_plus,
                        index=index,
                        address=address,
                        size=size,
                    )

                self._file_index += 1
                path = (
                    Path(self._temporary_directory.name)
                    / f"directory-output-{self._file_index}.exe"
                )
                path.write_bytes(fixture)
                result = PEParser(path).parse()

                top_level = result["data_directories"]
                nested = result["optional_header"]["data_directories"]
                self.assertEqual(top_level, nested)
                self.assertEqual(
                    top_level[3]["status"],
                    "Present - RVA range is file-backed",
                )
                self.assertEqual(
                    top_level[CERTIFICATE_DIRECTORY_INDEX]["status"],
                    "Present - file offset range is valid",
                )
                self.assertEqual(top_level[5]["status"], "Absent")
                self.assertEqual(
                    top_level[6]["status"],
                    "Invalid - RVA and size must both be nonzero",
                )
                self.assertEqual(
                    top_level[7]["status"],
                    "Unexpected - reserved directory must be zero",
                )
                self.assertEqual(
                    top_level[GLOBAL_POINTER_DIRECTORY_INDEX]["status"],
                    "Present - Global Pointer RVA is file-backed",
                )
                expected_format = "PE32+" if pe32_plus else "PE32"
                self.assertEqual(
                    result["optional_header"]["format"],
                    expected_format,
                )


if __name__ == "__main__":
    unittest.main()
