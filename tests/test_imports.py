from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from typing import Any

from pe.parser import PEFormatError, PEParser
from tests.test_parser import (
    OPTIONAL_HEADER_OFFSET,
    PE32_FIXED_SIZE,
    PE32_PLUS_FIXED_SIZE,
    build_pe_fixture,
)


IMPORT_DIRECTORY_RVA = 0x2000
IMPORT_DIRECTORY_SIZE = 3 * 20
FIRST_DESCRIPTOR_RVA = IMPORT_DIRECTORY_RVA
SECOND_DESCRIPTOR_RVA = FIRST_DESCRIPTOR_RVA + 20
FIRST_DLL_NAME_RVA = 0x2040
SECOND_DLL_NAME_RVA = 0x2050
FIRST_HINT_NAME_RVA = 0x2060
SECOND_HINT_NAME_RVA = 0x2070
FIRST_LOOKUP_TABLE_RVA = 0x2080
FIRST_IAT_RVA = 0x20A0
SECOND_IAT_RVA = 0x20C0
IMPORT_SECTION_RVA = 0x2000
IMPORT_SECTION_FILE_OFFSET = 0xA00
IMPORT_TEST_END_RVA = 0x2180

FIRST_DESCRIPTOR_TIMESTAMP = 0x5E2A5C01
FIRST_DESCRIPTOR_FORWARDER_CHAIN = 0xFFFFFFFF
BOUND_DESCRIPTOR_TIMESTAMP = 0x12345678


def _rva_to_file_offset(rva: int) -> int:
    return IMPORT_SECTION_FILE_OFFSET + rva - IMPORT_SECTION_RVA


def _import_directory_entry_offset(pe32_plus: bool) -> int:
    fixed_size = PE32_PLUS_FIXED_SIZE if pe32_plus else PE32_FIXED_SIZE
    return OPTIONAL_HEADER_OFFSET + fixed_size + 8


def _thunk_layout(pe32_plus: bool) -> tuple[str, int, int]:
    if pe32_plus:
        return "<Q", 8, 0x8000000000000000
    return "<I", 4, 0x80000000


def _pack_thunks(
    image: bytearray,
    pe32_plus: bool,
    table_rva: int,
    values: tuple[int, ...],
) -> None:
    format_string, entry_size, _ = _thunk_layout(pe32_plus)
    table_offset = _rva_to_file_offset(table_rva)
    for index, value in enumerate(values):
        struct.pack_into(
            format_string,
            image,
            table_offset + index * entry_size,
            value,
        )


def build_import_fixture(*, pe32_plus: bool) -> bytes:
    """Build a PE with two import descriptors and mixed import kinds."""

    image = bytearray(build_pe_fixture(pe32_plus=pe32_plus))
    struct.pack_into(
        "<II",
        image,
        _import_directory_entry_offset(pe32_plus),
        IMPORT_DIRECTORY_RVA,
        IMPORT_DIRECTORY_SIZE,
    )

    struct.pack_into(
        "<IIIII",
        image,
        _rva_to_file_offset(FIRST_DESCRIPTOR_RVA),
        FIRST_LOOKUP_TABLE_RVA,
        FIRST_DESCRIPTOR_TIMESTAMP,
        FIRST_DESCRIPTOR_FORWARDER_CHAIN,
        FIRST_DLL_NAME_RVA,
        FIRST_IAT_RVA,
    )
    struct.pack_into(
        "<IIIII",
        image,
        _rva_to_file_offset(SECOND_DESCRIPTOR_RVA),
        0,
        0,
        0,
        SECOND_DLL_NAME_RVA,
        SECOND_IAT_RVA,
    )

    first_dll = b"KERNEL32.dll\x00"
    second_dll = b"USER32.dll\x00"
    image[
        _rva_to_file_offset(FIRST_DLL_NAME_RVA) :
        _rva_to_file_offset(FIRST_DLL_NAME_RVA) + len(first_dll)
    ] = first_dll
    image[
        _rva_to_file_offset(SECOND_DLL_NAME_RVA) :
        _rva_to_file_offset(SECOND_DLL_NAME_RVA) + len(second_dll)
    ] = second_dll

    first_hint_name = struct.pack("<H", 0x1234) + b"CreateFileW\x00"
    second_hint_name = struct.pack("<H", 7) + b"MessageBoxA\x00"
    image[
        _rva_to_file_offset(FIRST_HINT_NAME_RVA) :
        _rva_to_file_offset(FIRST_HINT_NAME_RVA) + len(first_hint_name)
    ] = first_hint_name
    image[
        _rva_to_file_offset(SECOND_HINT_NAME_RVA) :
        _rva_to_file_offset(SECOND_HINT_NAME_RVA) + len(second_hint_name)
    ] = second_hint_name

    _, _, ordinal_flag = _thunk_layout(pe32_plus)
    _pack_thunks(
        image,
        pe32_plus,
        FIRST_LOOKUP_TABLE_RVA,
        (FIRST_HINT_NAME_RVA, ordinal_flag | 0x42, 0),
    )

    # Bound-looking IAT values ensure the parser really uses OriginalFirstThunk
    # for the first descriptor rather than accidentally reading FirstThunk.
    bound_image_base = 0x0000000140000000 if pe32_plus else 0x00400000
    _pack_thunks(
        image,
        pe32_plus,
        FIRST_IAT_RVA,
        (bound_image_base + 0x1234, bound_image_base + 0x5678, 0),
    )
    _pack_thunks(
        image,
        pe32_plus,
        SECOND_IAT_RVA,
        (SECOND_HINT_NAME_RVA, 0),
    )
    return bytes(image)


def build_bound_import_fixture(*, pe32_plus: bool) -> bytes:
    """Build a bound OFT-less descriptor whose IAT contains resolved addresses."""

    image = bytearray(build_import_fixture(pe32_plus=pe32_plus))
    struct.pack_into(
        "<I",
        image,
        _rva_to_file_offset(SECOND_DESCRIPTOR_RVA) + 4,
        BOUND_DESCRIPTOR_TIMESTAMP,
    )
    values = (
        (0x00007FFB12345678, 0x00007FFB23456789, 0)
        if pe32_plus
        else (0x76543210, 0x76544321, 0)
    )
    _pack_thunks(image, pe32_plus, SECOND_IAT_RVA, values)
    return bytes(image)


class ImportTableParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self._file_index = 0

    def _parse(self, data: bytes | bytearray) -> dict[str, Any]:
        self._file_index += 1
        path = (
            Path(self._temporary_directory.name)
            / f"import-fixture-{self._file_index}.exe"
        )
        path.write_bytes(data)
        return PEParser(path).parse()

    def test_parses_named_ordinal_and_oft_fallback_imports(self) -> None:
        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus):
                result = self._parse(build_import_fixture(pe32_plus=pe32_plus))
                entry_size = 8 if pe32_plus else 4
                ordinal_flag = (
                    0x8000000000000000 if pe32_plus else 0x80000000
                )

                self.assertEqual(
                    result["imports"],
                    [
                        {
                            "index": 1,
                            "dll_name": "KERNEL32.dll",
                            "original_first_thunk": FIRST_LOOKUP_TABLE_RVA,
                            "timestamp": FIRST_DESCRIPTOR_TIMESTAMP,
                            "forwarder_chain": (
                                FIRST_DESCRIPTOR_FORWARDER_CHAIN
                            ),
                            "name_rva": FIRST_DLL_NAME_RVA,
                            "first_thunk": FIRST_IAT_RVA,
                            "functions": [
                                {
                                    "index": 1,
                                    "kind": "name",
                                    "name": "CreateFileW",
                                    "ordinal": None,
                                    "hint": 0x1234,
                                    "is_ordinal": False,
                                    "lookup_table_rva": FIRST_LOOKUP_TABLE_RVA,
                                    "import_address_table_rva": FIRST_IAT_RVA,
                                    "name_rva": FIRST_HINT_NAME_RVA,
                                    "raw_value": FIRST_HINT_NAME_RVA,
                                },
                                {
                                    "index": 2,
                                    "kind": "ordinal",
                                    "name": None,
                                    "ordinal": 0x42,
                                    "hint": None,
                                    "is_ordinal": True,
                                    "lookup_table_rva": (
                                        FIRST_LOOKUP_TABLE_RVA + entry_size
                                    ),
                                    "import_address_table_rva": (
                                        FIRST_IAT_RVA + entry_size
                                    ),
                                    "name_rva": None,
                                    "raw_value": ordinal_flag | 0x42,
                                },
                            ],
                        },
                        {
                            "index": 2,
                            "dll_name": "USER32.dll",
                            "original_first_thunk": 0,
                            "timestamp": 0,
                            "forwarder_chain": 0,
                            "name_rva": SECOND_DLL_NAME_RVA,
                            "first_thunk": SECOND_IAT_RVA,
                            "functions": [
                                {
                                    "index": 1,
                                    "kind": "name",
                                    "name": "MessageBoxA",
                                    "ordinal": None,
                                    "hint": 7,
                                    "is_ordinal": False,
                                    "lookup_table_rva": SECOND_IAT_RVA,
                                    "import_address_table_rva": SECOND_IAT_RVA,
                                    "name_rva": SECOND_HINT_NAME_RVA,
                                    "raw_value": SECOND_HINT_NAME_RVA,
                                }
                            ],
                        },
                    ],
                )

    def test_preserves_bound_addresses_in_bound_oft_fallback(self) -> None:
        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus):
                result = self._parse(
                    build_bound_import_fixture(pe32_plus=pe32_plus)
                )
                descriptor = result["imports"][1]
                functions = descriptor["functions"]
                entry_size = 8 if pe32_plus else 4
                raw_values = (
                    (0x00007FFB12345678, 0x00007FFB23456789)
                    if pe32_plus
                    else (0x76543210, 0x76544321)
                )

                self.assertEqual(descriptor["original_first_thunk"], 0)
                self.assertEqual(
                    descriptor["timestamp"],
                    BOUND_DESCRIPTOR_TIMESTAMP,
                )
                self.assertEqual(len(functions), 2)
                for index, (function, raw_value) in enumerate(
                    zip(functions, raw_values, strict=True),
                    start=1,
                ):
                    with self.subTest(function=index):
                        self.assertEqual(
                            function,
                            {
                                "index": index,
                                "kind": "bound_address",
                                "name": None,
                                "ordinal": None,
                                "hint": None,
                                "is_ordinal": False,
                                "lookup_table_rva": (
                                    SECOND_IAT_RVA + (index - 1) * entry_size
                                ),
                                "import_address_table_rva": (
                                    SECOND_IAT_RVA + (index - 1) * entry_size
                                ),
                                "name_rva": None,
                                "raw_value": raw_value,
                            },
                        )

    def test_returns_empty_imports_when_directory_is_absent(self) -> None:
        for pe32_plus in (False, True):
            for directory_count in (0, 1):
                with self.subTest(
                    pe32_plus=pe32_plus,
                    directory_count=directory_count,
                ):
                    result = self._parse(
                        build_pe_fixture(
                            pe32_plus=pe32_plus,
                            directory_count=directory_count,
                        )
                    )
                    self.assertEqual(result["imports"], [])

            with self.subTest(pe32_plus=pe32_plus, zero_directory=True):
                image = bytearray(build_import_fixture(pe32_plus=pe32_plus))
                struct.pack_into(
                    "<II",
                    image,
                    _import_directory_entry_offset(pe32_plus),
                    0,
                    0,
                )
                self.assertEqual(self._parse(image)["imports"], [])

    def test_rejects_malformed_import_rvas_and_termination(self) -> None:
        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus, case="directory-rva"):
                image = bytearray(build_import_fixture(pe32_plus=pe32_plus))
                struct.pack_into(
                    "<I",
                    image,
                    _import_directory_entry_offset(pe32_plus),
                    0x3000,
                )
                with self.assertRaisesRegex(PEFormatError, "import directory RVA"):
                    self._parse(image)

            with self.subTest(pe32_plus=pe32_plus, case="directory-size"):
                image = bytearray(build_import_fixture(pe32_plus=pe32_plus))
                struct.pack_into(
                    "<I",
                    image,
                    _import_directory_entry_offset(pe32_plus) + 4,
                    0xFFFFFFFF,
                )
                with self.assertRaises(PEFormatError):
                    self._parse(image)

            with self.subTest(pe32_plus=pe32_plus, case="descriptor-terminator"):
                image = bytearray(build_import_fixture(pe32_plus=pe32_plus))
                struct.pack_into(
                    "<I",
                    image,
                    _import_directory_entry_offset(pe32_plus) + 4,
                    40,
                )
                with self.assertRaisesRegex(
                    PEFormatError,
                    "no null IMAGE_IMPORT_DESCRIPTOR terminator",
                ):
                    self._parse(image)

            with self.subTest(pe32_plus=pe32_plus, case="truncated-descriptor"):
                image = build_import_fixture(pe32_plus=pe32_plus)
                truncated_at = _rva_to_file_offset(FIRST_DESCRIPTOR_RVA) + 19
                with self.assertRaises(PEFormatError):
                    self._parse(image[:truncated_at])

            with self.subTest(pe32_plus=pe32_plus, case="dll-rva"):
                image = bytearray(build_import_fixture(pe32_plus=pe32_plus))
                struct.pack_into(
                    "<I",
                    image,
                    _rva_to_file_offset(FIRST_DESCRIPTOR_RVA) + 12,
                    0x3000,
                )
                with self.assertRaisesRegex(PEFormatError, "DLL name RVA"):
                    self._parse(image)

            with self.subTest(pe32_plus=pe32_plus, case="dll-termination"):
                image = bytearray(build_import_fixture(pe32_plus=pe32_plus))
                struct.pack_into(
                    "<I",
                    image,
                    _rva_to_file_offset(FIRST_DESCRIPTOR_RVA) + 12,
                    0x2170,
                )
                image[
                    _rva_to_file_offset(0x2170) :
                    _rva_to_file_offset(IMPORT_TEST_END_RVA)
                ] = b"A" * 16
                with self.assertRaisesRegex(PEFormatError, "Unterminated.*DLL name"):
                    self._parse(image[:_rva_to_file_offset(IMPORT_TEST_END_RVA)])

            with self.subTest(pe32_plus=pe32_plus, case="lookup-table-rva"):
                image = bytearray(build_import_fixture(pe32_plus=pe32_plus))
                struct.pack_into(
                    "<I",
                    image,
                    _rva_to_file_offset(FIRST_DESCRIPTOR_RVA),
                    0x3000,
                )
                with self.assertRaisesRegex(PEFormatError, "lookup table RVA"):
                    self._parse(image)

            with self.subTest(pe32_plus=pe32_plus, case="thunk-termination"):
                image = bytearray(build_import_fixture(pe32_plus=pe32_plus))
                struct.pack_into(
                    "<I",
                    image,
                    _rva_to_file_offset(FIRST_DESCRIPTOR_RVA),
                    0x2160,
                )
                format_string, entry_size, ordinal_flag = _thunk_layout(
                    pe32_plus
                )
                for index in range(0x20 // entry_size):
                    struct.pack_into(
                        format_string,
                        image,
                        _rva_to_file_offset(0x2160) + index * entry_size,
                        ordinal_flag | (index + 1),
                    )
                with self.assertRaisesRegex(
                    PEFormatError,
                    "thunk table has no null terminator",
                ):
                    self._parse(image[:_rva_to_file_offset(IMPORT_TEST_END_RVA)])

            format_string, _, _ = _thunk_layout(pe32_plus)
            with self.subTest(pe32_plus=pe32_plus, case="hint-rva"):
                image = bytearray(build_import_fixture(pe32_plus=pe32_plus))
                struct.pack_into(
                    format_string,
                    image,
                    _rva_to_file_offset(FIRST_LOOKUP_TABLE_RVA),
                    0x3000,
                )
                with self.assertRaisesRegex(PEFormatError, "function 1 hint RVA"):
                    self._parse(image)

            with self.subTest(pe32_plus=pe32_plus, case="truncated-hint"):
                image = bytearray(build_import_fixture(pe32_plus=pe32_plus))
                struct.pack_into(
                    format_string,
                    image,
                    _rva_to_file_offset(FIRST_LOOKUP_TABLE_RVA),
                    0x217F,
                )
                image[_rva_to_file_offset(0x217F)] = 1
                with self.assertRaisesRegex(
                    PEFormatError,
                    "Truncated.*function 1 hint",
                ):
                    self._parse(image[:_rva_to_file_offset(IMPORT_TEST_END_RVA)])

            with self.subTest(pe32_plus=pe32_plus, case="function-termination"):
                image = bytearray(build_import_fixture(pe32_plus=pe32_plus))
                struct.pack_into(
                    format_string,
                    image,
                    _rva_to_file_offset(FIRST_LOOKUP_TABLE_RVA),
                    0x2170,
                )
                struct.pack_into("<H", image, _rva_to_file_offset(0x2170), 1)
                image[
                    _rva_to_file_offset(0x2172) :
                    _rva_to_file_offset(IMPORT_TEST_END_RVA)
                ] = b"A" * 14
                with self.assertRaisesRegex(
                    PEFormatError,
                    "Unterminated.*function 1 name",
                ):
                    self._parse(image[:_rva_to_file_offset(IMPORT_TEST_END_RVA)])

    def test_rejects_invalid_directory_descriptor_and_ordinal_invariants(
        self,
    ) -> None:
        for pe32_plus in (False, True):
            directory_offset = _import_directory_entry_offset(pe32_plus)
            descriptor_offset = _rva_to_file_offset(FIRST_DESCRIPTOR_RVA)
            format_string, _, ordinal_flag = _thunk_layout(pe32_plus)

            for rva, size in ((0, IMPORT_DIRECTORY_SIZE), (IMPORT_DIRECTORY_RVA, 0)):
                with self.subTest(
                    pe32_plus=pe32_plus,
                    case="directory-pair",
                    rva=rva,
                    size=size,
                ):
                    image = bytearray(build_import_fixture(pe32_plus=pe32_plus))
                    struct.pack_into("<II", image, directory_offset, rva, size)
                    with self.assertRaises(PEFormatError):
                        self._parse(image)

            for first_thunk in (0, 0xDEADBEEF):
                with self.subTest(
                    pe32_plus=pe32_plus,
                    case="first-thunk",
                    first_thunk=first_thunk,
                ):
                    image = bytearray(build_import_fixture(pe32_plus=pe32_plus))
                    struct.pack_into(
                        "<I",
                        image,
                        descriptor_offset + 16,
                        first_thunk,
                    )
                    with self.assertRaises(PEFormatError):
                        self._parse(image)

            with self.subTest(pe32_plus=pe32_plus, case="ordinal-reserved-bits"):
                image = bytearray(build_import_fixture(pe32_plus=pe32_plus))
                struct.pack_into(
                    format_string,
                    image,
                    _rva_to_file_offset(FIRST_LOOKUP_TABLE_RVA),
                    ordinal_flag | 0x00010042,
                )
                with self.assertRaisesRegex(PEFormatError, "reserved"):
                    self._parse(image)

            if pe32_plus:
                with self.subTest(case="name-thunk-reserved-bits"):
                    image = bytearray(build_import_fixture(pe32_plus=True))
                    struct.pack_into(
                        "<Q",
                        image,
                        _rva_to_file_offset(FIRST_LOOKUP_TABLE_RVA),
                        0x0000000080002060,
                    )
                    with self.assertRaisesRegex(PEFormatError, "reserved"):
                        self._parse(image)

            with self.subTest(pe32_plus=pe32_plus, case="non-ascii-dll-name"):
                image = bytearray(build_import_fixture(pe32_plus=pe32_plus))
                image[_rva_to_file_offset(FIRST_DLL_NAME_RVA)] = 0xFF
                with self.assertRaisesRegex(PEFormatError, "valid ASCII"):
                    self._parse(image)

            with self.subTest(
                pe32_plus=pe32_plus,
                case="non-ascii-function-name",
            ):
                image = bytearray(build_import_fixture(pe32_plus=pe32_plus))
                image[_rva_to_file_offset(FIRST_HINT_NAME_RVA) + 2] = 0xFF
                with self.assertRaisesRegex(PEFormatError, "valid ASCII"):
                    self._parse(image)


if __name__ == "__main__":
    unittest.main()
