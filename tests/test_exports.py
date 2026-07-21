from __future__ import annotations

from dataclasses import replace
import struct
import tempfile
import unittest
from pathlib import Path

from pe.errors import PEFormatError
from pe.exports import ExportTableParser
from pe.models import ExportDirectory, ExportedFunction
from pe.parser import PEParser
from tests.test_parser import (
    OPTIONAL_HEADER_OFFSET,
    PE32_FIXED_SIZE,
    PE32_PLUS_FIXED_SIZE,
    build_pe_fixture,
)


EXPORT_DIRECTORY_RVA = 0x2000
EXPORT_DIRECTORY_SIZE = 0x100
EXPORT_ADDRESS_TABLE_RVA = 0x2028
NAME_POINTER_TABLE_RVA = 0x2040
ORDINAL_TABLE_RVA = 0x204C
DLL_NAME_RVA = 0x2060
ALPHA_NAME_RVA = 0x2070
ALPHA_ALIAS_NAME_RVA = 0x2078
FORWARDED_NAME_RVA = 0x2088
FORWARDER_RVA = 0x20A0
ORDINAL_BASE = 10


def _directory_entry_offset(pe32_plus: bool) -> int:
    fixed_size = PE32_PLUS_FIXED_SIZE if pe32_plus else PE32_FIXED_SIZE
    return OPTIONAL_HEADER_OFFSET + fixed_size


def _rva_to_file_offset(rva: int) -> int:
    if not 0x2000 <= rva < 0x2200:
        raise ValueError(f"Test RVA 0x{rva:X} is outside DATASECT")
    return 0xA00 + rva - 0x2000


def _write_at_rva(image: bytearray, rva: int, value: bytes) -> None:
    offset = _rva_to_file_offset(rva)
    image[offset : offset + len(value)] = value


def build_export_fixture(*, pe32_plus: bool) -> bytes:
    """Build a PE image with named, ordinal-only, aliased and forwarded exports."""

    image = bytearray(build_pe_fixture(pe32_plus=pe32_plus))
    struct.pack_into(
        "<II",
        image,
        _directory_entry_offset(pe32_plus),
        EXPORT_DIRECTORY_RVA,
        EXPORT_DIRECTORY_SIZE,
    )
    struct.pack_into(
        "<IIHHIIIIIII",
        image,
        _rva_to_file_offset(EXPORT_DIRECTORY_RVA),
        0xAABBCCDD,
        0x5E2A5C00,
        2,
        7,
        DLL_NAME_RVA,
        ORDINAL_BASE,
        5,
        3,
        EXPORT_ADDRESS_TABLE_RVA,
        NAME_POINTER_TABLE_RVA,
        ORDINAL_TABLE_RVA,
    )
    struct.pack_into(
        "<5I",
        image,
        _rva_to_file_offset(EXPORT_ADDRESS_TABLE_RVA),
        0x1010,
        0,
        0x1030,
        FORWARDER_RVA,
        0x1050,
    )
    struct.pack_into(
        "<3I",
        image,
        _rva_to_file_offset(NAME_POINTER_TABLE_RVA),
        ALPHA_NAME_RVA,
        ALPHA_ALIAS_NAME_RVA,
        FORWARDED_NAME_RVA,
    )
    struct.pack_into(
        "<3H",
        image,
        _rva_to_file_offset(ORDINAL_TABLE_RVA),
        0,
        0,
        3,
    )
    _write_at_rva(image, DLL_NAME_RVA, b"sample.dll\x00")
    _write_at_rva(image, ALPHA_NAME_RVA, b"Alpha\x00")
    _write_at_rva(image, ALPHA_ALIAS_NAME_RVA, b"AlphaAlias\x00")
    _write_at_rva(image, FORWARDED_NAME_RVA, b"Forwarded\x00")
    _write_at_rva(image, FORWARDER_RVA, b"KERNEL32.Sleep\x00")
    return bytes(image)


class ExportTableParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self._file_index = 0

    def _parse(
        self,
        data: bytes | bytearray,
        *,
        pe32_plus: bool,
    ) -> ExportDirectory | None:
        """Parse exports directly while using PEParser for base metadata."""

        self._file_index += 1
        metadata_data = bytearray(data)
        directory_offset = _directory_entry_offset(pe32_plus)
        directory_rva, directory_size = struct.unpack_from(
            "<II",
            metadata_data,
            directory_offset,
        )

        # Keep this helper independent of PEParser's integration of the same
        # component: metadata is parsed with an explicitly absent export table.
        struct.pack_into("<II", metadata_data, directory_offset, 0, 0)
        path = (
            Path(self._temporary_directory.name)
            / f"export-metadata-{self._file_index}.exe"
        )
        path.write_bytes(metadata_data)
        image = PEParser(path).parse_image()

        optional_header = image.optional_header
        if optional_header.data_directories:
            directories = list(optional_header.data_directories)
            directories[0] = replace(
                directories[0],
                virtual_address=directory_rva,
                size=directory_size,
            )
            optional_header = replace(
                optional_header,
                data_directories=tuple(directories),
            )

        return ExportTableParser(
            bytes(data),
            optional_header,
            image.sections,
        ).parse()

    def test_parses_named_ordinal_alias_gap_and_forwarded_exports(self) -> None:
        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus):
                result = self._parse(
                    build_export_fixture(pe32_plus=pe32_plus),
                    pe32_plus=pe32_plus,
                )

                self.assertEqual(
                    result,
                    ExportDirectory(
                        characteristics=0xAABBCCDD,
                        timestamp=0x5E2A5C00,
                        major_version=2,
                        minor_version=7,
                        name_rva=DLL_NAME_RVA,
                        dll_name="sample.dll",
                        ordinal_base=ORDINAL_BASE,
                        address_table_entries=5,
                        number_of_name_pointers=3,
                        export_address_table_rva=EXPORT_ADDRESS_TABLE_RVA,
                        name_pointer_rva=NAME_POINTER_TABLE_RVA,
                        ordinal_table_rva=ORDINAL_TABLE_RVA,
                        functions=(
                            ExportedFunction(
                                index=1,
                                ordinal=10,
                                ordinal_index=0,
                                name="Alpha",
                                names=("Alpha", "AlphaAlias"),
                                rva=0x1010,
                                is_forwarder=False,
                                forwarder=None,
                            ),
                            ExportedFunction(
                                index=2,
                                ordinal=11,
                                ordinal_index=1,
                                name=None,
                                names=(),
                                rva=0,
                                is_forwarder=False,
                                forwarder=None,
                            ),
                            ExportedFunction(
                                index=3,
                                ordinal=12,
                                ordinal_index=2,
                                name=None,
                                names=(),
                                rva=0x1030,
                                is_forwarder=False,
                                forwarder=None,
                            ),
                            ExportedFunction(
                                index=4,
                                ordinal=13,
                                ordinal_index=3,
                                name="Forwarded",
                                names=("Forwarded",),
                                rva=FORWARDER_RVA,
                                is_forwarder=True,
                                forwarder="KERNEL32.Sleep",
                            ),
                            ExportedFunction(
                                index=5,
                                ordinal=14,
                                ordinal_index=4,
                                name=None,
                                names=(),
                                rva=0x1050,
                                is_forwarder=False,
                                forwarder=None,
                            ),
                        ),
                    ),
                )

    def test_returns_none_when_export_directory_is_absent(self) -> None:
        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus, directory_count=16):
                self.assertIsNone(
                    self._parse(
                        build_pe_fixture(pe32_plus=pe32_plus),
                        pe32_plus=pe32_plus,
                    )
                )

            with self.subTest(pe32_plus=pe32_plus, directory_count=0):
                self.assertIsNone(
                    self._parse(
                        build_pe_fixture(
                            pe32_plus=pe32_plus,
                            directory_count=0,
                        ),
                        pe32_plus=pe32_plus,
                    )
                )

    def test_parses_a_valid_empty_export_directory(self) -> None:
        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus):
                image = bytearray(build_export_fixture(pe32_plus=pe32_plus))
                directory_offset = _rva_to_file_offset(EXPORT_DIRECTORY_RVA)
                struct.pack_into("<II", image, directory_offset + 20, 0, 0)
                struct.pack_into("<III", image, directory_offset + 28, 0, 0, 0)

                result = self._parse(image, pe32_plus=pe32_plus)
                self.assertIsNotNone(result)
                assert result is not None
                self.assertEqual(result.address_table_entries, 0)
                self.assertEqual(result.number_of_name_pointers, 0)
                self.assertEqual(result.functions, ())

    def test_rejects_invalid_directory_and_table_bounds(self) -> None:
        for pe32_plus in (False, True):
            directory_entry_offset = _directory_entry_offset(pe32_plus)
            directory_offset = _rva_to_file_offset(EXPORT_DIRECTORY_RVA)

            for rva, size in (
                (0, EXPORT_DIRECTORY_SIZE),
                (EXPORT_DIRECTORY_RVA, 0),
            ):
                with self.subTest(
                    pe32_plus=pe32_plus,
                    case="directory-pair",
                    rva=rva,
                    size=size,
                ):
                    image = bytearray(
                        build_export_fixture(pe32_plus=pe32_plus)
                    )
                    struct.pack_into(
                        "<II",
                        image,
                        directory_entry_offset,
                        rva,
                        size,
                    )
                    with self.assertRaisesRegex(
                        PEFormatError,
                        "RVA and size",
                    ):
                        self._parse(image, pe32_plus=pe32_plus)

            with self.subTest(pe32_plus=pe32_plus, case="directory-size"):
                image = bytearray(build_export_fixture(pe32_plus=pe32_plus))
                struct.pack_into(
                    "<I",
                    image,
                    directory_entry_offset + 4,
                    39,
                )
                with self.assertRaisesRegex(
                    PEFormatError,
                    "too small",
                ):
                    self._parse(image, pe32_plus=pe32_plus)

            with self.subTest(pe32_plus=pe32_plus, case="directory-rva"):
                image = bytearray(build_export_fixture(pe32_plus=pe32_plus))
                struct.pack_into(
                    "<II",
                    image,
                    directory_entry_offset,
                    0x3000,
                    40,
                )
                with self.assertRaisesRegex(
                    PEFormatError,
                    "export directory RVA",
                ):
                    self._parse(image, pe32_plus=pe32_plus)

            with self.subTest(pe32_plus=pe32_plus, case="address-table-rva"):
                image = bytearray(build_export_fixture(pe32_plus=pe32_plus))
                struct.pack_into("<I", image, directory_offset + 28, 0x21F8)
                with self.assertRaisesRegex(
                    PEFormatError,
                    "export address table",
                ):
                    self._parse(image, pe32_plus=pe32_plus)

            with self.subTest(pe32_plus=pe32_plus, case="name-table-rva"):
                image = bytearray(build_export_fixture(pe32_plus=pe32_plus))
                struct.pack_into("<I", image, directory_offset + 32, 0)
                with self.assertRaisesRegex(
                    PEFormatError,
                    "name pointer table.*zero RVA",
                ):
                    self._parse(image, pe32_plus=pe32_plus)

            with self.subTest(pe32_plus=pe32_plus, case="ordinal-table-rva"):
                image = bytearray(build_export_fixture(pe32_plus=pe32_plus))
                struct.pack_into("<I", image, directory_offset + 36, 0x3000)
                with self.assertRaisesRegex(
                    PEFormatError,
                    "export ordinal table RVA",
                ):
                    self._parse(image, pe32_plus=pe32_plus)

            with self.subTest(pe32_plus=pe32_plus, case="oversized-count"):
                image = bytearray(build_export_fixture(pe32_plus=pe32_plus))
                struct.pack_into("<I", image, directory_offset + 20, 0xFFFFFFFF)
                with self.assertRaises(PEFormatError):
                    self._parse(image, pe32_plus=pe32_plus)

    def test_rejects_malformed_names_ordinals_and_forwarders(self) -> None:
        for pe32_plus in (False, True):
            directory_offset = _rva_to_file_offset(EXPORT_DIRECTORY_RVA)

            with self.subTest(pe32_plus=pe32_plus, case="dll-name-rva"):
                image = bytearray(build_export_fixture(pe32_plus=pe32_plus))
                struct.pack_into("<I", image, directory_offset + 12, 0)
                with self.assertRaisesRegex(PEFormatError, "no DLL name RVA"):
                    self._parse(image, pe32_plus=pe32_plus)

            with self.subTest(pe32_plus=pe32_plus, case="dll-name-ascii"):
                image = bytearray(build_export_fixture(pe32_plus=pe32_plus))
                image[_rva_to_file_offset(DLL_NAME_RVA)] = 0xFF
                with self.assertRaisesRegex(PEFormatError, "not valid ASCII"):
                    self._parse(image, pe32_plus=pe32_plus)

            with self.subTest(pe32_plus=pe32_plus, case="dll-terminator"):
                image = bytearray(build_export_fixture(pe32_plus=pe32_plus))
                struct.pack_into("<I", image, directory_offset + 12, 0x21F8)
                _write_at_rva(image, 0x21F8, b"A" * 8)
                with self.assertRaisesRegex(PEFormatError, "Unterminated"):
                    self._parse(image, pe32_plus=pe32_plus)

            with self.subTest(pe32_plus=pe32_plus, case="export-name-ascii"):
                image = bytearray(build_export_fixture(pe32_plus=pe32_plus))
                image[_rva_to_file_offset(ALPHA_NAME_RVA)] = 0xFF
                with self.assertRaisesRegex(PEFormatError, "not valid ASCII"):
                    self._parse(image, pe32_plus=pe32_plus)

            with self.subTest(pe32_plus=pe32_plus, case="ordinal-index"):
                image = bytearray(build_export_fixture(pe32_plus=pe32_plus))
                struct.pack_into(
                    "<H",
                    image,
                    _rva_to_file_offset(ORDINAL_TABLE_RVA),
                    5,
                )
                with self.assertRaisesRegex(
                    PEFormatError,
                    "outside the export address table",
                ):
                    self._parse(image, pe32_plus=pe32_plus)

            with self.subTest(pe32_plus=pe32_plus, case="forwarder-bound"):
                image = bytearray(build_export_fixture(pe32_plus=pe32_plus))
                struct.pack_into(
                    "<I",
                    image,
                    _rva_to_file_offset(EXPORT_ADDRESS_TABLE_RVA) + 12,
                    0x20F8,
                )
                _write_at_rva(image, 0x20F8, b"A" * 8)
                with self.assertRaisesRegex(
                    PEFormatError,
                    "Unterminated.*forwarder",
                ):
                    self._parse(image, pe32_plus=pe32_plus)

            with self.subTest(pe32_plus=pe32_plus, case="forwarder-ascii"):
                image = bytearray(build_export_fixture(pe32_plus=pe32_plus))
                image[_rva_to_file_offset(FORWARDER_RVA)] = 0xFF
                with self.assertRaisesRegex(PEFormatError, "not valid ASCII"):
                    self._parse(image, pe32_plus=pe32_plus)

            with self.subTest(pe32_plus=pe32_plus, case="ordinal-overflow"):
                image = bytearray(build_export_fixture(pe32_plus=pe32_plus))
                struct.pack_into(
                    "<I",
                    image,
                    directory_offset + 16,
                    0xFFFFFFFE,
                )
                with self.assertRaisesRegex(
                    PEFormatError,
                    "ordinal space",
                ):
                    self._parse(image, pe32_plus=pe32_plus)


if __name__ == "__main__":
    unittest.main()
