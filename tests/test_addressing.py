from __future__ import annotations

from dataclasses import FrozenInstanceError
import unittest

from pe.addressing import AddressingService
from pe.errors import PEFormatError
from pe.models import OptionalHeader, SectionHeader


def _optional_header(
    *,
    pe32_plus: bool = False,
    image_base: int | None = None,
    size_of_image: int = 0x4000,
    size_of_headers: int = 0x200,
    magic: int | None = None,
) -> OptionalHeader:
    if image_base is None:
        image_base = 0x140000000 if pe32_plus else 0x400000
    return OptionalHeader(
        magic=magic if magic is not None else (0x20B if pe32_plus else 0x10B),
        format="PE32+" if pe32_plus else "PE32",
        major_linker_version=14,
        minor_linker_version=0,
        size_of_code=0x200,
        size_of_initialized_data=0x200,
        size_of_uninitialized_data=0,
        address_of_entry_point=0x1000,
        base_of_code=0x1000,
        base_of_data=None if pe32_plus else 0x2000,
        image_base=image_base,
        section_alignment=0x1000,
        file_alignment=0x200,
        major_operating_system_version=6,
        minor_operating_system_version=0,
        major_image_version=0,
        minor_image_version=0,
        major_subsystem_version=6,
        minor_subsystem_version=0,
        win32_version_value=0,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        checksum=0,
        subsystem=3,
        dll_characteristics=0,
        size_of_stack_reserve=0x100000,
        size_of_stack_commit=0x1000,
        size_of_heap_reserve=0x100000,
        size_of_heap_commit=0x1000,
        loader_flags=0,
        number_of_rva_and_sizes=0,
        data_directories=(),
    )


def _section(
    *,
    index: int = 1,
    name: str = ".text",
    virtual_address: int = 0x1000,
    virtual_size: int = 0x200,
    raw_pointer: int = 0x200,
    raw_size: int = 0x200,
) -> SectionHeader:
    encoded_name = name.encode("ascii")[:8]
    return SectionHeader(
        index=index,
        name=name,
        raw_name=encoded_name.ljust(8, b"\x00"),
        virtual_size=virtual_size,
        virtual_address=virtual_address,
        size_of_raw_data=raw_size,
        pointer_to_raw_data=raw_pointer,
        pointer_to_relocations=0,
        pointer_to_linenumbers=0,
        number_of_relocations=0,
        number_of_linenumbers=0,
        characteristics=0x60000020,
    )


class AddressingServiceTests(unittest.TestCase):
    def test_pe32_maps_headers_bidirectionally(self) -> None:
        service = AddressingService(
            _optional_header(),
            (_section(),),
            file_size=0x600,
        )

        mapping = service.resolve_rva(0x80)

        self.assertEqual(mapping.region_kind, "headers")
        self.assertIsNone(mapping.section_index)
        self.assertEqual(mapping.rva, 0x80)
        self.assertEqual(mapping.va, 0x400080)
        self.assertEqual(mapping.file_offset, 0x80)
        self.assertEqual(mapping.available_virtual_size, 0x180)
        self.assertEqual(mapping.available_file_size, 0x180)
        self.assertEqual(service.file_offset_to_rva(0x80), 0x80)
        self.assertEqual(service.file_offset_to_va(0x80), 0x400080)
        self.assertEqual(service.va_to_rva(0x400080), 0x80)

    def test_pe32_plus_maps_sections_with_64_bit_virtual_addresses(self) -> None:
        service = AddressingService(
            _optional_header(pe32_plus=True),
            (_section(),),
            file_size=0x600,
        )

        by_rva = service.rva_to_mapping(0x1010)
        by_va = service.resolve_va(0x140001010)
        by_file = service.resolve_file_offset(0x210)

        self.assertEqual(by_rva, by_va)
        self.assertEqual(by_rva, by_file)
        self.assertEqual(by_rva.section_name, ".text")
        self.assertEqual(by_rva.section_index, 1)
        self.assertEqual(by_rva.file_offset, 0x210)
        self.assertEqual(by_rva.va, 0x140001010)
        self.assertEqual(service.rva_to_va(0x1010), 0x140001010)

    def test_models_are_immutable_and_have_gui_ready_dictionaries(self) -> None:
        service = AddressingService(
            _optional_header(),
            (_section(),),
            file_size=0x600,
        )
        region = service.regions[1]
        mapping = service.rva_to_mapping(0x1020)

        self.assertEqual(
            region.to_dict(),
            {
                "kind": "section",
                "section_index": 1,
                "section_name": ".text",
                "rva_start": 0x1000,
                "rva_end": 0x1200,
                "va_start": 0x401000,
                "va_end": 0x401200,
                "file_offset_start": 0x200,
                "file_offset_end": 0x400,
            },
        )
        self.assertEqual(
            mapping.to_dict(),
            {
                "region_kind": "section",
                "section_index": 1,
                "section_name": ".text",
                "rva": 0x1020,
                "va": 0x401020,
                "file_offset": 0x220,
                "offset_within_region": 0x20,
                "status": "file-backed",
                "is_file_backed": True,
                "available_virtual_size": 0x1E0,
                "available_file_size": 0x1E0,
            },
        )
        with self.assertRaises(FrozenInstanceError):
            setattr(region, "rva_start", 1)
        with self.assertRaises(FrozenInstanceError):
            setattr(mapping, "rva", 1)

    def test_virtual_only_section_tail_remains_addressable(self) -> None:
        service = AddressingService(
            _optional_header(),
            (_section(virtual_size=0x300, raw_size=0x100),),
            file_size=0x500,
        )

        mapping = service.rva_to_mapping(0x1150)

        self.assertEqual(mapping.status, "virtual-only")
        self.assertFalse(mapping.is_file_backed)
        self.assertIsNone(mapping.file_offset)
        self.assertEqual(mapping.va, 0x401150)
        self.assertEqual(mapping.available_virtual_size, 0x1B0)
        self.assertEqual(mapping.available_file_size, 0)
        with self.assertRaisesRegex(PEFormatError, "virtual-only"):
            service.rva_to_file_offset(0x1150)

    def test_raw_padding_beyond_virtual_size_is_file_backed(self) -> None:
        service = AddressingService(
            _optional_header(),
            (_section(virtual_size=0x100, raw_size=0x200),),
            file_size=0x500,
        )

        mapping = service.rva_to_mapping(0x1150)

        self.assertEqual(mapping.status, "file-backed")
        self.assertEqual(mapping.file_offset, 0x350)
        self.assertEqual(service.file_offset_to_rva(0x350), 0x1150)

    def test_truncated_declared_ranges_are_reported(self) -> None:
        service = AddressingService(
            _optional_header(),
            (_section(),),
            file_size=0x280,
        )

        last_byte = service.rva_to_mapping(0x107F)
        missing = service.rva_to_mapping(0x1080)

        self.assertEqual(last_byte.file_offset, 0x27F)
        self.assertEqual(last_byte.available_file_size, 1)
        self.assertEqual(missing.status, "truncated")
        self.assertIsNone(missing.file_offset)
        with self.assertRaisesRegex(PEFormatError, "physical file size"):
            service.rva_to_file_offset(0x1080)
        with self.assertRaisesRegex(PEFormatError, "outside file size"):
            service.file_offset_to_mapping(0x280)

    def test_unmapped_gaps_and_overlay_file_offsets_are_rejected(self) -> None:
        service = AddressingService(
            _optional_header(),
            (_section(raw_size=0x100),),
            file_size=0x800,
        )

        # RVA/VA arithmetic is meaningful within SizeOfImage even when no
        # header or section owns the address.
        self.assertEqual(service.rva_to_va(0x500), 0x400500)
        with self.assertRaisesRegex(PEFormatError, "not mapped"):
            service.rva_to_mapping(0x500)
        with self.assertRaisesRegex(PEFormatError, "not mapped to an RVA"):
            service.file_offset_to_mapping(0x700)

    def test_overlapping_virtual_ranges_are_rejected_at_ambiguous_rva(self) -> None:
        sections = (
            _section(virtual_size=0x300, raw_size=0x300),
            _section(
                index=2,
                name=".data",
                virtual_address=0x1100,
                virtual_size=0x200,
                raw_pointer=0x600,
                raw_size=0x200,
            ),
        )
        service = AddressingService(
            _optional_header(),
            sections,
            file_size=0x900,
        )

        self.assertEqual(service.rva_to_mapping(0x1050).section_index, 1)
        with self.assertRaisesRegex(PEFormatError, "overlapping virtual"):
            service.rva_to_mapping(0x1150)

    def test_overlapping_raw_ranges_are_rejected_at_ambiguous_offset(self) -> None:
        sections = (
            _section(raw_size=0x200),
            _section(
                index=2,
                name=".data",
                virtual_address=0x2000,
                raw_pointer=0x300,
                raw_size=0x200,
            ),
        )
        service = AddressingService(
            _optional_header(),
            sections,
            file_size=0x600,
        )

        self.assertEqual(service.file_offset_to_mapping(0x250).section_index, 1)
        with self.assertRaisesRegex(PEFormatError, "overlapping raw"):
            service.file_offset_to_mapping(0x350)

    def test_rva_va_and_file_bounds_are_enforced(self) -> None:
        service = AddressingService(
            _optional_header(),
            (_section(),),
            file_size=0x600,
        )

        invalid_calls = (
            lambda: service.rva_to_va(-1),
            lambda: service.rva_to_va(0x4000),
            lambda: service.va_to_rva(0x3FFFFF),
            lambda: service.va_to_rva(0x404000),
            lambda: service.va_to_rva(0x1_0000_0000),
            lambda: service.file_offset_to_rva(-1),
            lambda: service.file_offset_to_rva(0x600),
        )
        for call in invalid_calls:
            with self.subTest(call=call), self.assertRaises(PEFormatError):
                call()

    def test_requested_ranges_must_remain_physically_backed(self) -> None:
        service = AddressingService(
            _optional_header(),
            (_section(raw_size=0x100, virtual_size=0x200),),
            file_size=0x600,
        )

        self.assertEqual(service.rva_to_file_offset(0x10F0, 0x10), 0x2F0)
        self.assertEqual(service.file_offset_to_rva(0x2F0, 0x10), 0x10F0)
        with self.assertRaisesRegex(PEFormatError, "not fully file-backed"):
            service.rva_to_file_offset(0x10F0, 0x11)
        with self.assertRaisesRegex(PEFormatError, "mapping boundary"):
            service.file_offset_to_rva(0x2F0, 0x11)
        with self.assertRaises(ValueError):
            service.rva_to_file_offset(0x1000, -1)

    def test_invalid_image_and_section_bounds_are_rejected(self) -> None:
        cases = (
            (
                _optional_header(magic=0x999),
                (_section(),),
                "magic",
            ),
            (
                _optional_header(size_of_image=0x100, size_of_headers=0x200),
                (),
                "SizeOfHeaders",
            ),
            (
                _optional_header(
                    image_base=0xFFF00000,
                    size_of_image=0x200000,
                ),
                (),
                "overflows",
            ),
            (
                _optional_header(size_of_image=0x1100),
                (_section(virtual_size=0x200),),
                "SizeOfImage",
            ),
        )
        for header, sections, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                PEFormatError,
                message,
            ):
                AddressingService(header, sections, file_size=0x600)


if __name__ == "__main__":
    unittest.main()
