import unittest

from pe.errors import PEFormatError
from pe.models import SectionHeader
from pe.rva import RVAResolver


def _section(
    *,
    index: int = 1,
    virtual_address: int = 0x1000,
    virtual_size: int = 0x200,
    raw_size: int = 0x100,
    raw_pointer: int = 0x200,
) -> SectionHeader:
    return SectionHeader(
        index=index,
        name=".test",
        raw_name=b".test\x00\x00\x00",
        virtual_size=virtual_size,
        virtual_address=virtual_address,
        size_of_raw_data=raw_size,
        pointer_to_raw_data=raw_pointer,
        pointer_to_relocations=0,
        pointer_to_linenumbers=0,
        number_of_relocations=0,
        number_of_linenumbers=0,
        characteristics=0x40000040,
    )


class RVAResolverTests(unittest.TestCase):
    def test_maps_header_and_file_backed_section_rvas(self) -> None:
        resolver = RVAResolver(bytes(0x400), (_section(),), 0x100)

        self.assertEqual(resolver.file_offset(0x20, 4, "header"), 0x20)
        self.assertEqual(resolver.file_offset(0x1010, 4, "section"), 0x210)
        self.assertEqual(resolver.resolve(0x1010, "section").available_size, 0xF0)

    def test_rejects_virtual_only_and_overlapping_section_ranges(self) -> None:
        resolver = RVAResolver(bytes(0x500), (_section(),), 0x100)
        with self.assertRaisesRegex(PEFormatError, "uninitialized"):
            resolver.file_offset(0x1150, 1, "virtual tail")

        overlapping = RVAResolver(
            bytes(0x600),
            (
                _section(),
                _section(
                    index=2,
                    virtual_address=0x1080,
                    raw_pointer=0x300,
                ),
            ),
            0x100,
        )
        with self.assertRaisesRegex(PEFormatError, "overlapping"):
            overlapping.file_offset(0x1090, 1, "overlap")

    def test_rejects_ranges_that_wrap_the_rva_address_space(self) -> None:
        resolver = RVAResolver(bytes(0x400), (_section(),), 0x100)

        with self.assertRaisesRegex(PEFormatError, "32-bit RVA space"):
            resolver.file_offset(0xFFFFFFF0, 0x20, "wrapped range")


if __name__ == "__main__":
    unittest.main()
