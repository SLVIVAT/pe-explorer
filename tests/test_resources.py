from __future__ import annotations

from dataclasses import dataclass
import struct
import unittest
from unittest.mock import patch

from pe.errors import PEFormatError
from pe.models import DataDirectory, OptionalHeader, ResourceNode, SectionHeader
from pe.resources import ResourceDirectoryParser


RESOURCE_RVA = 0x2000
RAW_OFFSET = 0x200
RAW_SIZE = 0x2000


@dataclass(frozen=True)
class _Leaf:
    payload: bytes
    code_page: int = 0
    reserved: int = 0


_Entry = tuple[int | str, "list[_Entry] | _Leaf"]


class _ResourceFixtureBuilder:
    """Construct a resource tree using real relative offsets and data RVAs."""

    def __init__(self) -> None:
        self.image = bytearray(RAW_OFFSET + RAW_SIZE)
        self.cursor = 0

    def build(self, entries: list[_Entry]) -> tuple[bytes, int]:
        root_offset = self._add_directory(entries)
        if root_offset != 0:
            raise AssertionError("root resource directory must begin at zero")
        return bytes(self.image), self._align(self.cursor, 4)

    def _allocate(self, size: int, alignment: int = 4) -> int:
        self.cursor = self._align(self.cursor, alignment)
        offset = self.cursor
        self.cursor += size
        if self.cursor > RAW_SIZE:
            raise AssertionError("resource fixture exceeds its section")
        return offset

    @staticmethod
    def _align(value: int, alignment: int) -> int:
        return (value + alignment - 1) & ~(alignment - 1)

    def _file_offset(self, relative_offset: int) -> int:
        return RAW_OFFSET + relative_offset

    def _add_directory(self, entries: list[_Entry]) -> int:
        named_count = sum(isinstance(name, str) for name, _ in entries)
        if any(
            not isinstance(name, str)
            for name, _ in entries[:named_count]
        ) or any(
            isinstance(name, str)
            for name, _ in entries[named_count:]
        ):
            raise AssertionError("named fixture entries must precede ID entries")

        directory_offset = self._allocate(16 + len(entries) * 8)
        struct.pack_into(
            "<IIHHHH",
            self.image,
            self._file_offset(directory_offset),
            0xAABBCCDD,
            0x5E2A5C00,
            2,
            7,
            named_count,
            len(entries) - named_count,
        )

        for index, (name, child) in enumerate(entries):
            if isinstance(name, str):
                name_offset = self._add_name(name)
                name_value = 0x80000000 | name_offset
            else:
                name_value = name

            if isinstance(child, _Leaf):
                child_offset = self._add_data(child)
                target_value = child_offset
            else:
                child_offset = self._add_directory(child)
                target_value = 0x80000000 | child_offset
            struct.pack_into(
                "<II",
                self.image,
                self._file_offset(directory_offset + 16 + index * 8),
                name_value,
                target_value,
            )
        return directory_offset

    def _add_name(self, value: str) -> int:
        encoded = value.encode("utf-16-le")
        offset = self._allocate(2 + len(encoded), alignment=2)
        struct.pack_into("<H", self.image, self._file_offset(offset), len(value))
        start = self._file_offset(offset + 2)
        self.image[start : start + len(encoded)] = encoded
        return offset

    def _add_data(self, leaf: _Leaf) -> int:
        data_entry_offset = self._allocate(16)
        payload_offset = self._allocate(len(leaf.payload))
        start = self._file_offset(payload_offset)
        self.image[start : start + len(leaf.payload)] = leaf.payload
        struct.pack_into(
            "<IIII",
            self.image,
            self._file_offset(data_entry_offset),
            RESOURCE_RVA + payload_offset,
            len(leaf.payload),
            leaf.code_page,
            leaf.reserved,
        )
        return data_entry_offset


def _make_optional_header(
    *,
    pe32_plus: bool,
    resource_size: int,
    resource_rva: int = RESOURCE_RVA,
) -> OptionalHeader:
    directories = (
        DataDirectory(0, "Export Table", 0, 0),
        DataDirectory(1, "Import Table", 0, 0),
        DataDirectory(2, "Resource Table", resource_rva, resource_size),
    )
    return OptionalHeader(
        magic=0x20B if pe32_plus else 0x10B,
        format="PE32+" if pe32_plus else "PE32",
        major_linker_version=14,
        minor_linker_version=0,
        size_of_code=0,
        size_of_initialized_data=RAW_SIZE,
        size_of_uninitialized_data=0,
        address_of_entry_point=0,
        base_of_code=0x1000,
        base_of_data=None if pe32_plus else RESOURCE_RVA,
        image_base=0x140000000 if pe32_plus else 0x400000,
        section_alignment=0x1000,
        file_alignment=0x200,
        major_operating_system_version=6,
        minor_operating_system_version=0,
        major_image_version=0,
        minor_image_version=0,
        major_subsystem_version=6,
        minor_subsystem_version=0,
        win32_version_value=0,
        size_of_image=0x4000,
        size_of_headers=RAW_OFFSET,
        checksum=0,
        subsystem=3,
        dll_characteristics=0,
        size_of_stack_reserve=0x100000,
        size_of_stack_commit=0x1000,
        size_of_heap_reserve=0x100000,
        size_of_heap_commit=0x1000,
        loader_flags=0,
        number_of_rva_and_sizes=3,
        data_directories=directories,
    )


def _make_section() -> SectionHeader:
    return SectionHeader(
        index=1,
        name=".rsrc",
        raw_name=b".rsrc\x00\x00\x00",
        virtual_size=RAW_SIZE,
        virtual_address=RESOURCE_RVA,
        size_of_raw_data=RAW_SIZE,
        pointer_to_raw_data=RAW_OFFSET,
        pointer_to_relocations=0,
        pointer_to_linenumbers=0,
        number_of_relocations=0,
        number_of_linenumbers=0,
        characteristics=0x40000040,
    )


def _utf16_z(value: str) -> bytes:
    return (value + "\x00").encode("utf-16-le")


def _version_block(
    key: str,
    value: bytes = b"",
    *,
    value_type: int,
    value_length: int | None = None,
    children: tuple[bytes, ...] = (),
) -> bytes:
    block = bytearray(6)
    block.extend(_utf16_z(key))
    while len(block) % 4:
        block.append(0)
    block.extend(value)
    if children:
        while len(block) % 4:
            block.append(0)
        for child in children:
            block.extend(child)
            while len(block) % 4:
                block.append(0)
    if value_length is None:
        value_length = len(value) // 2 if value_type == 1 else len(value)
    struct.pack_into("<HHH", block, 0, len(block), value_length, value_type)
    return bytes(block)


def _make_version_payload() -> bytes:
    company_value = _utf16_z("Acme Corporation")
    company = _version_block(
        "CompanyName",
        company_value,
        value_type=1,
    )
    description_value = _utf16_z("Resource fixture")
    description = _version_block(
        "FileDescription",
        description_value,
        value_type=1,
    )
    string_table = _version_block(
        "040904B0",
        value_type=1,
        children=(company, description),
    )
    string_file_info = _version_block(
        "StringFileInfo",
        value_type=1,
        children=(string_table,),
    )
    fixed = struct.pack(
        "<13I",
        0xFEEF04BD,
        0x00010000,
        0x00010002,
        0x00030004,
        0x00050006,
        0x00070008,
        0x3F,
        0,
        0x00040004,
        1,
        0,
        0,
        0,
    )
    return _version_block(
        "VS_VERSION_INFO",
        fixed,
        value_type=0,
        value_length=len(fixed),
        children=(string_file_info,),
    )


def _make_string_payload() -> bytes:
    result = bytearray()
    for index in range(16):
        value = "Hello" if index == 0 else "Last" if index == 15 else ""
        encoded = value.encode("utf-16-le")
        result.extend(struct.pack("<H", len(value)))
        result.extend(encoded)
    return bytes(result)


def _make_dialog_payload() -> bytes:
    result = bytearray(
        struct.pack(
            "<IIHhhhh",
            0x90C800C4,
            0,
            2,
            10,
            20,
            180,
            90,
        )
    )
    result.extend(struct.pack("<H", 0))  # no menu
    result.extend(struct.pack("<H", 0))  # default window class
    result.extend(_utf16_z("About PE Explorer"))
    return bytes(result)


def _standard_entries() -> list[_Entry]:
    bitmap_core = struct.pack(
        "<IHHHH",
        12,
        16,
        24,
        1,
        4,
    )
    icon = struct.pack(
        "<IiiHHIIIIII",
        40,
        32,
        64,  # Icon DIB height includes the XOR and AND masks.
        1,
        32,
        0,
        4096,
        0,
        0,
        0,
        0,
    )
    group_icon = struct.pack(
        "<HHHBBBBHHIH",
        0,
        1,
        1,
        32,
        32,
        0,
        0,
        1,
        32,
        len(icon),
        7,
    )
    group_cursor = (
        struct.pack("<HHH", 0, 2, 1)
        + struct.pack("<HHHHIH", 32, 64, 1, 1, 128, 8)
    )
    manifest = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<assembly manifestVersion="1.0"/>'
    ).encode("utf-8")

    def branch(payload: bytes, *, resource_id: int = 1) -> list[_Entry]:
        return [(resource_id, [(0x0409, _Leaf(payload, code_page=1200))])]

    return [
        ("CUSTOM_TYPE", branch(b"custom payload", resource_id=9)),
        (2, branch(bitmap_core)),
        (3, branch(icon, resource_id=7)),
        (5, branch(_make_dialog_payload())),
        (6, branch(_make_string_payload(), resource_id=2)),
        (12, branch(group_cursor)),
        (14, branch(group_icon)),
        (16, branch(_make_version_payload())),
        (24, branch(manifest)),
    ]


def _walk(root: ResourceNode) -> list[ResourceNode]:
    nodes = [root]
    for child in root.children:
        nodes.extend(_walk(child))
    return nodes


class ResourceDirectoryParserTests(unittest.TestCase):
    def _parse_fixture(
        self,
        *,
        pe32_plus: bool,
    ) -> tuple[ResourceNode, bytes, int]:
        image, resource_size = _ResourceFixtureBuilder().build(
            _standard_entries()
        )
        root = ResourceDirectoryParser(
            image,
            _make_optional_header(
                pe32_plus=pe32_plus,
                resource_size=resource_size,
            ),
            (_make_section(),),
        ).parse()
        self.assertIsNotNone(root)
        assert root is not None
        return root, image, resource_size

    def test_parses_complete_tree_and_useful_resource_content(self) -> None:
        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus):
                root, _, _ = self._parse_fixture(pe32_plus=pe32_plus)
                self.assertEqual(root.name, "Resources")
                self.assertEqual(root.level, 0)
                self.assertTrue(root.is_directory)
                self.assertEqual(root.characteristics, 0xAABBCCDD)
                self.assertEqual(root.timestamp, 0x5E2A5C00)
                self.assertEqual(root.major_version, 2)
                self.assertEqual(root.minor_version, 7)
                self.assertEqual(root.number_of_named_entries, 1)
                self.assertEqual(root.number_of_id_entries, 8)
                self.assertEqual(root.children[0].name, "CUSTOM_TYPE")
                self.assertIsNone(root.children[0].identifier)

                leaves = {
                    node.data.resource_type: node
                    for node in _walk(root)
                    if node.data is not None
                }
                self.assertEqual(
                    set(leaves),
                    {
                        "CUSTOM_TYPE",
                        "RT_BITMAP",
                        "RT_ICON",
                        "RT_DIALOG",
                        "RT_STRING",
                        "RT_GROUP_CURSOR",
                        "RT_GROUP_ICON",
                        "RT_VERSION",
                        "RT_MANIFEST",
                    },
                )
                for leaf in leaves.values():
                    assert leaf.data is not None
                    self.assertFalse(leaf.is_directory)
                    self.assertEqual(leaf.level, 3)
                    self.assertIsNotNone(leaf.data.file_offset)
                    self.assertEqual(leaf.data.code_page, 1200)
                    self.assertGreater(leaf.data.size, 0)

                icon = leaves["RT_ICON"].data
                assert icon is not None
                self.assertIn("32\u00d732", icon.summary)
                self.assertIn("32 bpp", icon.summary)

                bitmap = leaves["RT_BITMAP"].data
                assert bitmap is not None
                self.assertIn("16\u00d724", bitmap.summary)
                self.assertIn("4 bpp", bitmap.summary)
                self.assertIn("DIB header size: 12", bitmap.content or "")

                icon_group = leaves["RT_GROUP_ICON"].data
                assert icon_group is not None
                self.assertEqual(icon_group.summary, "1 icon image")
                self.assertIn("ID 7", icon_group.content or "")

                cursor_group = leaves["RT_GROUP_CURSOR"].data
                assert cursor_group is not None
                self.assertEqual(cursor_group.summary, "1 cursor image")
                self.assertIn("ID 8", cursor_group.content or "")
                self.assertIn("32\u00d764", cursor_group.content or "")

                version = leaves["RT_VERSION"].data
                assert version is not None
                self.assertIn("1.2.3.4", version.summary)
                self.assertIn("CompanyName: Acme Corporation", version.content or "")
                self.assertIn(
                    "FileDescription: Resource fixture",
                    version.content or "",
                )

                manifest = leaves["RT_MANIFEST"].data
                assert manifest is not None
                self.assertIn("Manifest text", manifest.summary)
                self.assertIn("manifestVersion", manifest.content or "")

                dialog = leaves["RT_DIALOG"].data
                assert dialog is not None
                self.assertIn("About PE Explorer", dialog.summary)
                self.assertIn("180\u00d790", dialog.summary)
                self.assertIn("Controls: 2", dialog.content or "")

                strings = leaves["RT_STRING"].data
                assert strings is not None
                self.assertIn("block 2", strings.summary)
                self.assertIn("String 16: Hello", strings.content or "")
                self.assertIn("String 31: Last", strings.content or "")

    def test_returns_none_for_absent_resource_directory(self) -> None:
        image = bytes(RAW_OFFSET + RAW_SIZE)
        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus, case="zero-directory"):
                optional_header = _make_optional_header(
                    pe32_plus=pe32_plus,
                    resource_size=0,
                    resource_rva=0,
                )
                self.assertIsNone(
                    ResourceDirectoryParser(
                        image, optional_header, (_make_section(),)
                    ).parse()
                )

            with self.subTest(pe32_plus=pe32_plus, case="missing-entry"):
                optional_header = _make_optional_header(
                    pe32_plus=pe32_plus,
                    resource_size=0,
                    resource_rva=0,
                )
                optional_header = OptionalHeader(
                    **{
                        **{
                            field: getattr(optional_header, field)
                            for field in optional_header.__dataclass_fields__
                        },
                        "number_of_rva_and_sizes": 2,
                        "data_directories": optional_header.data_directories[:2],
                    }
                )
                self.assertIsNone(
                    ResourceDirectoryParser(
                        image, optional_header, (_make_section(),)
                    ).parse()
                )

    def test_rejects_invalid_directory_ranges_and_entry_layout(self) -> None:
        root, image_bytes, resource_size = self._parse_fixture(pe32_plus=False)
        del root
        cases: list[tuple[str, bytearray, int, int, str]] = []

        mismatched_image = bytearray(image_bytes)
        cases.append(("missing RVA", mismatched_image, 0, resource_size, "both"))
        cases.append(("missing size", mismatched_image, RESOURCE_RVA, 0, "both"))
        cases.append(("tiny", mismatched_image, RESOURCE_RVA, 15, "too small"))

        out_of_range = bytearray(image_bytes)
        struct.pack_into(
            "<I",
            out_of_range,
            RAW_OFFSET + 16 + 4,
            0x80000000 | (resource_size + 4),
        )
        cases.append(
            ("child offset", out_of_range, RESOURCE_RVA, resource_size, "range")
        )

        bad_order = bytearray(image_bytes)
        struct.pack_into("<I", bad_order, RAW_OFFSET + 16, 7)
        cases.append(
            ("named ordering", bad_order, RESOURCE_RVA, resource_size, "named-entry")
        )

        reserved_id = bytearray(image_bytes)
        # The first numeric root entry follows the one named root entry.
        struct.pack_into("<I", reserved_id, RAW_OFFSET + 24, 0x00010003)
        cases.append(
            ("reserved ID", reserved_id, RESOURCE_RVA, resource_size, "reserved")
        )

        for label, image, rva, size, message in cases:
            with self.subTest(case=label):
                with self.assertRaisesRegex(PEFormatError, message):
                    ResourceDirectoryParser(
                        bytes(image),
                        _make_optional_header(
                            pe32_plus=False,
                            resource_size=size,
                            resource_rva=rva,
                        ),
                        (_make_section(),),
                    ).parse()

    def test_rejects_cycles_depth_excess_and_bad_payload_rvas(self) -> None:
        image, resource_size = _ResourceFixtureBuilder().build(
            [(3, [(1, [(0x0409, _Leaf(b"data"))])])]
        )

        cyclic = bytearray(image)
        # Root's first entry points back to the root directory itself.
        struct.pack_into("<I", cyclic, RAW_OFFSET + 20, 0x80000000)
        with self.assertRaisesRegex(PEFormatError, "cyclic"):
            ResourceDirectoryParser(
                bytes(cyclic),
                _make_optional_header(
                    pe32_plus=False,
                    resource_size=resource_size,
                ),
                (_make_section(),),
            ).parse()

        with patch.object(ResourceDirectoryParser, "MAX_DEPTH", 1):
            with self.assertRaisesRegex(PEFormatError, "maximum depth"):
                ResourceDirectoryParser(
                    image,
                    _make_optional_header(
                        pe32_plus=True,
                        resource_size=resource_size,
                    ),
                    (_make_section(),),
                ).parse()

        with patch.object(ResourceDirectoryParser, "MAX_NODES", 2):
            with self.assertRaisesRegex(PEFormatError, "node limit"):
                ResourceDirectoryParser(
                    image,
                    _make_optional_header(
                        pe32_plus=False,
                        resource_size=resource_size,
                    ),
                    (_make_section(),),
                ).parse()

        invalid_payload = bytearray(image)
        # Locate the only data entry via the three directory entries.
        first_directory = struct.unpack_from("<I", invalid_payload, RAW_OFFSET + 20)[0]
        first_directory &= 0x7FFFFFFF
        second_directory = struct.unpack_from(
            "<I", invalid_payload, RAW_OFFSET + first_directory + 20
        )[0] & 0x7FFFFFFF
        data_entry = struct.unpack_from(
            "<I", invalid_payload, RAW_OFFSET + second_directory + 20
        )[0] & 0x7FFFFFFF
        struct.pack_into("<I", invalid_payload, RAW_OFFSET + data_entry, 0x90000000)
        with self.assertRaisesRegex(PEFormatError, "payload RVA"):
            ResourceDirectoryParser(
                bytes(invalid_payload),
                _make_optional_header(
                    pe32_plus=False,
                    resource_size=resource_size,
                ),
                (_make_section(),),
            ).parse()

    def test_rejects_truncated_or_invalid_named_entries(self) -> None:
        image, resource_size = _ResourceFixtureBuilder().build(
            [("NAMED", [(1, _Leaf(b"value"))])]
        )
        mutable = bytearray(image)
        name_value = struct.unpack_from("<I", mutable, RAW_OFFSET + 16)[0]
        name_offset = name_value & 0x7FFFFFFF

        truncated_name = bytearray(mutable)
        struct.pack_into(
            "<H", truncated_name, RAW_OFFSET + name_offset, resource_size
        )
        with self.assertRaisesRegex(PEFormatError, "UTF-16 name"):
            ResourceDirectoryParser(
                bytes(truncated_name),
                _make_optional_header(
                    pe32_plus=False,
                    resource_size=resource_size,
                ),
                (_make_section(),),
            ).parse()

        invalid_utf16 = bytearray(mutable)
        struct.pack_into("<H", invalid_utf16, RAW_OFFSET + name_offset, 1)
        invalid_utf16[RAW_OFFSET + name_offset + 2 : RAW_OFFSET + name_offset + 4] = (
            b"\x00\xD8"
        )
        with self.assertRaisesRegex(PEFormatError, "valid UTF-16LE"):
            ResourceDirectoryParser(
                bytes(invalid_utf16),
                _make_optional_header(
                    pe32_plus=True,
                    resource_size=resource_size,
                ),
                (_make_section(),),
            ).parse()


if __name__ == "__main__":
    unittest.main()
