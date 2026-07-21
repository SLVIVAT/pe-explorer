"""Manual parsing and presentation of the PE resource directory.

The resource directory is unusual among PE data directories: offsets stored in
its tree are relative to the start of the directory, while leaf payloads are
addressed by ordinary RVAs.  This module keeps those two address spaces
separate and bounds-checks both of them.
"""

from __future__ import annotations

import struct
from typing import Final, cast

from pe.errors import PEFormatError
from pe.models import (
    OptionalHeader,
    ResourceData,
    ResourceNode,
    SectionHeader,
)
from pe.rva import RVAResolver


RESOURCE_DIRECTORY_INDEX: Final = 2

# These names are defined by winuser.h.  Keeping the ``RT_`` prefix makes
# unknown and application-defined resource types unambiguous in the GUI.
RESOURCE_TYPE_NAMES: Final[dict[int, str]] = {
    1: "RT_CURSOR",
    2: "RT_BITMAP",
    3: "RT_ICON",
    4: "RT_MENU",
    5: "RT_DIALOG",
    6: "RT_STRING",
    7: "RT_FONTDIR",
    8: "RT_FONT",
    9: "RT_ACCELERATOR",
    10: "RT_RCDATA",
    11: "RT_MESSAGETABLE",
    12: "RT_GROUP_CURSOR",
    14: "RT_GROUP_ICON",
    16: "RT_VERSION",
    17: "RT_DLGINCLUDE",
    19: "RT_PLUGPLAY",
    20: "RT_VXD",
    21: "RT_ANICURSOR",
    22: "RT_ANIICON",
    23: "RT_HTML",
    24: "RT_MANIFEST",
    241: "RT_TOOLBAR",
}


class ResourceDirectoryParser:
    """Parse the complete ``IMAGE_RESOURCE_DIRECTORY`` hierarchy."""

    _DIRECTORY = struct.Struct("<IIHHHH")
    _ENTRY = struct.Struct("<II")
    _DATA_ENTRY = struct.Struct("<IIII")
    _WORD = struct.Struct("<H")
    _NAMED_FLAG = 0x80000000
    _SUBDIRECTORY_FLAG = 0x80000000
    _OFFSET_MASK = 0x7FFFFFFF

    # Real resource trees normally have three levels (type, name, language).
    # The larger limit accepts legal extensions but rules out malicious cycles
    # and recursion bombs before Python's own recursion limit is approached.
    MAX_DEPTH: Final = 16
    MAX_NODES: Final = 65_536
    MAX_CONTENT_CHARACTERS: Final = 262_144

    def __init__(
        self,
        data: bytes,
        optional_header: OptionalHeader,
        sections: tuple[SectionHeader, ...],
    ) -> None:
        self._data = data
        self._optional_header = optional_header
        self._resolver = RVAResolver(
            data,
            sections,
            optional_header.size_of_headers,
        )
        self._base_file_offset = 0
        self._directory_size = 0
        self._node_count = 0

    def parse(self) -> ResourceNode | None:
        """Return the root resource node, or ``None`` when it is absent."""

        directories = self._optional_header.data_directories
        if len(directories) <= RESOURCE_DIRECTORY_INDEX:
            return None

        directory = directories[RESOURCE_DIRECTORY_INDEX]
        resource_rva = directory.virtual_address
        resource_size = directory.size
        if resource_rva == 0 and resource_size == 0:
            return None
        if resource_rva == 0 or resource_size == 0:
            raise PEFormatError(
                "Resource directory RVA and size must either both be zero or "
                "both be nonzero."
            )
        if resource_size < self._DIRECTORY.size:
            raise PEFormatError(
                "Resource directory is too small for its root header."
            )

        self._base_file_offset = self._resolver.file_offset(
            resource_rva,
            resource_size,
            "resource directory",
        )
        self._directory_size = resource_size
        self._node_count = 0
        return self._parse_directory(
            relative_offset=0,
            name="Resources",
            identifier=None,
            level=0,
            resource_type=None,
            path_identifiers=(),
            active_directories=set(),
        )

    def _parse_directory(
        self,
        relative_offset: int,
        name: str,
        identifier: int | None,
        level: int,
        resource_type: str | None,
        path_identifiers: tuple[int, ...],
        active_directories: set[int],
    ) -> ResourceNode:
        if level > self.MAX_DEPTH:
            raise PEFormatError(
                f"Resource tree exceeds the maximum depth of {self.MAX_DEPTH}."
            )
        if relative_offset in active_directories:
            raise PEFormatError(
                "Resource directory contains a cyclic subdirectory reference."
            )
        self._claim_node()

        directory_offset = self._relative_file_offset(
            relative_offset,
            self._DIRECTORY.size,
            f"resource directory at offset 0x{relative_offset:X}",
        )
        values = self._DIRECTORY.unpack_from(self._data, directory_offset)
        (
            characteristics,
            timestamp,
            major_version,
            minor_version,
            number_of_named_entries,
            number_of_id_entries,
        ) = cast(tuple[int, int, int, int, int, int], values)

        entry_count = number_of_named_entries + number_of_id_entries
        if entry_count > self.MAX_NODES:
            raise PEFormatError(
                "Resource directory declares too many child entries."
            )
        entries_relative_offset = relative_offset + self._DIRECTORY.size
        self._relative_file_offset(
            entries_relative_offset,
            entry_count * self._ENTRY.size,
            f"entries for resource directory at offset 0x{relative_offset:X}",
        )

        active_directories.add(relative_offset)
        children: list[ResourceNode] = []
        try:
            for entry_index in range(entry_count):
                entry_relative_offset = (
                    entries_relative_offset + entry_index * self._ENTRY.size
                )
                entry_offset = self._relative_file_offset(
                    entry_relative_offset,
                    self._ENTRY.size,
                    f"resource entry {entry_index + 1} at level {level}",
                )
                name_value, target_value = cast(
                    tuple[int, int],
                    self._ENTRY.unpack_from(self._data, entry_offset),
                )
                is_named = bool(name_value & self._NAMED_FLAG)
                if entry_index < number_of_named_entries and not is_named:
                    raise PEFormatError(
                        "Resource directory named-entry count does not match "
                        "its entry ordering."
                    )
                if entry_index >= number_of_named_entries and is_named:
                    raise PEFormatError(
                        "Resource directory ID-entry count does not match its "
                        "entry ordering."
                    )

                child_level = level + 1
                if is_named:
                    child_identifier = None
                    child_name = self._read_resource_name(
                        name_value & self._OFFSET_MASK
                    )
                else:
                    if name_value & 0xFFFF0000:
                        raise PEFormatError(
                            "Resource ID entry has nonzero reserved bits."
                        )
                    child_identifier = name_value & 0xFFFF
                    child_name = self._format_identifier(
                        child_identifier,
                        child_level,
                    )

                child_resource_type = resource_type
                if level == 0:
                    child_resource_type = (
                        child_name
                        if child_identifier is None
                        else self._resource_type_name(child_identifier)
                    )
                    if child_identifier is not None:
                        child_name = (
                            f"{child_resource_type} ({child_identifier})"
                        )

                child_path = path_identifiers
                if child_identifier is not None:
                    child_path += (child_identifier,)

                target_relative_offset = target_value & self._OFFSET_MASK
                if target_value & self._SUBDIRECTORY_FLAG:
                    child = self._parse_directory(
                        relative_offset=target_relative_offset,
                        name=child_name,
                        identifier=child_identifier,
                        level=child_level,
                        resource_type=child_resource_type,
                        path_identifiers=child_path,
                        active_directories=active_directories,
                    )
                else:
                    child = self._parse_data_entry(
                        relative_offset=target_relative_offset,
                        name=child_name,
                        identifier=child_identifier,
                        level=child_level,
                        resource_type=child_resource_type or "RT_UNKNOWN",
                        path_identifiers=child_path,
                    )
                children.append(child)
        finally:
            active_directories.remove(relative_offset)

        return ResourceNode(
            name=name,
            identifier=identifier,
            level=level,
            is_directory=True,
            characteristics=characteristics,
            timestamp=timestamp,
            major_version=major_version,
            minor_version=minor_version,
            number_of_named_entries=number_of_named_entries,
            number_of_id_entries=number_of_id_entries,
            data=None,
            children=tuple(children),
        )

    def _parse_data_entry(
        self,
        relative_offset: int,
        name: str,
        identifier: int | None,
        level: int,
        resource_type: str,
        path_identifiers: tuple[int, ...],
    ) -> ResourceNode:
        if level > self.MAX_DEPTH:
            raise PEFormatError(
                f"Resource tree exceeds the maximum depth of {self.MAX_DEPTH}."
            )
        self._claim_node()
        entry_offset = self._relative_file_offset(
            relative_offset,
            self._DATA_ENTRY.size,
            f"resource data entry at offset 0x{relative_offset:X}",
        )
        data_rva, data_size, code_page, reserved = cast(
            tuple[int, int, int, int],
            self._DATA_ENTRY.unpack_from(self._data, entry_offset),
        )

        file_offset: int | None = None
        payload = b""
        if data_size:
            if data_rva == 0:
                raise PEFormatError(
                    "Nonempty resource data entry has a zero payload RVA."
                )
            file_offset = self._resolver.file_offset(
                data_rva,
                data_size,
                f"{resource_type} resource payload",
            )
            payload = self._data[file_offset : file_offset + data_size]
        elif data_rva:
            file_offset = self._resolver.file_offset(
                data_rva,
                0,
                f"empty {resource_type} resource payload",
            )

        summary, content = self._describe_payload(
            resource_type,
            payload,
            path_identifiers,
        )
        resource_data = ResourceData(
            rva=data_rva,
            size=data_size,
            code_page=code_page,
            reserved=reserved,
            file_offset=file_offset,
            resource_type=resource_type,
            summary=summary,
            content=content,
        )
        return ResourceNode(
            name=name,
            identifier=identifier,
            level=level,
            is_directory=False,
            characteristics=None,
            timestamp=None,
            major_version=None,
            minor_version=None,
            number_of_named_entries=0,
            number_of_id_entries=0,
            data=resource_data,
            children=(),
        )

    def _claim_node(self) -> None:
        self._node_count += 1
        if self._node_count > self.MAX_NODES:
            raise PEFormatError(
                f"Resource tree exceeds the {self.MAX_NODES}-node limit."
            )

    def _relative_file_offset(
        self,
        relative_offset: int,
        size: int,
        context: str,
    ) -> int:
        if relative_offset < 0 or size < 0:
            raise PEFormatError(f"Invalid negative {context} range.")
        if relative_offset > self._directory_size:
            raise PEFormatError(f"Out-of-range {context}.")
        if size > self._directory_size - relative_offset:
            raise PEFormatError(f"Truncated or out-of-range {context}.")
        return self._base_file_offset + relative_offset

    def _read_resource_name(self, relative_offset: int) -> str:
        length_offset = self._relative_file_offset(
            relative_offset,
            self._WORD.size,
            "resource name length",
        )
        (length,) = cast(
            tuple[int], self._WORD.unpack_from(self._data, length_offset)
        )
        encoded_size = length * 2
        value_offset = self._relative_file_offset(
            relative_offset + self._WORD.size,
            encoded_size,
            "resource UTF-16 name",
        )
        try:
            return self._data[
                value_offset : value_offset + encoded_size
            ].decode("utf-16-le")
        except UnicodeDecodeError as error:
            raise PEFormatError(
                "Resource name is not valid UTF-16LE."
            ) from error

    @staticmethod
    def _resource_type_name(identifier: int) -> str:
        return RESOURCE_TYPE_NAMES.get(identifier, f"RT_UNKNOWN_{identifier}")

    @staticmethod
    def _format_identifier(identifier: int, level: int) -> str:
        if level == 3:
            return f"Language 0x{identifier:04X}"
        return f"ID {identifier}"

    def _describe_payload(
        self,
        resource_type: str,
        payload: bytes,
        path_identifiers: tuple[int, ...],
    ) -> tuple[str, str | None]:
        if not payload:
            return f"Empty {resource_type} resource", None

        try:
            if resource_type == "RT_ICON":
                return self._describe_icon(payload, is_icon=True)
            if resource_type == "RT_BITMAP":
                return self._describe_icon(payload, is_icon=False)
            if resource_type in {"RT_GROUP_ICON", "RT_GROUP_CURSOR"}:
                return self._describe_icon_group(payload, resource_type)
            if resource_type == "RT_VERSION":
                return self._describe_version(payload)
            if resource_type in {"RT_MANIFEST", "RT_HTML"}:
                text = self._decode_text(payload)
                kind = "Manifest" if resource_type == "RT_MANIFEST" else "HTML"
                return (
                    f"{kind} text ({len(text):,} characters)",
                    self._limit_content(text),
                )
            if resource_type == "RT_DIALOG":
                return self._describe_dialog(payload)
            if resource_type == "RT_STRING":
                return self._describe_string_table(payload, path_identifiers)
        except (OverflowError, struct.error, UnicodeError, ValueError):
            # Payload decoders enrich presentation; their failure must not
            # discard a structurally sound resource tree.
            pass
        return f"{resource_type} data ({len(payload):,} bytes)", None

    @staticmethod
    def _describe_icon(
        payload: bytes,
        *,
        is_icon: bool,
    ) -> tuple[str, str | None]:
        label = "Icon" if is_icon else "Bitmap"
        if (
            len(payload) >= 24
            and payload.startswith(b"\x89PNG\r\n\x1a\n")
            and payload[12:16] == b"IHDR"
        ):
            width, height = struct.unpack_from(">II", payload, 16)
            summary = f"{label} PNG: {width}\u00d7{height}, {len(payload):,} bytes"
            return summary, f"Format: PNG\nDimensions: {width}\u00d7{height}"

        if len(payload) >= 4:
            (header_size,) = struct.unpack_from("<I", payload, 0)
            dib_fields: tuple[int, int, int, int] | None = None
            if header_size == 12 and len(payload) >= 12:
                _, width, stored_height, planes, bit_count = struct.unpack_from(
                    "<IHHHH",
                    payload,
                    0,
                )
                dib_fields = width, stored_height, planes, bit_count
            elif 40 <= header_size <= len(payload) and len(payload) >= 16:
                _, width, stored_height, planes, bit_count = struct.unpack_from(
                    "<IiiHH",
                    payload,
                    0,
                )
                dib_fields = width, stored_height, planes, bit_count

            if dib_fields is not None:
                width, stored_height, planes, bit_count = dib_fields
                if width and stored_height:
                    height = abs(stored_height)
                    if is_icon:
                        height //= 2
                    width = abs(width)
                    summary = (
                        f"{label} DIB: {width}\u00d7{height}, {bit_count} bpp, "
                        f"{len(payload):,} bytes"
                    )
                    content = (
                        f"DIB header size: {header_size}\n"
                        f"Dimensions: {width}\u00d7{height}\n"
                        f"Planes: {planes}\nBit depth: {bit_count}"
                    )
                    return summary, content
        return f"{label} image data ({len(payload):,} bytes)", None

    @staticmethod
    def _describe_icon_group(
        payload: bytes,
        resource_type: str,
    ) -> tuple[str, str | None]:
        if len(payload) < 6:
            return f"Malformed {resource_type} ({len(payload):,} bytes)", None
        reserved, image_type, count = struct.unpack_from("<HHH", payload, 0)
        required_size = 6 + count * 14
        if required_size > len(payload):
            return (
                f"Truncated {resource_type}: declares {count} images",
                None,
            )

        rows: list[str] = []
        for index in range(count):
            entry_offset = 6 + index * 14
            if resource_type == "RT_GROUP_CURSOR":
                (
                    width,
                    height,
                    planes,
                    bit_count,
                    bytes_in_resource,
                    image_id,
                ) = struct.unpack_from("<HHHHIH", payload, entry_offset)
                rows.append(
                    f"#{index + 1}: ID {image_id}, {width}\u00d7{height}, "
                    f"{bit_count} bpp, {bytes_in_resource:,} bytes"
                )
            else:
                (
                    width,
                    height,
                    color_count,
                    entry_reserved,
                    planes,
                    bit_count,
                    bytes_in_resource,
                    image_id,
                ) = struct.unpack_from("<BBBBHHIH", payload, entry_offset)
                display_width = width or 256
                display_height = height or 256
                rows.append(
                    f"#{index + 1}: ID {image_id}, {display_width}\u00d7"
                    f"{display_height}, {bit_count} bpp, "
                    f"{bytes_in_resource:,} bytes, {color_count} colors"
                )
                if entry_reserved:
                    rows[-1] += f", reserved={entry_reserved}"

        group_kind = (
            "cursor" if resource_type == "RT_GROUP_CURSOR" else "icon"
        )
        summary = f"{count} {group_kind} image{'s' if count != 1 else ''}"
        content = (
            f"Reserved: {reserved}\nType: {image_type}\n" + "\n".join(rows)
        )
        return summary, content

    def _describe_version(self, payload: bytes) -> tuple[str, str | None]:
        if len(payload) < 6:
            return f"Malformed version resource ({len(payload):,} bytes)", None

        block_length, value_length, value_type = struct.unpack_from(
            "<HHH", payload, 0
        )
        if block_length < 6 or block_length > len(payload):
            return f"Malformed version resource ({len(payload):,} bytes)", None
        try:
            key, key_end = self._read_utf16_z(payload, 6, block_length)
        except ValueError:
            return f"Malformed version resource ({len(payload):,} bytes)", None
        if key != "VS_VERSION_INFO":
            return f"Version resource ({len(payload):,} bytes)", f"Key: {key}"

        value_offset = self._align_four(key_end)
        value_size = value_length * (2 if value_type == 1 else 1)
        value_end = value_offset + value_size
        if value_end > block_length:
            return f"Malformed version resource ({len(payload):,} bytes)", None

        file_version: str | None = None
        product_version: str | None = None
        lines: list[str] = []
        if value_length >= 52 and value_offset + 52 <= block_length:
            fixed = struct.unpack_from("<13I", payload, value_offset)
            if fixed[0] == 0xFEEF04BD:
                file_version = self._version_quad(fixed[2], fixed[3])
                product_version = self._version_quad(fixed[4], fixed[5])
                lines.extend(
                    (
                        f"File version: {file_version}",
                        f"Product version: {product_version}",
                        f"File flags: 0x{fixed[7]:08X}",
                        f"File OS: 0x{fixed[8]:08X}",
                        f"File type: 0x{fixed[9]:08X}",
                    )
                )

        strings: list[tuple[str, str]] = []
        children_offset = self._align_four(value_end)
        if children_offset < block_length:
            self._collect_version_strings(
                payload,
                children_offset,
                block_length,
                strings,
                depth=0,
            )
        lines.extend(f"{key_name}: {value}" for key_name, value in strings)

        if file_version:
            summary = f"Version {file_version}"
            if product_version and product_version != file_version:
                summary += f" (product {product_version})"
            if strings:
                summary += f"; {len(strings)} string value(s)"
        else:
            summary = f"Version information; {len(strings)} string value(s)"
        return summary, self._limit_content("\n".join(lines)) or None

    def _collect_version_strings(
        self,
        payload: bytes,
        start: int,
        limit: int,
        result: list[tuple[str, str]],
        depth: int,
    ) -> None:
        if depth > 8:
            return
        cursor = start
        block_count = 0
        while cursor + 6 <= limit and block_count < 4096:
            block_count += 1
            length, value_length, value_type = struct.unpack_from(
                "<HHH", payload, cursor
            )
            if length == 0:
                return
            block_end = cursor + length
            if length < 6 or block_end > limit:
                return
            try:
                key, key_end = self._read_utf16_z(
                    payload, cursor + 6, block_end
                )
            except ValueError:
                return
            value_offset = self._align_four(key_end)
            value_size = value_length * (2 if value_type == 1 else 1)
            value_end = value_offset + value_size
            if value_end > block_end:
                return

            if value_type == 1 and value_length and key:
                try:
                    value = payload[value_offset:value_end].decode(
                        "utf-16-le"
                    ).rstrip("\x00")
                except UnicodeDecodeError:
                    value = ""
                if value and key not in {
                    "StringFileInfo",
                    "VarFileInfo",
                    "Translation",
                }:
                    result.append((key, value))

            child_offset = self._align_four(value_end)
            if child_offset < block_end:
                self._collect_version_strings(
                    payload,
                    child_offset,
                    block_end,
                    result,
                    depth + 1,
                )
            cursor = self._align_four(block_end)

    @staticmethod
    def _version_quad(ms: int, ls: int) -> str:
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"

    @staticmethod
    def _read_utf16_z(
        payload: bytes,
        start: int,
        limit: int,
    ) -> tuple[str, int]:
        cursor = start
        while cursor + 2 <= limit:
            if payload[cursor : cursor + 2] == b"\x00\x00":
                value = payload[start:cursor].decode("utf-16-le")
                return value, cursor + 2
            cursor += 2
        raise ValueError("unterminated UTF-16 string")

    @staticmethod
    def _align_four(value: int) -> int:
        return (value + 3) & ~3

    @staticmethod
    def _describe_dialog(payload: bytes) -> tuple[str, str | None]:
        is_extended = (
            len(payload) >= 4
            and struct.unpack_from("<H", payload, 0)[0] == 1
            and struct.unpack_from("<H", payload, 2)[0] == 0xFFFF
        )
        if is_extended:
            if len(payload) < 26:
                return f"Malformed extended dialog ({len(payload):,} bytes)", None
            (
                dialog_version,
                signature,
                help_id,
                extended_style,
                style,
                item_count,
                x,
                y,
                width,
                height,
            ) = struct.unpack_from("<HHIIIHhhhh", payload, 0)
            cursor = 26
            kind = "Extended dialog"
            extra = f"Dialog version: {dialog_version}\nHelp ID: {help_id}\n"
        else:
            if len(payload) < 18:
                return f"Malformed dialog ({len(payload):,} bytes)", None
            style, extended_style, item_count, x, y, width, height = (
                struct.unpack_from("<IIHhhhh", payload, 0)
            )
            signature = 0
            cursor = 18
            kind = "Dialog"
            extra = ""

        try:
            menu, cursor = ResourceDirectoryParser._read_dialog_field(
                payload, cursor
            )
            window_class, cursor = ResourceDirectoryParser._read_dialog_field(
                payload, cursor
            )
            title, _ = ResourceDirectoryParser._read_dialog_field(
                payload, cursor
            )
        except ValueError:
            return f"Malformed {kind.lower()} ({len(payload):,} bytes)", None

        display_title = title or "(untitled)"
        summary = (
            f"{kind}: {display_title}, {width}\u00d7{height} at ({x}, {y}), "
            f"{item_count} control{'s' if item_count != 1 else ''}"
        )
        content = (
            f"{extra}Signature: 0x{signature:04X}\n"
            f"Title: {display_title}\nMenu: {menu or '(none)'}\n"
            f"Class: {window_class or '(default)'}\n"
            f"Bounds: x={x}, y={y}, width={width}, height={height}\n"
            f"Controls: {item_count}\nStyle: 0x{style:08X}\n"
            f"Extended style: 0x{extended_style:08X}"
        )
        return summary, content

    @staticmethod
    def _read_dialog_field(payload: bytes, start: int) -> tuple[str, int]:
        if start + 2 > len(payload):
            raise ValueError("truncated dialog field")
        first = struct.unpack_from("<H", payload, start)[0]
        if first == 0:
            return "", start + 2
        if first == 0xFFFF:
            if start + 4 > len(payload):
                raise ValueError("truncated dialog ordinal")
            ordinal = struct.unpack_from("<H", payload, start + 2)[0]
            return f"Ordinal {ordinal}", start + 4
        return ResourceDirectoryParser._read_utf16_z(
            payload, start, len(payload)
        )

    @staticmethod
    def _describe_string_table(
        payload: bytes,
        path_identifiers: tuple[int, ...],
    ) -> tuple[str, str | None]:
        block_identifier = (
            path_identifiers[1] if len(path_identifiers) > 1 else None
        )
        cursor = 0
        values: list[tuple[int, str]] = []
        for index in range(16):
            if cursor + 2 > len(payload):
                return (
                    f"Truncated string table ({len(payload):,} bytes)",
                    "\n".join(f"String {key}: {value}" for key, value in values)
                    or None,
                )
            length = struct.unpack_from("<H", payload, cursor)[0]
            cursor += 2
            byte_length = length * 2
            if cursor + byte_length > len(payload):
                return (
                    f"Truncated string table ({len(payload):,} bytes)",
                    "\n".join(f"String {key}: {value}" for key, value in values)
                    or None,
                )
            value = payload[cursor : cursor + byte_length].decode("utf-16-le")
            cursor += byte_length
            if value:
                string_identifier = (
                    (block_identifier - 1) * 16 + index
                    if block_identifier is not None and block_identifier > 0
                    else index
                )
                values.append((string_identifier, value))

        block_text = (
            f" block {block_identifier}" if block_identifier is not None else ""
        )
        summary = (
            f"String table{block_text}: {len(values)} populated of 16 entries"
        )
        content = "\n".join(
            f"String {identifier}: {value}" for identifier, value in values
        )
        return summary, content or None

    @staticmethod
    def _decode_text(payload: bytes) -> str:
        if payload.startswith(b"\xef\xbb\xbf"):
            return payload.decode("utf-8-sig").rstrip("\x00")
        if payload.startswith(b"\xff\xfe"):
            return payload.decode("utf-16").rstrip("\x00")
        if payload.startswith(b"\xfe\xff"):
            return payload.decode("utf-16").rstrip("\x00")
        if len(payload) >= 4 and payload[1::2].count(0) > len(payload) // 4:
            return payload.decode("utf-16-le").rstrip("\x00")
        try:
            return payload.decode("utf-8").rstrip("\x00")
        except UnicodeDecodeError:
            return payload.decode("cp1252").rstrip("\x00")

    def _limit_content(self, value: str) -> str:
        if len(value) <= self.MAX_CONTENT_CHARACTERS:
            return value
        omitted = len(value) - self.MAX_CONTENT_CHARACTERS
        return (
            value[: self.MAX_CONTENT_CHARACTERS]
            + f"\n\n[Content truncated; {omitted:,} characters omitted]"
        )
