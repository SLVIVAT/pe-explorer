"""Structured extraction of Windows version-information resources."""

from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Any, Final

from pe.models import ResourceNode


_FIXED_FILE_INFO_SIGNATURE: Final = 0xFEEF04BD
_MAX_BLOCK_DEPTH: Final = 16
_MAX_BLOCKS: Final = 16_384
_MAX_VERSION_RESOURCES: Final = 1_024
_MAX_VERSION_PAYLOAD_BYTES: Final = 32 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class VersionString:
    """One key/value pair from a version resource string table."""

    key: str
    value: str

    def to_dict(self) -> dict[str, str]:
        return {"key": self.key, "value": self.value}


@dataclass(frozen=True, slots=True)
class VersionStringTable:
    """One language/code-page ``StringTable`` block."""

    translation: str
    language_id: int | None
    code_page: int | None
    strings: tuple[VersionString, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "translation": self.translation,
            "language_id": self.language_id,
            "code_page": self.code_page,
            "strings": [item.to_dict() for item in self.strings],
        }


@dataclass(frozen=True, slots=True)
class VersionInformation:
    """Consolidated presentation of every parsed ``RT_VERSION`` leaf."""

    available: bool
    company_name: str | None
    product_name: str | None
    file_description: str | None
    product_version: str | None
    file_version: str | None
    original_filename: str | None
    legal_copyright: str | None
    fixed_file_version: str | None
    fixed_product_version: str | None
    string_tables: tuple[VersionStringTable, ...]
    resource_count: int
    unavailable_reason: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "company_name": self.company_name,
            "product_name": self.product_name,
            "file_description": self.file_description,
            "product_version": self.product_version,
            "file_version": self.file_version,
            "original_filename": self.original_filename,
            "legal_copyright": self.legal_copyright,
            "fixed_file_version": self.fixed_file_version,
            "fixed_product_version": self.fixed_product_version,
            "string_tables": [table.to_dict() for table in self.string_tables],
            "resource_count": self.resource_count,
            "unavailable_reason": self.unavailable_reason,
        }


@dataclass(frozen=True, slots=True)
class _VersionBlock:
    key: str
    value_type: int
    value: bytes
    children: tuple[_VersionBlock, ...]


@dataclass(slots=True)
class _ParseBudget:
    blocks: int = 0


class _VersionFormatError(ValueError):
    pass


class VersionInfoParser:
    """Extract structured fields from all file-backed ``RT_VERSION`` leaves."""

    _FIELD_KEYS: Final[dict[str, str]] = {
        "company_name": "CompanyName",
        "product_name": "ProductName",
        "file_description": "FileDescription",
        "product_version": "ProductVersion",
        "file_version": "FileVersion",
        "original_filename": "OriginalFilename",
        "legal_copyright": "LegalCopyright",
    }

    def __init__(self, data: bytes, resources: ResourceNode | None) -> None:
        self._data = data
        self._resources = resources

    def parse(self) -> VersionInformation:
        leaves = tuple(self._version_leaves(self._resources))
        if not leaves:
            return self._unavailable("No RT_VERSION resource is present.")

        tables: list[VersionStringTable] = []
        fixed_file_version: str | None = None
        fixed_product_version: str | None = None
        parsed_resources = 0
        errors: list[str] = []
        payload_bytes = 0
        leaves_to_parse = leaves[:_MAX_VERSION_RESOURCES]
        if len(leaves) > _MAX_VERSION_RESOURCES:
            errors.append(
                f"only the first {_MAX_VERSION_RESOURCES:,} of "
                f"{len(leaves):,} RT_VERSION resources were inspected because "
                "the resource-count safety limit was reached"
            )
        image = memoryview(self._data)

        for leaf_index, leaf in enumerate(leaves_to_parse, start=1):
            resource_data = leaf.data
            assert resource_data is not None
            offset = resource_data.file_offset
            size = resource_data.size
            if offset is None:
                errors.append(f"resource {leaf_index} is not file-backed")
                continue
            if offset < 0 or size < 0 or offset > len(self._data) - size:
                errors.append(f"resource {leaf_index} has an invalid file range")
                continue
            if size > _MAX_VERSION_PAYLOAD_BYTES - payload_bytes:
                errors.append(
                    f"resource {leaf_index} was not inspected because its "
                    f"{size:,}-byte payload would exceed the cumulative "
                    f"{_MAX_VERSION_PAYLOAD_BYTES:,}-byte payload safety limit"
                )
                break

            payload_bytes += size
            payload = image[offset : offset + size]
            try:
                root = self._parse_block(
                    payload,
                    0,
                    len(payload),
                    depth=0,
                    budget=_ParseBudget(),
                )
                if root.key != "VS_VERSION_INFO":
                    raise _VersionFormatError(
                        "root key is not VS_VERSION_INFO"
                    )
                resource_file_version, resource_product_version = (
                    self._fixed_versions(root.value)
                )
                if fixed_file_version is None:
                    fixed_file_version = resource_file_version
                if fixed_product_version is None:
                    fixed_product_version = resource_product_version
                tables.extend(self._string_tables(root))
                parsed_resources += 1
            except _VersionFormatError as error:
                errors.append(f"resource {leaf_index}: {error}")

        if parsed_resources == 0:
            detail = "; ".join(errors) if errors else "unknown parse error"
            return self._unavailable(
                f"RT_VERSION data is unavailable or malformed: {detail}",
                resource_count=len(leaves),
            )

        selected = self._select_fields(tables)
        file_version = selected["file_version"] or fixed_file_version
        product_version = selected["product_version"] or fixed_product_version
        return VersionInformation(
            available=True,
            company_name=selected["company_name"],
            product_name=selected["product_name"],
            file_description=selected["file_description"],
            product_version=product_version,
            file_version=file_version,
            original_filename=selected["original_filename"],
            legal_copyright=selected["legal_copyright"],
            fixed_file_version=fixed_file_version,
            fixed_product_version=fixed_product_version,
            string_tables=tuple(tables),
            resource_count=len(leaves),
            unavailable_reason=(
                "; ".join(errors) if errors else None
            ),
        )

    @classmethod
    def _unavailable(
        cls,
        reason: str,
        *,
        resource_count: int = 0,
    ) -> VersionInformation:
        return VersionInformation(
            available=False,
            company_name=None,
            product_name=None,
            file_description=None,
            product_version=None,
            file_version=None,
            original_filename=None,
            legal_copyright=None,
            fixed_file_version=None,
            fixed_product_version=None,
            string_tables=(),
            resource_count=resource_count,
            unavailable_reason=reason,
        )

    @classmethod
    def _version_leaves(
        cls,
        node: ResourceNode | None,
    ) -> tuple[ResourceNode, ...]:
        if node is None:
            return ()
        leaves: list[ResourceNode] = []
        if node.data is not None and node.data.resource_type == "RT_VERSION":
            leaves.append(node)
        for child in node.children:
            leaves.extend(cls._version_leaves(child))
        return tuple(leaves)

    @classmethod
    def _parse_block(
        cls,
        payload: bytes | memoryview,
        start: int,
        limit: int,
        *,
        depth: int,
        budget: _ParseBudget,
    ) -> _VersionBlock:
        if depth > _MAX_BLOCK_DEPTH:
            raise _VersionFormatError("version block nesting is too deep")
        budget.blocks += 1
        if budget.blocks > _MAX_BLOCKS:
            raise _VersionFormatError("version resource has too many blocks")
        if start < 0 or limit > len(payload) or start + 6 > limit:
            raise _VersionFormatError("truncated version block header")

        length, value_length, value_type = struct.unpack_from(
            "<HHH", payload, start
        )
        if length < 6 or length > limit - start:
            raise _VersionFormatError("invalid version block length")
        block_end = start + length
        key, key_end = cls._read_utf16_z(payload, start + 6, block_end)
        value_start = cls._align_four(key_end)
        value_size = value_length * (2 if value_type == 1 else 1)
        if value_start > block_end or value_size > block_end - value_start:
            raise _VersionFormatError("version block value is out of range")
        value_end = value_start + value_size
        value = bytes(payload[value_start:value_end])

        children: list[_VersionBlock] = []
        cursor = cls._align_four(value_end)
        while cursor < block_end:
            remaining = payload[cursor:block_end]
            if not any(remaining):
                break
            if cursor + 6 > block_end:
                raise _VersionFormatError("truncated child version block")
            child = cls._parse_block(
                payload,
                cursor,
                block_end,
                depth=depth + 1,
                budget=budget,
            )
            child_length = struct.unpack_from("<H", payload, cursor)[0]
            children.append(child)
            next_cursor = cls._align_four(cursor + child_length)
            if next_cursor <= cursor:
                raise _VersionFormatError("non-advancing version block")
            cursor = next_cursor
        return _VersionBlock(
            key=key,
            value_type=value_type,
            value=value,
            children=tuple(children),
        )

    @staticmethod
    def _read_utf16_z(
        payload: bytes | memoryview,
        start: int,
        limit: int,
    ) -> tuple[str, int]:
        cursor = start
        while cursor + 2 <= limit:
            if payload[cursor : cursor + 2] == b"\x00\x00":
                try:
                    return (
                        bytes(payload[start:cursor]).decode("utf-16-le"),
                        cursor + 2,
                    )
                except UnicodeDecodeError as error:
                    raise _VersionFormatError(
                        "version block key is not valid UTF-16LE"
                    ) from error
            cursor += 2
        raise _VersionFormatError("unterminated version block key")

    @staticmethod
    def _align_four(value: int) -> int:
        return (value + 3) & ~3

    @staticmethod
    def _fixed_versions(value: bytes) -> tuple[str | None, str | None]:
        if len(value) < 52:
            return None, None
        fields = struct.unpack_from("<13I", value, 0)
        if fields[0] != _FIXED_FILE_INFO_SIGNATURE:
            return None, None
        return (
            VersionInfoParser._format_version(fields[2], fields[3]),
            VersionInfoParser._format_version(fields[4], fields[5]),
        )

    @staticmethod
    def _format_version(ms: int, ls: int) -> str:
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"

    @classmethod
    def _string_tables(
        cls,
        root: _VersionBlock,
    ) -> tuple[VersionStringTable, ...]:
        tables: list[VersionStringTable] = []
        for child in root.children:
            if child.key != "StringFileInfo":
                continue
            for table in child.children:
                language_id: int | None = None
                code_page: int | None = None
                if len(table.key) == 8:
                    try:
                        language_id = int(table.key[:4], 16)
                        code_page = int(table.key[4:], 16)
                    except ValueError:
                        language_id = None
                        code_page = None
                strings: list[VersionString] = []
                for item in table.children:
                    if item.value_type != 1:
                        continue
                    try:
                        value = item.value.decode("utf-16-le").rstrip("\x00")
                    except UnicodeDecodeError:
                        continue
                    strings.append(VersionString(item.key, value))
                tables.append(
                    VersionStringTable(
                        translation=table.key,
                        language_id=language_id,
                        code_page=code_page,
                        strings=tuple(strings),
                    )
                )
        return tuple(tables)

    @classmethod
    def _select_fields(
        cls,
        tables: list[VersionStringTable],
    ) -> dict[str, str | None]:
        values: dict[str, str | None] = {
            attribute: None for attribute in cls._FIELD_KEYS
        }
        reverse = {
            key.casefold(): attribute
            for attribute, key in cls._FIELD_KEYS.items()
        }
        for table in tables:
            for item in table.strings:
                attribute = reverse.get(item.key.casefold())
                if attribute is not None and values[attribute] is None and item.value:
                    values[attribute] = item.value
        return values


def parse_version_info(
    data: bytes,
    resources: ResourceNode | None,
) -> VersionInformation:
    """Convenience wrapper for callers that do not need a parser instance."""

    return VersionInfoParser(data, resources).parse()


__all__ = [
    "VersionInfoParser",
    "VersionInformation",
    "VersionString",
    "VersionStringTable",
    "parse_version_info",
]
