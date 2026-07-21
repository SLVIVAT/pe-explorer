"""Bidirectional conversion between PE file offsets, RVAs, and VAs.

This module operates on the parser's typed optional and section headers.  It
does not read or reinterpret PE structures, which keeps address conversion
usable by parsers, analyzers, and GUI views alike.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, TypedDict

from pe.errors import PEFormatError
from pe.models import OptionalHeader, PEImage, SectionHeader


AddressRegionKind = Literal["headers", "section"]
AddressBackingStatus = Literal["file-backed", "virtual-only", "truncated"]


class AddressRegionInfo(TypedDict):
    """Dictionary representation of :class:`AddressRegion`."""

    kind: AddressRegionKind
    section_index: int | None
    section_name: str | None
    rva_start: int
    rva_end: int
    va_start: int
    va_end: int
    file_offset_start: int | None
    file_offset_end: int | None


class AddressMappingInfo(TypedDict):
    """Dictionary representation of :class:`AddressMapping`."""

    region_kind: AddressRegionKind
    section_index: int | None
    section_name: str | None
    rva: int
    va: int
    file_offset: int | None
    offset_within_region: int
    status: AddressBackingStatus
    is_file_backed: bool
    available_virtual_size: int
    available_file_size: int


@dataclass(frozen=True, slots=True)
class AddressRegion:
    """One declared PE address region, expressed as half-open ranges.

    A section's RVA range uses ``max(VirtualSize, SizeOfRawData)``.  This
    mirrors the loader-oriented convention used elsewhere in the project and
    preserves addressability of both zero-filled virtual tails and raw
    alignment padding.
    """

    kind: AddressRegionKind
    section_index: int | None
    section_name: str | None
    rva_start: int
    rva_end: int
    va_start: int
    va_end: int
    file_offset_start: int | None
    file_offset_end: int | None

    def to_dict(self) -> AddressRegionInfo:
        """Return a presentation-friendly dictionary."""

        return {
            "kind": self.kind,
            "section_index": self.section_index,
            "section_name": self.section_name,
            "rva_start": self.rva_start,
            "rva_end": self.rva_end,
            "va_start": self.va_start,
            "va_end": self.va_end,
            "file_offset_start": self.file_offset_start,
            "file_offset_end": self.file_offset_end,
        }


@dataclass(frozen=True, slots=True)
class AddressMapping:
    """The resolved forms and backing state of one PE address."""

    region_kind: AddressRegionKind
    section_index: int | None
    section_name: str | None
    rva: int
    va: int
    file_offset: int | None
    offset_within_region: int
    status: AddressBackingStatus
    is_file_backed: bool
    available_virtual_size: int
    available_file_size: int

    def to_dict(self) -> AddressMappingInfo:
        """Return a presentation-friendly dictionary."""

        return {
            "region_kind": self.region_kind,
            "section_index": self.section_index,
            "section_name": self.section_name,
            "rva": self.rva,
            "va": self.va,
            "file_offset": self.file_offset,
            "offset_within_region": self.offset_within_region,
            "status": self.status,
            "is_file_backed": self.is_file_backed,
            "available_virtual_size": self.available_virtual_size,
            "available_file_size": self.available_file_size,
        }


class AddressingService:
    """Resolve addresses in an already-parsed PE32 or PE32+ image.

    ``file_size`` should be supplied when resolving a concrete file so that
    truncated declared ranges can be distinguished from file-backed bytes. If
    omitted, the service assumes all declared header and section raw ranges
    exist. Overlay bytes and gaps intentionally have no RVA and are rejected
    by file-offset conversion.
    """

    _MAX_RVA_EXCLUSIVE = 0x1_0000_0000
    _MAX_PE32_VA_EXCLUSIVE = 0x1_0000_0000
    _MAX_PE32_PLUS_VA_EXCLUSIVE = 0x1_0000_0000_0000_0000

    def __init__(
        self,
        optional_header: OptionalHeader,
        sections: Sequence[SectionHeader],
        file_size: int | None = None,
    ) -> None:
        self._optional_header = optional_header
        self._sections = tuple(sections)
        self._validate_image_fields()
        self._regions = self._build_regions()

        if file_size is not None and file_size < 0:
            raise ValueError("file_size cannot be negative")
        self._file_size = (
            file_size
            if file_size is not None
            else max(
                (
                    region.file_offset_end or 0
                    for region in self._regions
                ),
                default=0,
            )
        )

    @classmethod
    def from_image(cls, image: PEImage) -> AddressingService:
        """Build a service from a complete parsed image."""

        return cls(
            image.optional_header,
            image.sections,
            file_size=image.file_size,
        )

    @property
    def regions(self) -> tuple[AddressRegion, ...]:
        """Return immutable declared address-region descriptions."""

        return self._regions

    @property
    def file_size(self) -> int:
        """Return the physical or inferred file size used for bounds checks."""

        return self._file_size

    def rva_to_va(self, rva: int) -> int:
        """Convert an in-image RVA to a virtual address."""

        self._validate_rva(rva)
        va = self._optional_header.image_base + rva
        if va >= self._maximum_va_exclusive:
            raise PEFormatError(
                f"RVA 0x{rva:X} overflows the {self._format_name} VA space."
            )
        return va

    def va_to_rva(self, va: int) -> int:
        """Convert an in-image virtual address to an RVA."""

        if not isinstance(va, int) or va < 0:
            raise PEFormatError(f"Invalid VA {va!r}.")
        if va >= self._maximum_va_exclusive:
            raise PEFormatError(
                f"VA 0x{va:X} is outside the {self._format_name} VA space."
            )

        image_base = self._optional_header.image_base
        if va < image_base:
            raise PEFormatError(
                f"VA 0x{va:X} is below image base 0x{image_base:X}."
            )
        rva = va - image_base
        self._validate_rva(rva)
        return rva

    def rva_to_mapping(self, rva: int) -> AddressMapping:
        """Resolve an RVA, retaining virtual-only or truncated state."""

        self._validate_rva(rva)
        matches = tuple(
            region
            for region in self._regions
            if region.rva_start <= rva < region.rva_end
        )
        if not matches:
            raise PEFormatError(f"RVA 0x{rva:08X} is not mapped.")
        if len(matches) > 1:
            raise PEFormatError(
                f"RVA 0x{rva:08X} has overlapping virtual mappings."
            )
        return self._mapping_for_region(matches[0], rva)

    def va_to_mapping(self, va: int) -> AddressMapping:
        """Resolve a VA, retaining virtual-only or truncated state."""

        return self.rva_to_mapping(self.va_to_rva(va))

    def file_offset_to_mapping(self, file_offset: int) -> AddressMapping:
        """Resolve a physical file offset to its RVA and VA."""

        self._validate_file_offset(file_offset)
        matches = tuple(
            region
            for region in self._regions
            if region.file_offset_start is not None
            and region.file_offset_end is not None
            and region.file_offset_start <= file_offset < region.file_offset_end
        )
        if not matches:
            raise PEFormatError(
                f"File offset 0x{file_offset:X} is not mapped to an RVA."
            )
        if len(matches) > 1:
            raise PEFormatError(
                f"File offset 0x{file_offset:X} has overlapping raw mappings."
            )

        region = matches[0]
        assert region.file_offset_start is not None
        rva = region.rva_start + file_offset - region.file_offset_start
        return self._mapping_for_region(region, rva)

    # Resolver-style names make the service convenient at GUI and parser call
    # sites while the explicit conversion names remain self-documenting.
    resolve_rva = rva_to_mapping
    resolve_va = va_to_mapping
    resolve_file_offset = file_offset_to_mapping

    def rva_to_file_offset(self, rva: int, size: int = 1) -> int:
        """Convert an RVA and require ``size`` contiguous physical bytes."""

        self._validate_size(size)
        mapping = self.rva_to_mapping(rva)
        if mapping.file_offset is None:
            if mapping.status == "virtual-only":
                raise PEFormatError(
                    f"RVA 0x{rva:08X} is virtual-only and has no file offset."
                )
            raise PEFormatError(
                f"RVA 0x{rva:08X} lies beyond the physical file size."
            )
        if size > mapping.available_file_size:
            raise PEFormatError(
                f"RVA range 0x{rva:08X}+0x{size:X} is not fully file-backed."
            )
        return mapping.file_offset

    def file_offset_to_rva(self, file_offset: int, size: int = 1) -> int:
        """Convert a file offset and require ``size`` mapped physical bytes."""

        self._validate_size(size)
        mapping = self.file_offset_to_mapping(file_offset)
        if size > mapping.available_file_size:
            raise PEFormatError(
                f"File range 0x{file_offset:X}+0x{size:X} crosses a mapping "
                "boundary or the end of the file."
            )
        return mapping.rva

    def file_offset_to_va(self, file_offset: int, size: int = 1) -> int:
        """Convert a mapped file offset directly to a VA."""

        rva = self.file_offset_to_rva(file_offset, size)
        return self.rva_to_va(rva)

    @property
    def _format_name(self) -> str:
        return "PE32+" if self._optional_header.magic == 0x20B else "PE32"

    @property
    def _maximum_va_exclusive(self) -> int:
        if self._optional_header.magic == 0x20B:
            return self._MAX_PE32_PLUS_VA_EXCLUSIVE
        return self._MAX_PE32_VA_EXCLUSIVE

    def _validate_image_fields(self) -> None:
        header = self._optional_header
        if header.magic not in (0x10B, 0x20B):
            raise PEFormatError(
                f"Unsupported optional-header magic 0x{header.magic:X}."
            )
        if not 0 < header.size_of_image <= self._MAX_RVA_EXCLUSIVE:
            raise PEFormatError("SizeOfImage is outside the 32-bit RVA space.")
        if not 0 <= header.size_of_headers <= header.size_of_image:
            raise PEFormatError("SizeOfHeaders exceeds SizeOfImage.")
        if not 0 <= header.image_base < self._maximum_va_exclusive:
            raise PEFormatError(
                f"Image base is outside the {self._format_name} VA space."
            )
        if (
            header.image_base + header.size_of_image
            > self._maximum_va_exclusive
        ):
            raise PEFormatError(
                f"Image range overflows the {self._format_name} VA space."
            )

        for section in self._sections:
            values = (
                section.virtual_address,
                section.virtual_size,
                section.pointer_to_raw_data,
                section.size_of_raw_data,
            )
            if any(
                not isinstance(value, int)
                or value < 0
                or value >= self._MAX_RVA_EXCLUSIVE
                for value in values
            ):
                raise PEFormatError(
                    f"Section {section.name!r} contains an invalid address or size."
                )

            mapped_size = max(section.virtual_size, section.size_of_raw_data)
            rva_end = section.virtual_address + mapped_size
            if rva_end > self._MAX_RVA_EXCLUSIVE:
                raise PEFormatError(
                    f"Section {section.name!r} exceeds the 32-bit RVA space."
                )
            if rva_end > header.size_of_image:
                raise PEFormatError(
                    f"Section {section.name!r} exceeds SizeOfImage."
                )

    def _build_regions(self) -> tuple[AddressRegion, ...]:
        header = self._optional_header
        regions: list[AddressRegion] = []
        if header.size_of_headers:
            regions.append(
                AddressRegion(
                    kind="headers",
                    section_index=None,
                    section_name=None,
                    rva_start=0,
                    rva_end=header.size_of_headers,
                    va_start=header.image_base,
                    va_end=header.image_base + header.size_of_headers,
                    file_offset_start=0,
                    file_offset_end=header.size_of_headers,
                )
            )

        for section in self._sections:
            mapped_size = max(section.virtual_size, section.size_of_raw_data)
            if mapped_size == 0:
                continue
            rva_end = section.virtual_address + mapped_size
            raw_start: int | None = None
            raw_end: int | None = None
            if section.size_of_raw_data:
                raw_start = section.pointer_to_raw_data
                raw_end = raw_start + section.size_of_raw_data
            regions.append(
                AddressRegion(
                    kind="section",
                    section_index=section.index,
                    section_name=section.name,
                    rva_start=section.virtual_address,
                    rva_end=rva_end,
                    va_start=header.image_base + section.virtual_address,
                    va_end=header.image_base + rva_end,
                    file_offset_start=raw_start,
                    file_offset_end=raw_end,
                )
            )
        return tuple(regions)

    def _mapping_for_region(
        self,
        region: AddressRegion,
        rva: int,
    ) -> AddressMapping:
        offset_within_region = rva - region.rva_start
        file_offset: int | None = None
        available_file_size = 0
        status: AddressBackingStatus = "virtual-only"

        if (
            region.file_offset_start is not None
            and region.file_offset_end is not None
            and offset_within_region
            < region.file_offset_end - region.file_offset_start
        ):
            candidate = region.file_offset_start + offset_within_region
            if candidate < self._file_size:
                file_offset = candidate
                available_file_size = min(
                    region.file_offset_end - candidate,
                    self._file_size - candidate,
                )
                status = "file-backed"
            else:
                status = "truncated"

        return AddressMapping(
            region_kind=region.kind,
            section_index=region.section_index,
            section_name=region.section_name,
            rva=rva,
            va=self._optional_header.image_base + rva,
            file_offset=file_offset,
            offset_within_region=offset_within_region,
            status=status,
            is_file_backed=file_offset is not None,
            available_virtual_size=region.rva_end - rva,
            available_file_size=available_file_size,
        )

    def _validate_rva(self, rva: int) -> None:
        if not isinstance(rva, int) or not 0 <= rva < self._MAX_RVA_EXCLUSIVE:
            raise PEFormatError(f"Invalid RVA {rva!r}.")
        if rva >= self._optional_header.size_of_image:
            raise PEFormatError(
                f"RVA 0x{rva:08X} is outside SizeOfImage "
                f"0x{self._optional_header.size_of_image:X}."
            )

    def _validate_file_offset(self, file_offset: int) -> None:
        if not isinstance(file_offset, int) or file_offset < 0:
            raise PEFormatError(f"Invalid file offset {file_offset!r}.")
        if file_offset >= self._file_size:
            raise PEFormatError(
                f"File offset 0x{file_offset:X} is outside file size "
                f"0x{self._file_size:X}."
            )

    @staticmethod
    def _validate_size(size: int) -> None:
        if not isinstance(size, int) or size < 0:
            raise ValueError("size cannot be negative")


__all__ = [
    "AddressBackingStatus",
    "AddressMapping",
    "AddressMappingInfo",
    "AddressRegion",
    "AddressRegionInfo",
    "AddressRegionKind",
    "AddressingService",
]
