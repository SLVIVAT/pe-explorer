"""Safe conversion of PE relative virtual addresses to file offsets."""

from dataclasses import dataclass
import struct

from pe.errors import PEFormatError
from pe.models import SectionHeader


@dataclass(frozen=True, slots=True)
class MappedRange:
    """A file-backed range beginning at a requested RVA."""

    file_offset: int
    available_size: int


class RVAResolver:
    """Resolve RVAs through PE headers and section-table mappings."""

    def __init__(
        self,
        data: bytes,
        sections: tuple[SectionHeader, ...],
        size_of_headers: int,
    ) -> None:
        self._data = data
        self._sections = sections
        self._size_of_headers = size_of_headers

    def resolve(self, rva: int, context: str) -> MappedRange:
        """Resolve *rva* and report how many contiguous bytes are file-backed."""

        if not 0 <= rva <= 0xFFFFFFFF:
            raise PEFormatError(f"Invalid {context} RVA 0x{rva:X}.")

        if rva < self._size_of_headers:
            if rva >= len(self._data):
                raise PEFormatError(f"{context} RVA points beyond the file.")
            return MappedRange(
                file_offset=rva,
                available_size=min(
                    self._size_of_headers - rva,
                    len(self._data) - rva,
                ),
            )

        matching_sections: list[SectionHeader] = []
        for section in self._sections:
            mapped_size = max(section.virtual_size, section.size_of_raw_data)
            section_end = section.virtual_address + mapped_size
            if section_end > 0x100000000:
                raise PEFormatError("Section mapping exceeds the 32-bit RVA space.")
            if (
                section.virtual_address
                <= rva
                < section_end
            ):
                matching_sections.append(section)

        if len(matching_sections) > 1:
            raise PEFormatError(
                f"{context} RVA 0x{rva:08X} has overlapping section mappings."
            )

        if matching_sections:
            section = matching_sections[0]

            section_offset = rva - section.virtual_address
            if section_offset >= section.size_of_raw_data:
                raise PEFormatError(
                    f"{context} RVA points into uninitialized section data."
                )

            file_offset = section.pointer_to_raw_data + section_offset
            if file_offset >= len(self._data):
                raise PEFormatError(f"{context} RVA points beyond the file.")

            return MappedRange(
                file_offset=file_offset,
                available_size=min(
                    section.size_of_raw_data - section_offset,
                    len(self._data) - file_offset,
                ),
            )

        raise PEFormatError(f"{context} RVA 0x{rva:08X} is not mapped.")

    def file_offset(self, rva: int, size: int, context: str) -> int:
        """Resolve an RVA and require *size* contiguous file-backed bytes."""

        if size < 0:
            raise ValueError("size cannot be negative")
        if not 0 <= rva <= 0xFFFFFFFF:
            raise PEFormatError(f"Invalid {context} RVA 0x{rva:X}.")
        if size > 0x100000000 - rva:
            raise PEFormatError(f"{context} exceeds the 32-bit RVA space.")

        mapped = self.resolve(rva, context)
        if size > mapped.available_size:
            raise PEFormatError(f"Truncated or out-of-range {context}.")
        return mapped.file_offset

    def unpack(
        self,
        structure: struct.Struct,
        rva: int,
        context: str,
    ) -> tuple[object, ...]:
        """Unpack a little-endian structure addressed by RVA."""

        offset = self.file_offset(rva, structure.size, context)
        return structure.unpack_from(self._data, offset)

    def read_c_string(
        self,
        rva: int,
        context: str,
        max_length: int = 4096,
    ) -> bytes:
        """Read a null-terminated byte string without leaving its mapped range."""

        if max_length <= 0:
            raise ValueError("max_length must be positive")

        mapped = self.resolve(rva, context)
        readable_size = min(mapped.available_size, max_length)
        end_limit = mapped.file_offset + readable_size
        terminator = self._data.find(b"\x00", mapped.file_offset, end_limit)
        if terminator == -1:
            raise PEFormatError(
                f"Unterminated or excessively long {context} string."
            )
        return self._data[mapped.file_offset:terminator]
