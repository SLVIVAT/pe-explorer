"""Manual Portable Executable parser.

Only Python's standard library is used for binary parsing. The parser covers
the DOS locator/signatures, complete COFF and PE32/PE32+ optional headers,
data directories, sections, imports, exports, resources, and explained static
security analysis.
"""

from pathlib import Path
import struct
from typing import cast

from pe.analysis import PEAnalyzer
from pe.constants import (
    DATA_DIRECTORY_NAMES,
    MACHINE_TYPES,
    PE32_MAGIC,
    PE32_PLUS_MAGIC,
)
from pe.directories import resolve_data_directory_statuses
from pe.errors import PEFormatError
from pe.exports import ExportTableParser
from pe.imports import ImportTableParser
from pe.models import (
    COFFHeader,
    DataDirectory,
    OptionalHeader,
    PEImage,
    PEInfo,
    SectionHeader,
)
from pe.resources import ResourceDirectoryParser


class PEParser:
    """Parse a PE image from disk using bounds-checked little-endian reads."""

    _COFF_HEADER_FORMAT = "<HHIIIHH"
    _COFF_HEADER_SIZE = struct.calcsize(_COFF_HEADER_FORMAT)
    _PE32_HEADER_FORMAT = "<HBB9I6H4I2H6I"
    _PE32_HEADER_SIZE = struct.calcsize(_PE32_HEADER_FORMAT)
    _PE32_PLUS_HEADER_FORMAT = "<HBB5IQ2I6H4I2H4Q2I"
    _PE32_PLUS_HEADER_SIZE = struct.calcsize(_PE32_PLUS_HEADER_FORMAT)
    _DATA_DIRECTORY_FORMAT = "<II"
    _DATA_DIRECTORY_SIZE = struct.calcsize(_DATA_DIRECTORY_FORMAT)
    _SECTION_HEADER_FORMAT = "<8sIIIIIIHHI"
    _SECTION_HEADER_SIZE = struct.calcsize(_SECTION_HEADER_FORMAT)

    def __init__(self, file_path: str | Path) -> None:
        self.file_path = Path(file_path)
        self.data: bytes = b""

    def parse(self) -> PEInfo:
        """Parse the image and return the backward-compatible dictionary API."""

        return self.parse_image().to_dict()

    def parse_image(self) -> PEImage:
        """Parse the image and return a typed, immutable representation."""

        self._read_file()

        pe_offset = self._read_pe_offset()
        self._read_pe_signature(pe_offset)

        coff_header = self._read_coff_header(pe_offset)
        optional_header_offset = pe_offset + 4 + self._COFF_HEADER_SIZE
        optional_header = self._read_optional_header(
            optional_header_offset,
            coff_header.optional_header_size,
        )
        section_table_offset = (
            optional_header_offset + coff_header.optional_header_size
        )
        sections = self._read_section_table(
            section_table_offset,
            coff_header.number_of_sections,
        )
        optional_header = resolve_data_directory_statuses(
            self.data,
            optional_header,
            sections,
        )
        imports = ImportTableParser(
            self.data,
            optional_header,
            sections,
        ).parse()
        exports = ExportTableParser(
            self.data,
            optional_header,
            sections,
        ).parse()
        resources = ResourceDirectoryParser(
            self.data,
            optional_header,
            sections,
        ).parse()
        analysis = PEAnalyzer(
            self.data,
            coff_header,
            optional_header,
            sections,
            imports,
            exports,
            resources,
        ).analyze()

        return PEImage(
            file_path=self.file_path,
            file_size=len(self.data),
            mz_signature="MZ",
            pe_offset=pe_offset,
            pe_signature="PE",
            coff_header=coff_header,
            optional_header=optional_header,
            sections=sections,
            imports=imports,
            exports=exports,
            resources=resources,
            analysis=analysis,
        )

    def _read_file(self) -> None:
        if not self.file_path.exists():
            raise FileNotFoundError(self.file_path)

        self.data = self.file_path.read_bytes()

        if len(self.data) < 64:
            raise PEFormatError("File is too small to contain a DOS header.")

        if self.data[:2] != b"MZ":
            raise PEFormatError("Invalid DOS signature; expected 'MZ'.")

    def _read_pe_offset(self) -> int:
        (offset,) = self._unpack_from("<I", 0x3C, "DOS PE-header offset")
        pe_offset = cast(int, offset)

        if pe_offset > len(self.data) - 4:
            raise PEFormatError("Invalid PE header offset.")

        return pe_offset

    def _read_pe_signature(self, offset: int) -> None:
        self._require_range(offset, 4, "PE signature")
        if self.data[offset : offset + 4] != b"PE\x00\x00":
            raise PEFormatError("Invalid PE signature; expected 'PE\\0\\0'.")

    def _read_coff_header(self, pe_offset: int) -> COFFHeader:
        start = pe_offset + 4
        values = self._unpack_from(
            self._COFF_HEADER_FORMAT,
            start,
            "COFF header",
        )
        (
            machine,
            number_of_sections,
            timestamp,
            pointer_to_symbol_table,
            number_of_symbols,
            optional_header_size,
            characteristics,
        ) = cast(tuple[int, int, int, int, int, int, int], values)

        return COFFHeader(
            machine=machine,
            number_of_sections=number_of_sections,
            timestamp=timestamp,
            pointer_to_symbol_table=pointer_to_symbol_table,
            number_of_symbols=number_of_symbols,
            optional_header_size=optional_header_size,
            characteristics=characteristics,
        )

    def _read_optional_header(self, offset: int, size: int) -> OptionalHeader:
        if size < 2:
            raise PEFormatError("Optional header is missing its magic value.")

        self._require_range(offset, size, "optional header")
        (raw_magic,) = self._unpack_from("<H", offset, "optional-header magic")
        magic = cast(int, raw_magic)

        if magic == PE32_MAGIC:
            return self._read_pe32_optional_header(offset, size)
        if magic == PE32_PLUS_MAGIC:
            return self._read_pe32_plus_optional_header(offset, size)

        raise PEFormatError(
            f"Unsupported optional-header magic 0x{magic:04X}; "
            "expected PE32 or PE32+."
        )

    def _read_pe32_optional_header(
        self,
        offset: int,
        declared_size: int,
    ) -> OptionalHeader:
        if declared_size < self._PE32_HEADER_SIZE:
            raise PEFormatError(
                "PE32 optional header is smaller than its 96-byte fixed part."
            )

        values = self._unpack_from(
            self._PE32_HEADER_FORMAT,
            offset,
            "PE32 optional header",
        )
        (
            magic,
            major_linker_version,
            minor_linker_version,
            size_of_code,
            size_of_initialized_data,
            size_of_uninitialized_data,
            address_of_entry_point,
            base_of_code,
            base_of_data,
            image_base,
            section_alignment,
            file_alignment,
            major_operating_system_version,
            minor_operating_system_version,
            major_image_version,
            minor_image_version,
            major_subsystem_version,
            minor_subsystem_version,
            win32_version_value,
            size_of_image,
            size_of_headers,
            checksum,
            subsystem,
            dll_characteristics,
            size_of_stack_reserve,
            size_of_stack_commit,
            size_of_heap_reserve,
            size_of_heap_commit,
            loader_flags,
            number_of_rva_and_sizes,
        ) = cast(tuple[int, ...], values)

        data_directories = self._read_data_directories(
            offset + self._PE32_HEADER_SIZE,
            declared_size - self._PE32_HEADER_SIZE,
            number_of_rva_and_sizes,
        )

        return OptionalHeader(
            magic=magic,
            format="PE32",
            major_linker_version=major_linker_version,
            minor_linker_version=minor_linker_version,
            size_of_code=size_of_code,
            size_of_initialized_data=size_of_initialized_data,
            size_of_uninitialized_data=size_of_uninitialized_data,
            address_of_entry_point=address_of_entry_point,
            base_of_code=base_of_code,
            base_of_data=base_of_data,
            image_base=image_base,
            section_alignment=section_alignment,
            file_alignment=file_alignment,
            major_operating_system_version=major_operating_system_version,
            minor_operating_system_version=minor_operating_system_version,
            major_image_version=major_image_version,
            minor_image_version=minor_image_version,
            major_subsystem_version=major_subsystem_version,
            minor_subsystem_version=minor_subsystem_version,
            win32_version_value=win32_version_value,
            size_of_image=size_of_image,
            size_of_headers=size_of_headers,
            checksum=checksum,
            subsystem=subsystem,
            dll_characteristics=dll_characteristics,
            size_of_stack_reserve=size_of_stack_reserve,
            size_of_stack_commit=size_of_stack_commit,
            size_of_heap_reserve=size_of_heap_reserve,
            size_of_heap_commit=size_of_heap_commit,
            loader_flags=loader_flags,
            number_of_rva_and_sizes=number_of_rva_and_sizes,
            data_directories=data_directories,
        )

    def _read_pe32_plus_optional_header(
        self,
        offset: int,
        declared_size: int,
    ) -> OptionalHeader:
        if declared_size < self._PE32_PLUS_HEADER_SIZE:
            raise PEFormatError(
                "PE32+ optional header is smaller than its 112-byte fixed part."
            )

        values = self._unpack_from(
            self._PE32_PLUS_HEADER_FORMAT,
            offset,
            "PE32+ optional header",
        )
        (
            magic,
            major_linker_version,
            minor_linker_version,
            size_of_code,
            size_of_initialized_data,
            size_of_uninitialized_data,
            address_of_entry_point,
            base_of_code,
            image_base,
            section_alignment,
            file_alignment,
            major_operating_system_version,
            minor_operating_system_version,
            major_image_version,
            minor_image_version,
            major_subsystem_version,
            minor_subsystem_version,
            win32_version_value,
            size_of_image,
            size_of_headers,
            checksum,
            subsystem,
            dll_characteristics,
            size_of_stack_reserve,
            size_of_stack_commit,
            size_of_heap_reserve,
            size_of_heap_commit,
            loader_flags,
            number_of_rva_and_sizes,
        ) = cast(tuple[int, ...], values)

        data_directories = self._read_data_directories(
            offset + self._PE32_PLUS_HEADER_SIZE,
            declared_size - self._PE32_PLUS_HEADER_SIZE,
            number_of_rva_and_sizes,
        )

        return OptionalHeader(
            magic=magic,
            format="PE32+",
            major_linker_version=major_linker_version,
            minor_linker_version=minor_linker_version,
            size_of_code=size_of_code,
            size_of_initialized_data=size_of_initialized_data,
            size_of_uninitialized_data=size_of_uninitialized_data,
            address_of_entry_point=address_of_entry_point,
            base_of_code=base_of_code,
            base_of_data=None,
            image_base=image_base,
            section_alignment=section_alignment,
            file_alignment=file_alignment,
            major_operating_system_version=major_operating_system_version,
            minor_operating_system_version=minor_operating_system_version,
            major_image_version=major_image_version,
            minor_image_version=minor_image_version,
            major_subsystem_version=major_subsystem_version,
            minor_subsystem_version=minor_subsystem_version,
            win32_version_value=win32_version_value,
            size_of_image=size_of_image,
            size_of_headers=size_of_headers,
            checksum=checksum,
            subsystem=subsystem,
            dll_characteristics=dll_characteristics,
            size_of_stack_reserve=size_of_stack_reserve,
            size_of_stack_commit=size_of_stack_commit,
            size_of_heap_reserve=size_of_heap_reserve,
            size_of_heap_commit=size_of_heap_commit,
            loader_flags=loader_flags,
            number_of_rva_and_sizes=number_of_rva_and_sizes,
            data_directories=data_directories,
        )

    def _read_data_directories(
        self,
        offset: int,
        available_size: int,
        count: int,
    ) -> tuple[DataDirectory, ...]:
        required_size = count * self._DATA_DIRECTORY_SIZE
        if required_size > available_size:
            raise PEFormatError(
                "Optional header declares more data directories than fit "
                "within SizeOfOptionalHeader."
            )

        directories: list[DataDirectory] = []
        for index in range(count):
            entry_offset = offset + index * self._DATA_DIRECTORY_SIZE
            values = self._unpack_from(
                self._DATA_DIRECTORY_FORMAT,
                entry_offset,
                f"data directory {index}",
            )
            virtual_address, size = cast(tuple[int, int], values)
            name = (
                DATA_DIRECTORY_NAMES[index]
                if index < len(DATA_DIRECTORY_NAMES)
                else f"Directory {index}"
            )
            directories.append(
                DataDirectory(
                    index=index,
                    name=name,
                    virtual_address=virtual_address,
                    size=size,
                )
            )

        return tuple(directories)

    def _read_section_table(
        self,
        offset: int,
        count: int,
    ) -> tuple[SectionHeader, ...]:
        table_size = count * self._SECTION_HEADER_SIZE
        self._require_range(offset, table_size, "section table")

        sections: list[SectionHeader] = []
        for index in range(count):
            entry_offset = offset + index * self._SECTION_HEADER_SIZE
            values = self._unpack_from(
                self._SECTION_HEADER_FORMAT,
                entry_offset,
                f"section header {index}",
            )
            (
                raw_name_value,
                virtual_size,
                virtual_address,
                size_of_raw_data,
                pointer_to_raw_data,
                pointer_to_relocations,
                pointer_to_linenumbers,
                number_of_relocations,
                number_of_linenumbers,
                characteristics,
            ) = values
            raw_name = cast(bytes, raw_name_value)
            encoded_name = raw_name.split(b"\x00", maxsplit=1)[0]
            name = encoded_name.decode("utf-8", errors="replace")

            sections.append(
                SectionHeader(
                    index=index + 1,
                    name=name,
                    raw_name=raw_name,
                    virtual_size=cast(int, virtual_size),
                    virtual_address=cast(int, virtual_address),
                    size_of_raw_data=cast(int, size_of_raw_data),
                    pointer_to_raw_data=cast(int, pointer_to_raw_data),
                    pointer_to_relocations=cast(int, pointer_to_relocations),
                    pointer_to_linenumbers=cast(int, pointer_to_linenumbers),
                    number_of_relocations=cast(int, number_of_relocations),
                    number_of_linenumbers=cast(int, number_of_linenumbers),
                    characteristics=cast(int, characteristics),
                )
            )

        return tuple(sections)

    def _unpack_from(
        self,
        format_string: str,
        offset: int,
        context: str,
    ) -> tuple[object, ...]:
        size = struct.calcsize(format_string)
        self._require_range(offset, size, context)
        return struct.unpack_from(format_string, self.data, offset)

    def _require_range(self, offset: int, size: int, context: str) -> None:
        if offset < 0 or size < 0 or offset > len(self.data) - size:
            raise PEFormatError(f"Truncated or out-of-range {context}.")


__all__ = ["MACHINE_TYPES", "PEFormatError", "PEParser"]
