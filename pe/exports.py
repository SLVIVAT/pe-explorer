"""Manual parsing of the PE export directory and its related tables."""

from __future__ import annotations

import struct
from typing import cast

from pe.errors import PEFormatError
from pe.models import (
    ExportDirectory,
    ExportedFunction,
    OptionalHeader,
    SectionHeader,
)
from pe.rva import RVAResolver


EXPORT_DIRECTORY_INDEX = 0


class ExportTableParser:
    """Parse ``IMAGE_EXPORT_DIRECTORY`` and its three lookup tables."""

    _DIRECTORY = struct.Struct("<IIHHIIIIIII")
    _DWORD = struct.Struct("<I")
    _WORD = struct.Struct("<H")
    _MAX_STRING_LENGTH = 4096
    _RVA_LIMIT = 0x100000000

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

    def parse(self) -> ExportDirectory | None:
        """Return the parsed export directory, or ``None`` when absent."""

        directories = self._optional_header.data_directories
        if len(directories) <= EXPORT_DIRECTORY_INDEX:
            return None

        directory = directories[EXPORT_DIRECTORY_INDEX]
        directory_rva = directory.virtual_address
        directory_size = directory.size
        if directory_rva == 0 and directory_size == 0:
            return None
        if directory_rva == 0 or directory_size == 0:
            raise PEFormatError(
                "Export directory RVA and size must either both be zero or "
                "both be nonzero."
            )
        if directory_size < self._DIRECTORY.size:
            raise PEFormatError(
                "Export directory is too small for "
                "IMAGE_EXPORT_DIRECTORY."
            )
        if directory_size > self._RVA_LIMIT - directory_rva:
            raise PEFormatError("Export directory exceeds the 32-bit RVA space.")

        # Requiring the declared directory range up front prevents later string
        # and forwarder reads from accepting bytes outside its file-backed data.
        self._resolver.file_offset(
            directory_rva,
            directory_size,
            "export directory",
        )
        directory_end_rva = directory_rva + directory_size

        values = self._resolver.unpack(
            self._DIRECTORY,
            directory_rva,
            "IMAGE_EXPORT_DIRECTORY",
        )
        (
            characteristics,
            timestamp,
            major_version,
            minor_version,
            name_rva,
            ordinal_base,
            address_table_entries,
            number_of_name_pointers,
            export_address_table_rva,
            name_pointer_rva,
            ordinal_table_rva,
        ) = cast(tuple[int, ...], values)

        if name_rva == 0:
            raise PEFormatError("Export directory has no DLL name RVA.")
        encoded_dll_name = self._resolver.read_c_string(
            name_rva,
            "export DLL name",
            self._MAX_STRING_LENGTH,
        )
        if not encoded_dll_name:
            raise PEFormatError("Export directory has an empty DLL name.")
        dll_name = self._decode_ascii(encoded_dll_name, "Export DLL name")

        function_rvas = self._read_dword_table(
            export_address_table_rva,
            address_table_entries,
            "export address table",
        )
        names_by_ordinal = self._read_names(
            name_pointer_rva=name_pointer_rva,
            ordinal_table_rva=ordinal_table_rva,
            number_of_names=number_of_name_pointers,
            number_of_functions=address_table_entries,
        )

        functions: list[ExportedFunction] = []
        for ordinal_index, function_rva in enumerate(function_rvas):
            if ordinal_base > 0xFFFFFFFF - ordinal_index:
                raise PEFormatError(
                    "Export ordinal base and address-table index exceed the "
                    "32-bit ordinal space."
                )

            names = tuple(names_by_ordinal[ordinal_index])
            is_forwarder = (
                function_rva != 0
                and directory_rva <= function_rva < directory_end_rva
            )
            forwarder: str | None = None
            if is_forwarder:
                forwarder = self._read_bounded_ascii_string(
                    function_rva,
                    directory_end_rva,
                    f"export ordinal {ordinal_base + ordinal_index} forwarder",
                )
                if not forwarder:
                    raise PEFormatError(
                        f"Export ordinal {ordinal_base + ordinal_index} has "
                        "an empty forwarder string."
                    )

            functions.append(
                ExportedFunction(
                    index=ordinal_index + 1,
                    ordinal=ordinal_base + ordinal_index,
                    ordinal_index=ordinal_index,
                    name=names[0] if names else None,
                    names=names,
                    rva=function_rva,
                    is_forwarder=is_forwarder,
                    forwarder=forwarder,
                )
            )

        return ExportDirectory(
            characteristics=characteristics,
            timestamp=timestamp,
            major_version=major_version,
            minor_version=minor_version,
            name_rva=name_rva,
            dll_name=dll_name,
            ordinal_base=ordinal_base,
            address_table_entries=address_table_entries,
            number_of_name_pointers=number_of_name_pointers,
            export_address_table_rva=export_address_table_rva,
            name_pointer_rva=name_pointer_rva,
            ordinal_table_rva=ordinal_table_rva,
            functions=tuple(functions),
        )

    def _read_names(
        self,
        *,
        name_pointer_rva: int,
        ordinal_table_rva: int,
        number_of_names: int,
        number_of_functions: int,
    ) -> list[list[str]]:
        names_by_ordinal: list[list[str]] = [
            [] for _ in range(number_of_functions)
        ]
        if number_of_names == 0:
            return names_by_ordinal
        if number_of_functions == 0:
            raise PEFormatError(
                "Export directory has names but no export address entries."
            )

        name_rvas = self._read_dword_table(
            name_pointer_rva,
            number_of_names,
            "export name pointer table",
        )
        ordinal_indexes = self._read_word_table(
            ordinal_table_rva,
            number_of_names,
            "export ordinal table",
        )

        for name_index, (export_name_rva, ordinal_index) in enumerate(
            zip(name_rvas, ordinal_indexes, strict=True),
            start=1,
        ):
            if ordinal_index >= number_of_functions:
                raise PEFormatError(
                    f"Export name {name_index} references ordinal index "
                    f"{ordinal_index}, outside the export address table."
                )
            if export_name_rva == 0:
                raise PEFormatError(
                    f"Export name pointer {name_index} has a zero RVA."
                )

            encoded_name = self._resolver.read_c_string(
                export_name_rva,
                f"export name {name_index}",
                self._MAX_STRING_LENGTH,
            )
            if not encoded_name:
                raise PEFormatError(f"Export name {name_index} is empty.")
            name = self._decode_ascii(
                encoded_name,
                f"Export name {name_index}",
            )
            names_by_ordinal[ordinal_index].append(name)

        return names_by_ordinal

    def _read_dword_table(
        self,
        table_rva: int,
        count: int,
        context: str,
    ) -> tuple[int, ...]:
        return self._read_integer_table(
            table_rva,
            count,
            self._DWORD,
            context,
        )

    def _read_word_table(
        self,
        table_rva: int,
        count: int,
        context: str,
    ) -> tuple[int, ...]:
        return self._read_integer_table(
            table_rva,
            count,
            self._WORD,
            context,
        )

    def _read_integer_table(
        self,
        table_rva: int,
        count: int,
        entry: struct.Struct,
        context: str,
    ) -> tuple[int, ...]:
        if count == 0:
            return ()
        if table_rva == 0:
            raise PEFormatError(f"{context.capitalize()} has a zero RVA.")

        table_size = count * entry.size
        table_offset = self._resolver.file_offset(
            table_rva,
            table_size,
            context,
        )
        return tuple(
            cast(
                int,
                entry.unpack_from(
                    self._data,
                    table_offset + index * entry.size,
                )[0],
            )
            for index in range(count)
        )

    def _read_bounded_ascii_string(
        self,
        rva: int,
        end_rva: int,
        context: str,
    ) -> str:
        """Read a C string that must terminate inside the export directory."""

        mapped = self._resolver.resolve(rva, context)
        readable_size = min(
            mapped.available_size,
            end_rva - rva,
            self._MAX_STRING_LENGTH,
        )
        end_offset = mapped.file_offset + readable_size
        terminator = self._data.find(b"\x00", mapped.file_offset, end_offset)
        if terminator == -1:
            raise PEFormatError(
                f"Unterminated or excessively long {context} string."
            )
        encoded = self._data[mapped.file_offset:terminator]
        return self._decode_ascii(encoded, context)

    @staticmethod
    def _decode_ascii(value: bytes, context: str) -> str:
        try:
            return value.decode("ascii")
        except UnicodeDecodeError as error:
            raise PEFormatError(f"{context} is not valid ASCII.") from error
