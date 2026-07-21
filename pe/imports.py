"""Manual parsing of the PE import directory and thunk tables."""

import struct
from typing import Literal, cast

from pe.errors import PEFormatError
from pe.models import (
    ImportDescriptor,
    ImportedFunction,
    OptionalHeader,
    SectionHeader,
)
from pe.rva import RVAResolver


IMPORT_DIRECTORY_INDEX = 1


class ImportTableParser:
    """Parse IMAGE_IMPORT_DESCRIPTOR and IMAGE_THUNK_DATA structures."""

    _DESCRIPTOR = struct.Struct("<IIIII")
    _PE32_THUNK = struct.Struct("<I")
    _PE32_PLUS_THUNK = struct.Struct("<Q")
    _HINT = struct.Struct("<H")
    _PE32_ORDINAL_FLAG = 0x80000000
    _PE32_PLUS_ORDINAL_FLAG = 0x8000000000000000

    def __init__(
        self,
        data: bytes,
        optional_header: OptionalHeader,
        sections: tuple[SectionHeader, ...],
    ) -> None:
        self._optional_header = optional_header
        self._resolver = RVAResolver(
            data,
            sections,
            optional_header.size_of_headers,
        )

    def parse(self) -> tuple[ImportDescriptor, ...]:
        """Return every terminated descriptor in the import data directory."""

        directories = self._optional_header.data_directories
        if len(directories) <= IMPORT_DIRECTORY_INDEX:
            return ()

        directory = directories[IMPORT_DIRECTORY_INDEX]
        if directory.virtual_address == 0 and directory.size == 0:
            return ()
        if directory.virtual_address == 0 or directory.size == 0:
            raise PEFormatError(
                "Import directory RVA and size must either both be zero or "
                "both be nonzero."
            )
        if directory.size < self._DESCRIPTOR.size:
            raise PEFormatError(
                "Import directory is too small for an import descriptor."
            )

        self._resolver.file_offset(
            directory.virtual_address,
            directory.size,
            "import directory",
        )
        descriptor_slots = directory.size // self._DESCRIPTOR.size

        descriptors: list[ImportDescriptor] = []
        for descriptor_index in range(descriptor_slots):
            descriptor_rva = (
                directory.virtual_address
                + descriptor_index * self._DESCRIPTOR.size
            )
            values = self._resolver.unpack(
                self._DESCRIPTOR,
                descriptor_rva,
                f"import descriptor {descriptor_index + 1}",
            )
            (
                original_first_thunk,
                timestamp,
                forwarder_chain,
                name_rva,
                first_thunk,
            ) = cast(tuple[int, int, int, int, int], values)

            if not any(values):
                return tuple(descriptors)

            if name_rva == 0:
                raise PEFormatError(
                    f"Import descriptor {descriptor_index + 1} has no DLL name RVA."
                )
            if first_thunk == 0:
                raise PEFormatError(
                    f"Import descriptor {descriptor_index + 1} has no "
                    "FirstThunk RVA."
                )

            encoded_dll_name = self._resolver.read_c_string(
                name_rva,
                f"import descriptor {descriptor_index + 1} DLL name",
            )
            if not encoded_dll_name:
                raise PEFormatError(
                    f"Import descriptor {descriptor_index + 1} has an empty "
                    "DLL name."
                )
            dll_name = self._decode_ascii(
                encoded_dll_name,
                f"import descriptor {descriptor_index + 1} DLL name",
            )
            functions = self._read_functions(
                descriptor_index=descriptor_index,
                original_first_thunk=original_first_thunk,
                first_thunk=first_thunk,
                timestamp=timestamp,
            )
            descriptors.append(
                ImportDescriptor(
                    index=descriptor_index + 1,
                    dll_name=dll_name,
                    original_first_thunk=original_first_thunk,
                    timestamp=timestamp,
                    forwarder_chain=forwarder_chain,
                    name_rva=name_rva,
                    first_thunk=first_thunk,
                    functions=functions,
                )
            )

        raise PEFormatError(
            "Import directory has no null IMAGE_IMPORT_DESCRIPTOR terminator."
        )

    def _read_functions(
        self,
        descriptor_index: int,
        original_first_thunk: int,
        first_thunk: int,
        timestamp: int,
    ) -> tuple[ImportedFunction, ...]:
        lookup_table_rva = original_first_thunk or first_thunk
        if lookup_table_rva == 0:
            return ()

        is_pe32_plus = self._optional_header.format == "PE32+"
        thunk = self._PE32_PLUS_THUNK if is_pe32_plus else self._PE32_THUNK
        ordinal_flag = (
            self._PE32_PLUS_ORDINAL_FLAG
            if is_pe32_plus
            else self._PE32_ORDINAL_FLAG
        )
        is_bound_table = original_first_thunk == 0 and timestamp != 0

        mapped = self._resolver.resolve(
            lookup_table_rva,
            f"import descriptor {descriptor_index + 1} lookup table",
        )
        thunk_slots = mapped.available_size // thunk.size
        functions: list[ImportedFunction] = []

        for function_index in range(thunk_slots):
            entry_rva = lookup_table_rva + function_index * thunk.size
            (raw_value_object,) = self._resolver.unpack(
                thunk,
                entry_rva,
                (
                    f"import descriptor {descriptor_index + 1} "
                    f"thunk {function_index + 1}"
                ),
            )
            raw_value = cast(int, raw_value_object)
            if raw_value == 0:
                self._resolver.file_offset(
                    first_thunk,
                    (function_index + 1) * thunk.size,
                    f"import descriptor {descriptor_index + 1} address table",
                )
                return tuple(functions)

            is_ordinal = bool(raw_value & ordinal_flag)
            kind: Literal["name", "ordinal", "bound_address"]
            ordinal: int | None = None
            hint: int | None = None
            function_name: str | None = None
            name_rva: int | None = None

            if is_bound_table:
                kind = "bound_address"
                is_ordinal = False
            elif is_ordinal:
                kind = "ordinal"
                reserved_bits = (raw_value & (ordinal_flag - 1)) & ~0xFFFF
                if reserved_bits:
                    raise PEFormatError(
                        f"Import descriptor {descriptor_index + 1} ordinal "
                        f"thunk {function_index + 1} has reserved bits set."
                    )
                ordinal = raw_value & 0xFFFF
            else:
                kind = "name"
                if is_pe32_plus and raw_value > 0x7FFFFFFF:
                    raise PEFormatError(
                        f"Import descriptor {descriptor_index + 1} name "
                        f"thunk {function_index + 1} has reserved bits set."
                    )
                name_rva = raw_value & (ordinal_flag - 1)
                (hint_object,) = self._resolver.unpack(
                    self._HINT,
                    name_rva,
                    (
                        f"import descriptor {descriptor_index + 1} "
                        f"function {function_index + 1} hint"
                    ),
                )
                hint = cast(int, hint_object)
                encoded_name = self._resolver.read_c_string(
                    name_rva + self._HINT.size,
                    (
                        f"import descriptor {descriptor_index + 1} "
                        f"function {function_index + 1} name"
                    ),
                )
                if not encoded_name:
                    raise PEFormatError(
                        f"Import descriptor {descriptor_index + 1} function "
                        f"{function_index + 1} has an empty name."
                    )
                function_name = self._decode_ascii(
                    encoded_name,
                    (
                        f"import descriptor {descriptor_index + 1} function "
                        f"{function_index + 1} name"
                    ),
                )

            functions.append(
                ImportedFunction(
                    index=function_index + 1,
                    kind=kind,
                    name=function_name,
                    ordinal=ordinal,
                    hint=hint,
                    is_ordinal=is_ordinal,
                    lookup_table_rva=entry_rva,
                    import_address_table_rva=(
                        first_thunk + function_index * thunk.size
                    ),
                    name_rva=name_rva,
                    raw_value=raw_value,
                )
            )

        raise PEFormatError(
            f"Import descriptor {descriptor_index + 1} thunk table has no "
            "null terminator."
        )

    @staticmethod
    def _decode_ascii(value: bytes, context: str) -> str:
        try:
            return value.decode("ascii")
        except UnicodeDecodeError as error:
            raise PEFormatError(f"{context} is not valid ASCII.") from error
