"""Validation and status classification for PE data-directory entries."""

from dataclasses import replace

from pe.errors import PEFormatError
from pe.models import DataDirectory, OptionalHeader, SectionHeader
from pe.rva import RVAResolver


CERTIFICATE_DIRECTORY_INDEX = 4
ARCHITECTURE_DIRECTORY_INDEX = 7
GLOBAL_POINTER_DIRECTORY_INDEX = 8
RESERVED_DIRECTORY_INDEX = 15
RESERVED_DIRECTORY_INDICES = {
    ARCHITECTURE_DIRECTORY_INDEX,
    RESERVED_DIRECTORY_INDEX,
}


def resolve_data_directory_statuses(
    data: bytes,
    optional_header: OptionalHeader,
    sections: tuple[SectionHeader, ...],
) -> OptionalHeader:
    """Return an optional header whose directories have useful status text."""

    resolver = RVAResolver(data, sections, optional_header.size_of_headers)
    resolved: list[DataDirectory] = []

    for directory in optional_header.data_directories:
        status = _directory_status(data, resolver, directory)
        resolved.append(replace(directory, status=status))

    return replace(optional_header, data_directories=tuple(resolved))


def _directory_status(
    data: bytes,
    resolver: RVAResolver,
    directory: DataDirectory,
) -> str:
    address = directory.virtual_address
    size = directory.size

    if address == 0 and size == 0:
        return "Absent"

    if directory.index in RESERVED_DIRECTORY_INDICES:
        return "Unexpected - reserved directory must be zero"

    if directory.index == GLOBAL_POINTER_DIRECTORY_INDEX:
        if address == 0:
            return "Invalid - Global Pointer RVA is zero"
        if size != 0:
            return "Invalid - Global Pointer size must be zero"
        try:
            resolver.file_offset(address, 1, directory.name)
        except PEFormatError as error:
            return f"Invalid - {error}"
        return "Present - Global Pointer RVA is file-backed"

    if address == 0 or size == 0:
        return "Invalid - RVA and size must both be nonzero"

    if directory.index == CERTIFICATE_DIRECTORY_INDEX:
        if address > len(data) or size > len(data) - address:
            return "Invalid - certificate file range is out of bounds"
        return "Present - file offset range is valid"

    try:
        resolver.file_offset(address, size, directory.name)
    except PEFormatError as error:
        return f"Invalid - {error}"

    return "Present - RVA range is file-backed"
