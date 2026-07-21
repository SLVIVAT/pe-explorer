"""Pure formatting helpers for PE information displayed by the GUI."""

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Literal, cast

from pe.constants import (
    COFF_CHARACTERISTICS,
    DLL_CHARACTERISTICS,
    flag_names,
    section_characteristic_names,
    subsystem_name,
)
from pe.models import OptionalHeaderInfo, PEInfo, SectionHeaderInfo
from utils.file_utils import format_hex, format_size


FieldStyle = Literal["decimal", "hex16", "hex32", "wide"]
OptionalField = tuple[str, str, FieldStyle]

STANDARD_OPTIONAL_FIELDS: tuple[OptionalField, ...] = (
    ("Magic", "magic", "hex16"),
    ("MajorLinkerVersion", "major_linker_version", "decimal"),
    ("MinorLinkerVersion", "minor_linker_version", "decimal"),
    ("SizeOfCode", "size_of_code", "hex32"),
    ("SizeOfInitializedData", "size_of_initialized_data", "hex32"),
    ("SizeOfUninitializedData", "size_of_uninitialized_data", "hex32"),
    ("AddressOfEntryPoint", "address_of_entry_point", "hex32"),
    ("BaseOfCode", "base_of_code", "hex32"),
    ("BaseOfData", "base_of_data", "hex32"),
)

WINDOWS_OPTIONAL_FIELDS: tuple[OptionalField, ...] = (
    ("ImageBase", "image_base", "wide"),
    ("SectionAlignment", "section_alignment", "hex32"),
    ("FileAlignment", "file_alignment", "hex32"),
    (
        "MajorOperatingSystemVersion",
        "major_operating_system_version",
        "decimal",
    ),
    (
        "MinorOperatingSystemVersion",
        "minor_operating_system_version",
        "decimal",
    ),
    ("MajorImageVersion", "major_image_version", "decimal"),
    ("MinorImageVersion", "minor_image_version", "decimal"),
    ("MajorSubsystemVersion", "major_subsystem_version", "decimal"),
    ("MinorSubsystemVersion", "minor_subsystem_version", "decimal"),
    ("Win32VersionValue", "win32_version_value", "hex32"),
    ("SizeOfImage", "size_of_image", "hex32"),
    ("SizeOfHeaders", "size_of_headers", "hex32"),
    ("CheckSum", "checksum", "hex32"),
    ("Subsystem", "subsystem", "hex16"),
    ("DllCharacteristics", "dll_characteristics", "hex16"),
    ("SizeOfStackReserve", "size_of_stack_reserve", "wide"),
    ("SizeOfStackCommit", "size_of_stack_commit", "wide"),
    ("SizeOfHeapReserve", "size_of_heap_reserve", "wide"),
    ("SizeOfHeapCommit", "size_of_heap_commit", "wide"),
    ("LoaderFlags", "loader_flags", "hex32"),
    ("NumberOfRvaAndSizes", "number_of_rva_and_sizes", "decimal"),
)

SECTION_FIELDS: tuple[tuple[str, str], ...] = (
    ("#", "index"),
    ("Name", "name"),
    ("Raw Name", "raw_name"),
    ("VirtualSize", "virtual_size"),
    ("VirtualAddress", "virtual_address"),
    ("SizeOfRawData", "size_of_raw_data"),
    ("PointerToRawData", "pointer_to_raw_data"),
    ("PointerToRelocations", "pointer_to_relocations"),
    ("PointerToLinenumbers", "pointer_to_linenumbers"),
    ("NumberOfRelocations", "number_of_relocations"),
    ("NumberOfLinenumbers", "number_of_linenumbers"),
    ("Characteristics", "characteristics"),
)


def format_summary(info: PEInfo) -> str:
    """Build the overview text while retaining the original report fields."""

    coff = info["coff_header"]
    optional = info["optional_header"]
    imports = info.get("imports", [])
    imported_function_count = sum(
        len(descriptor["functions"]) for descriptor in imports
    )
    exports = info.get("exports")
    exported_function_count = (
        sum(function["rva"] != 0 for function in exports["functions"])
        if exports is not None
        else 0
    )
    resources = info.get("resources")
    analysis = info.get("analysis")
    present_directory_count = sum(
        directory["status"].startswith("Present")
        for directory in optional["data_directories"]
    )
    machine = coff["machine_name"]
    if not machine.startswith("Unknown ("):
        machine = f"{machine} ({format_hex(coff['machine'], 4)})"
    characteristics = format_flag_value(
        coff["characteristics"],
        4,
        COFF_CHARACTERISTICS,
    )

    lines = [
        "========== PE EXPLORER ==========",
        "",
        f"File name             : {info['file_name']}",
        f"File path             : {info['file_path']}",
        (
            "File size             : "
            f"{format_size(info['file_size'])} ({info['file_size']} bytes)"
        ),
        "",
        "----- DOS HEADER -----",
        f"Signature             : {info['mz_signature']}",
        f"PE Offset             : {format_hex(info['pe_offset'])}",
        "",
        "----- PE / COFF HEADER -----",
        f"Signature             : {info['pe_signature']}",
        f"Machine               : {machine}",
        f"Sections              : {coff['number_of_sections']}",
        (
            "TimeDateStamp         : "
            f"{format_hex(coff['timestamp'])} "
            f"({format_timestamp(coff['timestamp'])})"
        ),
        (
            "PointerToSymbolTable  : "
            f"{format_hex(coff['pointer_to_symbol_table'])}"
        ),
        f"NumberOfSymbols       : {coff['number_of_symbols']}",
        f"Optional Header Size  : {coff['optional_header_size']} bytes",
        f"Characteristics       : {characteristics}",
        "",
        "----- PARSED CONTENT -----",
        (
            "Optional Header       : "
            f"{optional['format']} ({format_hex(optional['magic'], 4)})"
        ),
        f"Data Directories      : {len(optional['data_directories'])}",
        f"Present Directories   : {present_directory_count}",
        f"Section Headers       : {len(info['sections'])}",
        f"Imported DLLs         : {len(imports)}",
        f"Imported Functions    : {imported_function_count}",
        f"Exported Functions    : {exported_function_count}",
        f"Resources             : {'Present' if resources else 'Absent'}",
        (
            "Overall Risk         : "
            + (
                f"{analysis['overall_risk']} ({analysis['risk_score']}/100)"
                if analysis is not None
                else "Unavailable"
            )
        ),
        "",
        (
            "Use the structure tabs for complete fields and Analysis for "
            "explained security conclusions."
        ),
    ]
    return "\n".join(lines)


def format_optional_value(
    field: str,
    value: int,
    style: FieldStyle,
    header: OptionalHeaderInfo,
) -> str:
    """Format one optional-header value with the correct PE bit width."""

    if style == "decimal":
        result = str(value)
    elif style == "hex16":
        result = format_hex(value, 4)
    elif style == "wide":
        result = format_hex(value, 16 if header["format"] == "PE32+" else 8)
    else:
        result = format_hex(value)

    if field == "magic":
        return f"{result} ({header['format']})"
    if field == "subsystem":
        description = subsystem_name(value)
        return description if description.startswith("Unknown (") else (
            f"{result} ({description})"
        )
    if field == "dll_characteristics":
        return format_flag_value(value, 4, DLL_CHARACTERISTICS)
    return result


def format_section_value(field: str, section: SectionHeaderInfo) -> str:
    """Format one section-table cell without losing its raw value."""

    value = cast(Mapping[str, object], section)[field]
    if field in {"index", "number_of_relocations", "number_of_linenumbers"}:
        return str(value)
    if field == "name":
        return str(value)
    if field == "raw_name":
        return cast_bytes(value).hex(" ").upper()
    return format_hex(int(value))


def section_characteristics_tooltip(value: int) -> str:
    """Return a readable tooltip for section characteristic flags."""

    names = section_characteristic_names(value)
    return ", ".join(names) if names else "No recognized flags"


def format_timestamp(timestamp: int) -> str:
    """Format the unsigned COFF timestamp as UTC without platform limits."""

    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    try:
        parsed = epoch + timedelta(seconds=timestamp)
    except OverflowError:
        return "outside supported UTC range"
    return parsed.strftime("%Y-%m-%d %H:%M:%S UTC")


def format_flag_value(
    value: int,
    digits: int,
    flags: Mapping[int, str],
) -> str:
    """Format a bit field followed by all recognized flag descriptions."""

    descriptions = flag_names(value, flags)
    raw = format_hex(value, digits)
    return f"{raw} ({', '.join(descriptions)})" if descriptions else raw


def cast_bytes(value: object) -> bytes:
    """Narrow a raw-name value emitted by the typed parser model."""

    if not isinstance(value, bytes):
        raise TypeError("Section raw_name must be bytes.")
    return value
