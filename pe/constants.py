"""Constants used by the Portable Executable parser and presentation layer."""

from collections.abc import Mapping


PE32_MAGIC = 0x010B
PE32_PLUS_MAGIC = 0x020B

MACHINE_TYPES: Mapping[int, str] = {
    0x0000: "Unknown",
    0x014C: "Intel 386",
    0x0160: "MIPS R3000 (big endian)",
    0x0162: "MIPS R3000",
    0x0166: "MIPS R4000",
    0x0168: "MIPS R10000",
    0x0169: "MIPS WCE v2",
    0x0184: "Alpha AXP",
    0x01A2: "Hitachi SH3",
    0x01A3: "Hitachi SH3 DSP",
    0x01A6: "Hitachi SH4",
    0x01A8: "Hitachi SH5",
    0x01C0: "ARM",
    0x01C2: "Thumb",
    0x01C4: "ARM Thumb-2",
    0x01D3: "Matsushita AM33",
    0x01F0: "PowerPC",
    0x01F1: "PowerPC with floating point support",
    0x0200: "Intel Itanium",
    0x0266: "MIPS16",
    0x0284: "Alpha AXP 64",
    0x0366: "MIPS with FPU",
    0x0466: "MIPS16 with FPU",
    0x0EBC: "EFI byte code",
    0x5032: "RISC-V 32-bit",
    0x5064: "RISC-V 64-bit",
    0x5128: "RISC-V 128-bit",
    0x6232: "LoongArch 32-bit",
    0x6264: "LoongArch 64-bit",
    0x8664: "x64",
    0x9041: "Mitsubishi M32R",
    0xA641: "ARM64EC",
    0xA64E: "ARM64X",
    0xAA64: "ARM64",
    0xC0EE: "Common Language Infrastructure",
}

DATA_DIRECTORY_NAMES: tuple[str, ...] = (
    "Export Table",
    "Import Table",
    "Resource Table",
    "Exception Table",
    "Certificate Table",
    "Base Relocation Table",
    "Debug",
    "Architecture",
    "Global Pointer",
    "Thread Local Storage",
    "Load Configuration",
    "Bound Import",
    "Import Address Table",
    "Delay Import Descriptor",
    "CLR Runtime Header",
    "Reserved",
)

SUBSYSTEM_TYPES: Mapping[int, str] = {
    0: "Unknown",
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI",
    5: "OS/2 CUI",
    7: "POSIX CUI",
    8: "Native Win9x driver",
    9: "Windows CE GUI",
    10: "EFI application",
    11: "EFI boot service driver",
    12: "EFI runtime driver",
    13: "EFI ROM image",
    14: "Xbox",
    16: "Windows boot application",
    17: "Xbox code catalog",
}

COFF_CHARACTERISTICS: Mapping[int, str] = {
    0x0001: "Relocations stripped",
    0x0002: "Executable image",
    0x0004: "Line numbers stripped",
    0x0008: "Local symbols stripped",
    0x0010: "Aggressive working-set trim",
    0x0020: "Large address aware",
    0x0080: "Bytes reversed (low)",
    0x0100: "32-bit machine",
    0x0200: "Debug information stripped",
    0x0400: "Run from swap on removable media",
    0x0800: "Run from swap on network media",
    0x1000: "System file",
    0x2000: "DLL",
    0x4000: "Uniprocessor only",
    0x8000: "Bytes reversed (high)",
}

DLL_CHARACTERISTICS: Mapping[int, str] = {
    0x0020: "High-entropy virtual addresses",
    0x0040: "Dynamic base",
    0x0080: "Code integrity checks",
    0x0100: "NX compatible",
    0x0200: "Isolation disabled",
    0x0400: "Structured exception handling disabled",
    0x0800: "Do not bind",
    0x1000: "AppContainer",
    0x2000: "WDM driver",
    0x4000: "Control Flow Guard",
    0x8000: "Terminal Server aware",
}

SECTION_CHARACTERISTICS: Mapping[int, str] = {
    0x00000008: "No padding",
    0x00000020: "Code",
    0x00000040: "Initialized data",
    0x00000080: "Uninitialized data",
    0x00000100: "Other linker information",
    0x00000200: "Linker information",
    0x00000800: "Remove from image",
    0x00001000: "COMDAT",
    0x00008000: "Global-pointer data",
    0x00020000: "Purgeable or 16-bit memory",
    0x00040000: "Locked memory",
    0x00080000: "Preloaded memory",
    0x01000000: "Extended relocations",
    0x02000000: "Discardable",
    0x04000000: "Not cached",
    0x08000000: "Not paged",
    0x10000000: "Shared",
    0x20000000: "Executable",
    0x40000000: "Readable",
    0x80000000: "Writable",
}

SECTION_ALIGNMENT_MASK = 0x00F00000
SECTION_ALIGNMENTS: Mapping[int, str] = {
    0x00100000: "1-byte alignment",
    0x00200000: "2-byte alignment",
    0x00300000: "4-byte alignment",
    0x00400000: "8-byte alignment",
    0x00500000: "16-byte alignment",
    0x00600000: "32-byte alignment",
    0x00700000: "64-byte alignment",
    0x00800000: "128-byte alignment",
    0x00900000: "256-byte alignment",
    0x00A00000: "512-byte alignment",
    0x00B00000: "1024-byte alignment",
    0x00C00000: "2048-byte alignment",
    0x00D00000: "4096-byte alignment",
    0x00E00000: "8192-byte alignment",
}


def machine_name(machine: int) -> str:
    """Return a lossless display name for a COFF machine identifier."""

    return MACHINE_TYPES.get(machine, f"Unknown (0x{machine:04X})")


def subsystem_name(subsystem: int) -> str:
    """Return a lossless display name for a Windows subsystem value."""

    return SUBSYSTEM_TYPES.get(subsystem, f"Unknown (0x{subsystem:04X})")


def flag_names(value: int, flags: Mapping[int, str]) -> tuple[str, ...]:
    """Return descriptions for all independent flags set in *value*."""

    return tuple(
        description
        for flag, description in flags.items()
        if value & flag == flag
    )


def section_characteristic_names(value: int) -> tuple[str, ...]:
    """Decode independent section flags and its exclusive alignment field."""

    names = list(flag_names(value, SECTION_CHARACTERISTICS))
    alignment = value & SECTION_ALIGNMENT_MASK
    if alignment in SECTION_ALIGNMENTS:
        names.append(SECTION_ALIGNMENTS[alignment])
    return tuple(names)
