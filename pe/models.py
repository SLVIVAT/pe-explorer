"""Typed data models for parsed Portable Executable images."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, TypedDict

from pe.constants import machine_name


class COFFHeaderInfo(TypedDict):
    machine: int
    machine_name: str
    number_of_sections: int
    timestamp: int
    pointer_to_symbol_table: int
    number_of_symbols: int
    optional_header_size: int
    characteristics: int


class DataDirectoryInfo(TypedDict):
    index: int
    name: str
    virtual_address: int
    size: int
    status: str


class OptionalHeaderInfo(TypedDict):
    magic: int
    format: str
    major_linker_version: int
    minor_linker_version: int
    size_of_code: int
    size_of_initialized_data: int
    size_of_uninitialized_data: int
    address_of_entry_point: int
    base_of_code: int
    base_of_data: int | None
    image_base: int
    section_alignment: int
    file_alignment: int
    major_operating_system_version: int
    minor_operating_system_version: int
    major_image_version: int
    minor_image_version: int
    major_subsystem_version: int
    minor_subsystem_version: int
    win32_version_value: int
    size_of_image: int
    size_of_headers: int
    checksum: int
    subsystem: int
    dll_characteristics: int
    size_of_stack_reserve: int
    size_of_stack_commit: int
    size_of_heap_reserve: int
    size_of_heap_commit: int
    loader_flags: int
    number_of_rva_and_sizes: int
    data_directories: list[DataDirectoryInfo]


class SectionHeaderInfo(TypedDict):
    index: int
    name: str
    raw_name: bytes
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    pointer_to_relocations: int
    pointer_to_linenumbers: int
    number_of_relocations: int
    number_of_linenumbers: int
    characteristics: int


class ImportedFunctionInfo(TypedDict):
    index: int
    kind: Literal["name", "ordinal", "bound_address"]
    name: str | None
    ordinal: int | None
    hint: int | None
    is_ordinal: bool
    lookup_table_rva: int
    import_address_table_rva: int
    name_rva: int | None
    raw_value: int


class ImportDescriptorInfo(TypedDict):
    index: int
    dll_name: str
    original_first_thunk: int
    timestamp: int
    forwarder_chain: int
    name_rva: int
    first_thunk: int
    functions: list[ImportedFunctionInfo]


class ExportedFunctionInfo(TypedDict):
    index: int
    ordinal: int
    ordinal_index: int
    name: str | None
    names: list[str]
    rva: int
    is_forwarder: bool
    forwarder: str | None


class ExportDirectoryInfo(TypedDict):
    characteristics: int
    timestamp: int
    major_version: int
    minor_version: int
    name_rva: int
    dll_name: str
    ordinal_base: int
    address_table_entries: int
    number_of_name_pointers: int
    export_address_table_rva: int
    name_pointer_rva: int
    ordinal_table_rva: int
    functions: list[ExportedFunctionInfo]


class ResourceDataInfo(TypedDict):
    rva: int
    size: int
    code_page: int
    reserved: int
    file_offset: int | None
    resource_type: str
    summary: str
    content: str | None


class ResourceNodeInfo(TypedDict):
    name: str
    identifier: int | None
    level: int
    is_directory: bool
    characteristics: int | None
    timestamp: int | None
    major_version: int | None
    minor_version: int | None
    number_of_named_entries: int
    number_of_id_entries: int
    data: ResourceDataInfo | None
    children: list[ResourceNodeInfo]


class AnalysisFindingInfo(TypedDict):
    key: str
    label: str
    value: str
    severity: Literal["good", "info", "warning", "danger"]
    explanation: str


class SecurityAnalysisInfo(TypedDict):
    overall_risk: Literal["Low", "Medium", "High"]
    risk_score: int
    findings: list[AnalysisFindingInfo]


class _RequiredPEInfo(TypedDict):
    file_name: str
    file_path: str
    file_size: int
    mz_signature: str
    pe_offset: int
    pe_signature: str
    machine: str
    number_of_sections: int
    timestamp: int
    pointer_to_symbol_table: int
    number_of_symbols: int
    optional_header_size: int
    characteristics: int
    coff_header: COFFHeaderInfo
    optional_header: OptionalHeaderInfo
    sections: list[SectionHeaderInfo]


class PEInfo(_RequiredPEInfo, total=False):
    """Public parse result with optional milestone fields for compatibility."""

    imports: list[ImportDescriptorInfo]
    exports: ExportDirectoryInfo | None
    resources: ResourceNodeInfo | None
    data_directories: list[DataDirectoryInfo]
    analysis: SecurityAnalysisInfo | None


@dataclass(frozen=True, slots=True)
class COFFHeader:
    """The complete 20-byte COFF file header."""

    machine: int
    number_of_sections: int
    timestamp: int
    pointer_to_symbol_table: int
    number_of_symbols: int
    optional_header_size: int
    characteristics: int

    def to_dict(self) -> COFFHeaderInfo:
        return {
            "machine": self.machine,
            "machine_name": machine_name(self.machine),
            "number_of_sections": self.number_of_sections,
            "timestamp": self.timestamp,
            "pointer_to_symbol_table": self.pointer_to_symbol_table,
            "number_of_symbols": self.number_of_symbols,
            "optional_header_size": self.optional_header_size,
            "characteristics": self.characteristics,
        }


@dataclass(frozen=True, slots=True)
class DataDirectory:
    """One IMAGE_DATA_DIRECTORY entry from the optional header."""

    index: int
    name: str
    virtual_address: int
    size: int
    status: str = "Unresolved"

    def to_dict(self) -> DataDirectoryInfo:
        return {
            "index": self.index,
            "name": self.name,
            "virtual_address": self.virtual_address,
            "size": self.size,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class OptionalHeader:
    """All standard and Windows-specific PE32/PE32+ optional-header fields."""

    magic: int
    format: str
    major_linker_version: int
    minor_linker_version: int
    size_of_code: int
    size_of_initialized_data: int
    size_of_uninitialized_data: int
    address_of_entry_point: int
    base_of_code: int
    base_of_data: int | None
    image_base: int
    section_alignment: int
    file_alignment: int
    major_operating_system_version: int
    minor_operating_system_version: int
    major_image_version: int
    minor_image_version: int
    major_subsystem_version: int
    minor_subsystem_version: int
    win32_version_value: int
    size_of_image: int
    size_of_headers: int
    checksum: int
    subsystem: int
    dll_characteristics: int
    size_of_stack_reserve: int
    size_of_stack_commit: int
    size_of_heap_reserve: int
    size_of_heap_commit: int
    loader_flags: int
    number_of_rva_and_sizes: int
    data_directories: tuple[DataDirectory, ...]

    def to_dict(self) -> OptionalHeaderInfo:
        return {
            "magic": self.magic,
            "format": self.format,
            "major_linker_version": self.major_linker_version,
            "minor_linker_version": self.minor_linker_version,
            "size_of_code": self.size_of_code,
            "size_of_initialized_data": self.size_of_initialized_data,
            "size_of_uninitialized_data": self.size_of_uninitialized_data,
            "address_of_entry_point": self.address_of_entry_point,
            "base_of_code": self.base_of_code,
            "base_of_data": self.base_of_data,
            "image_base": self.image_base,
            "section_alignment": self.section_alignment,
            "file_alignment": self.file_alignment,
            "major_operating_system_version": self.major_operating_system_version,
            "minor_operating_system_version": self.minor_operating_system_version,
            "major_image_version": self.major_image_version,
            "minor_image_version": self.minor_image_version,
            "major_subsystem_version": self.major_subsystem_version,
            "minor_subsystem_version": self.minor_subsystem_version,
            "win32_version_value": self.win32_version_value,
            "size_of_image": self.size_of_image,
            "size_of_headers": self.size_of_headers,
            "checksum": self.checksum,
            "subsystem": self.subsystem,
            "dll_characteristics": self.dll_characteristics,
            "size_of_stack_reserve": self.size_of_stack_reserve,
            "size_of_stack_commit": self.size_of_stack_commit,
            "size_of_heap_reserve": self.size_of_heap_reserve,
            "size_of_heap_commit": self.size_of_heap_commit,
            "loader_flags": self.loader_flags,
            "number_of_rva_and_sizes": self.number_of_rva_and_sizes,
            "data_directories": [
                directory.to_dict() for directory in self.data_directories
            ],
        }


@dataclass(frozen=True, slots=True)
class SectionHeader:
    """One complete 40-byte section-table entry."""

    # PE section numbers are one-based.
    index: int
    name: str
    raw_name: bytes
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    pointer_to_relocations: int
    pointer_to_linenumbers: int
    number_of_relocations: int
    number_of_linenumbers: int
    characteristics: int

    def to_dict(self) -> SectionHeaderInfo:
        return {
            "index": self.index,
            "name": self.name,
            "raw_name": self.raw_name,
            "virtual_size": self.virtual_size,
            "virtual_address": self.virtual_address,
            "size_of_raw_data": self.size_of_raw_data,
            "pointer_to_raw_data": self.pointer_to_raw_data,
            "pointer_to_relocations": self.pointer_to_relocations,
            "pointer_to_linenumbers": self.pointer_to_linenumbers,
            "number_of_relocations": self.number_of_relocations,
            "number_of_linenumbers": self.number_of_linenumbers,
            "characteristics": self.characteristics,
        }


@dataclass(frozen=True, slots=True)
class ImportedFunction:
    """One IMAGE_THUNK_DATA import resolved by name, ordinal, or binding.

    ``lookup_table_rva`` and ``import_address_table_rva`` identify this
    function's individual table entries rather than the table base addresses.
    """

    index: int
    kind: Literal["name", "ordinal", "bound_address"]
    name: str | None
    ordinal: int | None
    hint: int | None
    is_ordinal: bool
    lookup_table_rva: int
    import_address_table_rva: int
    name_rva: int | None
    raw_value: int

    def to_dict(self) -> ImportedFunctionInfo:
        return {
            "index": self.index,
            "kind": self.kind,
            "name": self.name,
            "ordinal": self.ordinal,
            "hint": self.hint,
            "is_ordinal": self.is_ordinal,
            "lookup_table_rva": self.lookup_table_rva,
            "import_address_table_rva": self.import_address_table_rva,
            "name_rva": self.name_rva,
            "raw_value": self.raw_value,
        }


@dataclass(frozen=True, slots=True)
class ImportDescriptor:
    """One complete IMAGE_IMPORT_DESCRIPTOR and its imported functions."""

    index: int
    dll_name: str
    original_first_thunk: int
    timestamp: int
    forwarder_chain: int
    name_rva: int
    first_thunk: int
    functions: tuple[ImportedFunction, ...]

    def to_dict(self) -> ImportDescriptorInfo:
        return {
            "index": self.index,
            "dll_name": self.dll_name,
            "original_first_thunk": self.original_first_thunk,
            "timestamp": self.timestamp,
            "forwarder_chain": self.forwarder_chain,
            "name_rva": self.name_rva,
            "first_thunk": self.first_thunk,
            "functions": [function.to_dict() for function in self.functions],
        }


@dataclass(frozen=True, slots=True)
class ExportedFunction:
    """One entry from the Export Address Table, including zero-RVA gaps."""

    index: int
    ordinal: int
    ordinal_index: int
    name: str | None
    names: tuple[str, ...]
    rva: int
    is_forwarder: bool
    forwarder: str | None

    def to_dict(self) -> ExportedFunctionInfo:
        return {
            "index": self.index,
            "ordinal": self.ordinal,
            "ordinal_index": self.ordinal_index,
            "name": self.name,
            "names": list(self.names),
            "rva": self.rva,
            "is_forwarder": self.is_forwarder,
            "forwarder": self.forwarder,
        }


@dataclass(frozen=True, slots=True)
class ExportDirectory:
    """The IMAGE_EXPORT_DIRECTORY and all resolved exports."""

    characteristics: int
    timestamp: int
    major_version: int
    minor_version: int
    name_rva: int
    dll_name: str
    ordinal_base: int
    address_table_entries: int
    number_of_name_pointers: int
    export_address_table_rva: int
    name_pointer_rva: int
    ordinal_table_rva: int
    functions: tuple[ExportedFunction, ...]

    def to_dict(self) -> ExportDirectoryInfo:
        return {
            "characteristics": self.characteristics,
            "timestamp": self.timestamp,
            "major_version": self.major_version,
            "minor_version": self.minor_version,
            "name_rva": self.name_rva,
            "dll_name": self.dll_name,
            "ordinal_base": self.ordinal_base,
            "address_table_entries": self.address_table_entries,
            "number_of_name_pointers": self.number_of_name_pointers,
            "export_address_table_rva": self.export_address_table_rva,
            "name_pointer_rva": self.name_pointer_rva,
            "ordinal_table_rva": self.ordinal_table_rva,
            "functions": [function.to_dict() for function in self.functions],
        }


@dataclass(frozen=True, slots=True)
class ResourceData:
    """One IMAGE_RESOURCE_DATA_ENTRY and its decoded presentation."""

    rva: int
    size: int
    code_page: int
    reserved: int
    file_offset: int | None
    resource_type: str
    summary: str
    content: str | None

    def to_dict(self) -> ResourceDataInfo:
        return {
            "rva": self.rva,
            "size": self.size,
            "code_page": self.code_page,
            "reserved": self.reserved,
            "file_offset": self.file_offset,
            "resource_type": self.resource_type,
            "summary": self.summary,
            "content": self.content,
        }


@dataclass(frozen=True, slots=True)
class ResourceNode:
    """A directory or leaf in the complete PE resource tree."""

    name: str
    identifier: int | None
    level: int
    is_directory: bool
    characteristics: int | None
    timestamp: int | None
    major_version: int | None
    minor_version: int | None
    number_of_named_entries: int
    number_of_id_entries: int
    data: ResourceData | None
    children: tuple[ResourceNode, ...]

    def to_dict(self) -> ResourceNodeInfo:
        return {
            "name": self.name,
            "identifier": self.identifier,
            "level": self.level,
            "is_directory": self.is_directory,
            "characteristics": self.characteristics,
            "timestamp": self.timestamp,
            "major_version": self.major_version,
            "minor_version": self.minor_version,
            "number_of_named_entries": self.number_of_named_entries,
            "number_of_id_entries": self.number_of_id_entries,
            "data": self.data.to_dict() if self.data is not None else None,
            "children": [child.to_dict() for child in self.children],
        }


@dataclass(frozen=True, slots=True)
class AnalysisFinding:
    """One explained conclusion in the automatic PE analysis."""

    key: str
    label: str
    value: str
    severity: Literal["good", "info", "warning", "danger"]
    explanation: str

    def to_dict(self) -> AnalysisFindingInfo:
        return {
            "key": self.key,
            "label": self.label,
            "value": self.value,
            "severity": self.severity,
            "explanation": self.explanation,
        }


@dataclass(frozen=True, slots=True)
class SecurityAnalysis:
    """Deterministic explained security and packing assessment."""

    overall_risk: Literal["Low", "Medium", "High"]
    risk_score: int
    findings: tuple[AnalysisFinding, ...]

    def to_dict(self) -> SecurityAnalysisInfo:
        return {
            "overall_risk": self.overall_risk,
            "risk_score": self.risk_score,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True, slots=True)
class PEImage:
    """A fully parsed Portable Executable image."""

    file_path: Path
    file_size: int
    mz_signature: str
    pe_offset: int
    pe_signature: str
    coff_header: COFFHeader
    optional_header: OptionalHeader
    sections: tuple[SectionHeader, ...]
    imports: tuple[ImportDescriptor, ...] = ()
    exports: ExportDirectory | None = None
    resources: ResourceNode | None = None
    analysis: SecurityAnalysis | None = None

    def to_dict(self) -> PEInfo:
        """Return the public dictionary representation.

        The original flat keys remain available for compatibility, while the
        complete typed structures are exposed under nested keys.
        """

        coff = self.coff_header.to_dict()
        return {
            "file_name": self.file_path.name,
            "file_path": str(self.file_path),
            "file_size": self.file_size,
            "mz_signature": self.mz_signature,
            "pe_offset": self.pe_offset,
            "pe_signature": self.pe_signature,
            "machine": coff["machine_name"],
            "number_of_sections": self.coff_header.number_of_sections,
            "timestamp": self.coff_header.timestamp,
            "pointer_to_symbol_table": self.coff_header.pointer_to_symbol_table,
            "number_of_symbols": self.coff_header.number_of_symbols,
            "optional_header_size": self.coff_header.optional_header_size,
            "characteristics": self.coff_header.characteristics,
            "coff_header": coff,
            "optional_header": self.optional_header.to_dict(),
            "sections": [section.to_dict() for section in self.sections],
            "imports": [descriptor.to_dict() for descriptor in self.imports],
            "exports": self.exports.to_dict() if self.exports is not None else None,
            "resources": (
                self.resources.to_dict() if self.resources is not None else None
            ),
            "data_directories": [
                directory.to_dict()
                for directory in self.optional_header.data_directories
            ],
            "analysis": (
                self.analysis.to_dict() if self.analysis is not None else None
            ),
        }
