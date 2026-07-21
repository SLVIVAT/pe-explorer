"""Portable Executable parsing package."""

from pe.addressing import AddressMapping, AddressingService
from pe.analysis import PEAnalyzer
from pe.certificates import CertificateAnalysis, CertificateParser
from pe.exports import ExportTableParser
from pe.file_analysis import FileAnalysis, FileAnalyzer
from pe.imports import ImportTableParser
from pe.models import (
    AnalysisFinding,
    COFFHeader,
    DataDirectory,
    ExportDirectory,
    ExportedFunction,
    ImportDescriptor,
    ImportedFunction,
    OptionalHeader,
    PEImage,
    PEInfo,
    ResourceData,
    ResourceNode,
    SectionHeader,
    SecurityAnalysis,
)
from pe.resources import ResourceDirectoryParser
from pe.parser import PEFormatError, PEParser
from pe.document import PEInspectionDocument
from pe.reports import ReportGenerator
from pe.search import SearchResult, SearchService
from pe.strings import ExtractedString, StringExtractionResult, StringExtractor
from pe.version_info import VersionInfoParser, VersionInformation

__all__ = [
    "AddressMapping",
    "AddressingService",
    "AnalysisFinding",
    "CertificateAnalysis",
    "CertificateParser",
    "COFFHeader",
    "DataDirectory",
    "ExportDirectory",
    "ExportTableParser",
    "ExportedFunction",
    "ExtractedString",
    "FileAnalysis",
    "FileAnalyzer",
    "ImportDescriptor",
    "ImportTableParser",
    "ImportedFunction",
    "OptionalHeader",
    "PEAnalyzer",
    "PEFormatError",
    "PEImage",
    "PEInfo",
    "PEInspectionDocument",
    "PEParser",
    "ResourceData",
    "ResourceDirectoryParser",
    "ResourceNode",
    "ReportGenerator",
    "SearchResult",
    "SearchService",
    "SectionHeader",
    "SecurityAnalysis",
    "StringExtractionResult",
    "StringExtractor",
    "VersionInfoParser",
    "VersionInformation",
]
