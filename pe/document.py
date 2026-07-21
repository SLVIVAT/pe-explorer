"""Aggregate, immutable inspection document for parser, GUI, and reports."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pe.addressing import AddressingService
from pe.certificates import CertificateAnalysis, CertificateParser
from pe.file_analysis import FileAnalysis, FileAnalyzer
from pe.models import PEImage, PEInfo
from pe.parser import PEParser
from pe.reports import ReportGenerator
from pe.search import SearchService
from pe.strings import ExtractedString, StringExtractor
from pe.version_info import VersionInfoParser, VersionInformation


ProgressCallback = Callable[[str], None]


@dataclass(frozen=True, slots=True)
class PEInspectionDocument:
    """One fully inspected PE file with reusable derived services.

    Raw bytes are retained exactly once and are deliberately excluded from
    dictionary/report serialization. All heavyweight work happens in
    :meth:`load`, making the object safe to create in a GUI worker thread and
    cheap to hand to virtualized Qt models afterward.
    """

    path: Path
    data: bytes
    image: PEImage
    addressing: AddressingService
    strings: tuple[ExtractedString, ...]
    strings_truncated: bool
    string_limit: int | None
    search: SearchService
    file_analysis: FileAnalysis
    certificate: CertificateAnalysis
    version_information: VersionInformation

    @classmethod
    def load(
        cls,
        path: str | Path,
        *,
        minimum_string_length: int = 4,
        maximum_strings: int | None = 250_000,
        progress: ProgressCallback | None = None,
    ) -> PEInspectionDocument:
        """Parse and derive all professional inspection data once.

        String extraction is capped at 250,000 results by default so unusually
        large binaries cannot create millions of GUI rows. Pass
        ``maximum_strings=None`` to opt into the original unlimited behavior.
        """

        report = progress or (lambda message: None)
        file_path = Path(path)

        report("Parsing PE structures")
        parser = PEParser(file_path)
        image = parser.parse_image()
        data = parser.data

        report("Mapping file offsets, RVAs, and VAs")
        addressing = AddressingService.from_image(image)

        report("Extracting ASCII and UTF-16 strings")
        string_extraction = StringExtractor(
            data,
            minimum_string_length,
            addressing,
        ).extract_result(maximum_strings=maximum_strings)

        report("Calculating hashes, entropy, and overlay data")
        file_analysis = FileAnalyzer(
            data,
            image.optional_header,
            image.sections,
        ).analyze()

        report("Inspecting the embedded digital signature")
        certificate = CertificateParser(
            data,
            image.optional_header,
        ).parse()

        report("Parsing version information")
        version_information = VersionInfoParser(
            data,
            image.resources,
        ).parse()

        report("Preparing global search")
        search = SearchService(data, addressing)
        report("Ready")
        return cls(
            path=file_path,
            data=data,
            image=image,
            addressing=addressing,
            strings=string_extraction.strings,
            strings_truncated=string_extraction.truncated,
            string_limit=string_extraction.limit,
            search=search,
            file_analysis=file_analysis,
            certificate=certificate,
            version_information=version_information,
        )

    @property
    def structural_info(self) -> PEInfo:
        """Return the existing public parser dictionary unchanged."""

        return self.image.to_dict()

    @property
    def extension_mapping(self) -> Mapping[str, object]:
        """Return report-ready additions without large string collections."""

        return {
            "entropy": self.file_analysis.sections,
            "overlay": self.file_analysis.overlay,
            "hashes": self.file_analysis.hashes,
            "digital_signature": self.certificate,
            "version_information": self.version_information,
        }

    def to_dict(self) -> dict[str, Any]:
        """Return structural information plus derived presentation fields."""

        result: dict[str, Any] = dict(self.structural_info)
        result.update(
            {
                "strings": [item.to_dict() for item in self.strings],
                "strings_truncated": self.strings_truncated,
                "string_limit": self.string_limit,
                "file_analysis": self.file_analysis.to_dict(),
                "entropy": [
                    item.to_dict() for item in self.file_analysis.sections
                ],
                "overlay": self.file_analysis.overlay.to_dict(),
                "hashes": self.file_analysis.hashes.to_dict(),
                "certificate": self.certificate.to_dict(),
                "version_information": self.version_information.to_dict(),
            }
        )
        return result

    def report_generator(self) -> ReportGenerator:
        """Build a deterministic report generator for this document."""

        return ReportGenerator(
            self.structural_info,
            self.extension_mapping,
        )


__all__ = ["PEInspectionDocument", "ProgressCallback"]
