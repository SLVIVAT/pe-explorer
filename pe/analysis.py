"""Deterministic, explained security analysis for parsed PE images.

The checks in this module deliberately consume the parser's typed models.  It
does not re-parse PE structures and it does not make claims about malware; the
result is a compact review of hardening flags and common static packing or
section-layout indicators.
"""

from __future__ import annotations

from collections.abc import Sequence
import math
from typing import Literal

from pe.constants import machine_name
from pe.models import (
    AnalysisFinding,
    COFFHeader,
    ExportDirectory,
    ImportDescriptor,
    OptionalHeader,
    ResourceNode,
    SectionHeader,
    SecurityAnalysis,
)


_IMAGE_FILE_DLL = 0x2000
_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
_IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
_IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_WRITE = 0x80000000

_CERTIFICATE_DIRECTORY_INDEX = 4
_MIN_WIN_CERTIFICATE_SIZE = 8
_HIGH_ENTROPY_THRESHOLD = 7.2
_MIN_ENTROPY_SAMPLE_SIZE = 256

# Exact names and fragments used by established executable packers and
# protectors.  Names are compared case-insensitively.
_PACKER_SECTION_NAMES = frozenset(
    {
        "!epack",
        ".adata",
        ".aspack",
        ".boom",
        ".ccg",
        ".charmve",
        ".mpress",
        ".packed",
        ".pack",
        ".petite",
        ".themida",
        ".upx0",
        ".upx1",
        ".upx2",
        ".vmp0",
        ".vmp1",
        ".vmp2",
        "bitarts",
        "kkrunchy",
        "nsp0",
        "nsp1",
        "nsp2",
        "pec1",
        "pec2",
        "upx0",
        "upx1",
        "upx2",
        "wwpack32",
        "y0da",
    }
)
_PACKER_NAME_FRAGMENTS = (
    "aspack",
    "mpress",
    "packed",
    "petite",
    "themida",
    "upx",
    "vmp",
)


class PEAnalyzer:
    """Analyze one already-parsed PE image and explain every conclusion.

    The score is intentionally deterministic and bounded to 0..100.  It is a
    triage aid, not a malware verdict: missing mitigations and signatures are
    weak signals, while writable/executable sections and packing indicators
    receive more weight.
    """

    def __init__(
        self,
        data: bytes,
        coff_header: COFFHeader,
        optional_header: OptionalHeader,
        sections: Sequence[SectionHeader],
        imports: Sequence[ImportDescriptor],
        exports: ExportDirectory | None,
        resources: ResourceNode | None,
    ) -> None:
        self._data = data
        self._coff_header = coff_header
        self._optional_header = optional_header
        self._sections = tuple(sections)
        self._imports = tuple(imports)
        self._exports = exports
        self._resources = resources

    def analyze(self) -> SecurityAnalysis:
        """Return explained findings and a reproducible aggregate risk level."""

        findings: list[AnalysisFinding] = []
        contributions: list[tuple[int, str]] = []

        findings.extend(self._identity_findings())

        aslr_enabled = bool(
            self._optional_header.dll_characteristics
            & _IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        )
        findings.append(
            self._mitigation_finding(
                key="aslr",
                label="ASLR",
                enabled=aslr_enabled,
                flag=_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
                enabled_explanation=(
                    "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040) is set, "
                    "so the loader may relocate the image for address-space "
                    "layout randomization."
                ),
                disabled_explanation=(
                    "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040) is not "
                    "set, so the image does not advertise ASLR support."
                ),
            )
        )
        if not aslr_enabled:
            contributions.append((8, "ASLR is not enabled"))

        dep_enabled = bool(
            self._optional_header.dll_characteristics
            & _IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        )
        findings.append(
            self._mitigation_finding(
                key="dep",
                label="DEP / NX",
                enabled=dep_enabled,
                flag=_IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
                enabled_explanation=(
                    "IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x0100) is set, so "
                    "the image opts in to Data Execution Prevention."
                ),
                disabled_explanation=(
                    "IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x0100) is not set, "
                    "so the image does not advertise DEP compatibility."
                ),
            )
        )
        if not dep_enabled:
            contributions.append((12, "DEP compatibility is not enabled"))

        cfg_enabled = bool(
            self._optional_header.dll_characteristics
            & _IMAGE_DLLCHARACTERISTICS_GUARD_CF
        )
        findings.append(
            self._mitigation_finding(
                key="cfg",
                label="Control Flow Guard",
                enabled=cfg_enabled,
                flag=_IMAGE_DLLCHARACTERISTICS_GUARD_CF,
                enabled_explanation=(
                    "IMAGE_DLLCHARACTERISTICS_GUARD_CF (0x4000) is set, so "
                    "the image advertises Control Flow Guard instrumentation."
                ),
                disabled_explanation=(
                    "IMAGE_DLLCHARACTERISTICS_GUARD_CF (0x4000) is not set. "
                    "CFG may be unavailable for older toolchains, so this is "
                    "treated as a weak signal."
                ),
            )
        )
        if not cfg_enabled:
            contributions.append((3, "CFG is not advertised"))

        signature_present, signature_explanation = self._signature_status()
        findings.append(
            AnalysisFinding(
                key="digital_signature",
                label="Digital Signature",
                value="Present" if signature_present else "Missing",
                severity="good" if signature_present else "warning",
                explanation=signature_explanation,
            )
        )
        if not signature_present:
            contributions.append((2, "no valid certificate-table range was found"))

        import_count = sum(
            len(descriptor.functions) for descriptor in self._imports
        )
        export_count = (
            sum(function.rva != 0 for function in self._exports.functions)
            if self._exports is not None
            else 0
        )
        findings.extend(
            (
                AnalysisFinding(
                    key="section_count",
                    label="Sections",
                    value=str(len(self._sections)),
                    severity="info",
                    explanation=(
                        f"The parsed section table contains "
                        f"{len(self._sections)} section header(s)."
                    ),
                ),
                AnalysisFinding(
                    key="import_count",
                    label="Imported Functions",
                    value=str(import_count),
                    severity="info",
                    explanation=(
                        f"{import_count} imported function(s) were resolved "
                        f"across {len(self._imports)} DLL descriptor(s)."
                    ),
                ),
                AnalysisFinding(
                    key="export_count",
                    label="Exported Functions",
                    value=str(export_count),
                    severity="info",
                    explanation=(
                        f"The export address table contains {export_count} "
                        "active (nonzero-RVA) exported function(s)."
                    ),
                ),
                AnalysisFinding(
                    key="resources",
                    label="Resources",
                    value="Present" if self._resources is not None else "Absent",
                    severity="info",
                    explanation=(
                        "A parsed resource-directory root is present."
                        if self._resources is not None
                        else "No parsed resource-directory root is present in "
                        "the image."
                    ),
                ),
            )
        )

        suspicious_names = self._suspicious_section_names()
        findings.append(
            AnalysisFinding(
                key="suspicious_section_names",
                label="Suspicious Section Names",
                value=(", ".join(suspicious_names) if suspicious_names else "None"),
                severity="warning" if suspicious_names else "good",
                explanation=(
                    "The following names match known packer/protector naming "
                    f"patterns: {', '.join(suspicious_names)}."
                    if suspicious_names
                    else "No section name matches the analyzer's known "
                    "packer/protector naming patterns."
                ),
            )
        )
        if suspicious_names:
            contributions.append((15, "suspicious section names were found"))

        writable_executable = tuple(
            self._display_section_name(section)
            for section in self._sections
            if self._is_writable_executable(section)
        )
        findings.append(
            AnalysisFinding(
                key="writable_executable_sections",
                label="Writable + Executable Sections",
                value=(
                    ", ".join(writable_executable)
                    if writable_executable
                    else "None"
                ),
                severity="danger" if writable_executable else "good",
                explanation=(
                    "These sections set both IMAGE_SCN_MEM_WRITE (0x80000000) "
                    "and IMAGE_SCN_MEM_EXECUTE (0x20000000), allowing mutable "
                    f"executable memory: {', '.join(writable_executable)}."
                    if writable_executable
                    else "No parsed section sets both the writable and "
                    "executable memory flags."
                ),
            )
        )
        if writable_executable:
            contributions.append((30, "writable and executable sections exist"))

        packing_signals = self._packing_signals(suspicious_names)
        findings.append(
            AnalysisFinding(
                key="packed_heuristics",
                label="Packed Executable Heuristics",
                value="Indicators detected" if packing_signals else "Not detected",
                severity="danger" if packing_signals else "good",
                explanation=(
                    "Static packing indicators were found: "
                    + "; ".join(packing_signals)
                    + ". These are heuristics and do not prove maliciousness."
                    if packing_signals
                    else "No known packer-style name, high-entropy raw section "
                    "(at least 7.2 bits/byte over at least 256 bytes), or "
                    "executable zero-raw-data section was found."
                ),
            )
        )
        if packing_signals:
            contributions.append((25, "packing heuristics were triggered"))

        score = min(100, sum(points for points, _ in contributions))
        risk: Literal["Low", "Medium", "High"]
        risk_severity: Literal["good", "warning", "danger"]
        if score >= 50:
            risk = "High"
            risk_severity = "danger"
        elif score >= 20:
            risk = "Medium"
            risk_severity = "warning"
        else:
            risk = "Low"
            risk_severity = "good"

        contribution_text = (
            "; ".join(
                f"+{points} {reason}" for points, reason in contributions
            )
            if contributions
            else "no score-raising conditions were found"
        )
        findings.append(
            AnalysisFinding(
                key="overall_risk",
                label="Overall Risk",
                value=f"{risk} ({score}/100)",
                severity=risk_severity,
                explanation=(
                    f"The deterministic score is {score}/100: "
                    f"{contribution_text}. Scores below 20 are Low, 20-49 "
                    "are Medium, and 50 or above are High. This static score "
                    "is a triage aid, not a malware verdict."
                ),
            )
        )

        return SecurityAnalysis(
            overall_risk=risk,
            risk_score=score,
            findings=tuple(findings),
        )

    def _identity_findings(self) -> tuple[AnalysisFinding, ...]:
        architecture = machine_name(self._coff_header.machine)
        image_type = (
            "DLL"
            if self._coff_header.characteristics & _IMAGE_FILE_DLL
            else "EXE"
        )
        return (
            AnalysisFinding(
                key="architecture",
                label="Architecture",
                value=architecture,
                severity="info",
                explanation=(
                    f"COFF Machine is 0x{self._coff_header.machine:04X}, "
                    f"which maps to {architecture}."
                ),
            ),
            AnalysisFinding(
                key="pe_format",
                label="PE Format",
                value=self._optional_header.format,
                severity="info",
                explanation=(
                    f"Optional-header Magic is "
                    f"0x{self._optional_header.magic:04X}, identifying "
                    f"{self._optional_header.format}."
                ),
            ),
            AnalysisFinding(
                key="image_type",
                label="Image Type",
                value=image_type,
                severity="info",
                explanation=(
                    "COFF IMAGE_FILE_DLL (0x2000) is set."
                    if image_type == "DLL"
                    else "COFF IMAGE_FILE_DLL (0x2000) is not set, so the "
                    "image is classified as an executable rather than a DLL."
                ),
            ),
        )

    @staticmethod
    def _mitigation_finding(
        *,
        key: str,
        label: str,
        enabled: bool,
        flag: int,
        enabled_explanation: str,
        disabled_explanation: str,
    ) -> AnalysisFinding:
        # ``flag`` documents the exact tested bit at each call site and keeps
        # accidental zero-valued checks from silently producing a conclusion.
        if flag == 0:
            raise ValueError("A mitigation flag must be nonzero.")
        return AnalysisFinding(
            key=key,
            label=label,
            value="Enabled" if enabled else "Not enabled",
            severity="good" if enabled else "warning",
            explanation=(
                enabled_explanation if enabled else disabled_explanation
            ),
        )

    def _signature_status(self) -> tuple[bool, str]:
        directories = self._optional_header.data_directories
        if len(directories) <= _CERTIFICATE_DIRECTORY_INDEX:
            return (
                False,
                "The optional header has no Certificate Table entry at data "
                "directory index 4.",
            )

        directory = directories[_CERTIFICATE_DIRECTORY_INDEX]
        file_offset = directory.virtual_address
        size = directory.size
        if file_offset == 0 or size == 0:
            return (
                False,
                "Certificate Table directory index 4 has a zero file offset "
                "or size, so no embedded signature is present.",
            )
        if size < _MIN_WIN_CERTIFICATE_SIZE:
            return (
                False,
                f"Certificate Table directory index 4 declares only {size} "
                "byte(s), smaller than an 8-byte WIN_CERTIFICATE header.",
            )
        if file_offset > len(self._data) or size > len(self._data) - file_offset:
            return (
                False,
                "Certificate Table directory index 4 points outside the file "
                f"(offset 0x{file_offset:X}, size 0x{size:X}, file size "
                f"0x{len(self._data):X}).",
            )

        return (
            True,
            "Certificate Table directory index 4 names a complete in-file "
            f"range at file offset 0x{file_offset:X} with size 0x{size:X}. "
            "This establishes signature presence only; cryptographic trust "
            "and certificate validity were not verified.",
        )

    def _suspicious_section_names(self) -> tuple[str, ...]:
        suspicious: list[str] = []
        for section in self._sections:
            normalized = section.name.strip().lower()
            is_packer_name = normalized in _PACKER_SECTION_NAMES or any(
                fragment in normalized for fragment in _PACKER_NAME_FRAGMENTS
            )
            is_malformed_name = not normalized or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in normalized
            )
            if is_packer_name or is_malformed_name:
                suspicious.append(self._display_section_name(section))
        return tuple(suspicious)

    def _packing_signals(
        self,
        suspicious_names: Sequence[str],
    ) -> tuple[str, ...]:
        signals: list[str] = []
        if suspicious_names:
            signals.append(
                "packer/protector-style section name(s) "
                + ", ".join(suspicious_names)
            )

        for section in self._sections:
            entropy = self._section_entropy(section)
            if entropy is not None and entropy >= _HIGH_ENTROPY_THRESHOLD:
                signals.append(
                    f"{self._display_section_name(section)} entropy is "
                    f"{entropy:.2f} bits/byte"
                )

            if (
                section.virtual_size > 0
                and section.size_of_raw_data == 0
                and section.characteristics & _IMAGE_SCN_MEM_EXECUTE
            ):
                signals.append(
                    f"{self._display_section_name(section)} is executable with "
                    "nonzero virtual size but no raw file data"
                )

        return tuple(signals)

    def _section_entropy(self, section: SectionHeader) -> float | None:
        start = section.pointer_to_raw_data
        size = section.size_of_raw_data
        if (
            size < _MIN_ENTROPY_SAMPLE_SIZE
            or start < 0
            or start >= len(self._data)
        ):
            return None

        end = min(len(self._data), start + size)
        sample = self._data[start:end]
        if len(sample) < _MIN_ENTROPY_SAMPLE_SIZE:
            return None

        frequencies = [0] * 256
        for byte in sample:
            frequencies[byte] += 1

        sample_size = len(sample)
        entropy = 0.0
        for count in frequencies:
            if count:
                probability = count / sample_size
                entropy -= probability * math.log2(probability)
        return entropy

    @staticmethod
    def _is_writable_executable(section: SectionHeader) -> bool:
        required = _IMAGE_SCN_MEM_WRITE | _IMAGE_SCN_MEM_EXECUTE
        return section.characteristics & required == required

    @staticmethod
    def _display_section_name(section: SectionHeader) -> str:
        return section.name if section.name else f"<unnamed #{section.index}>"
