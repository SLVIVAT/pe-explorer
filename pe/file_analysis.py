"""File-level hashes, section entropy, and PE overlay inspection."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import struct
from typing import Literal, TypedDict

from pe.models import OptionalHeader, SectionHeader


EntropyColor = Literal["gray", "green", "amber", "red"]
OverlaySuspicionLevel = Literal["None", "Review", "High"]
_CERTIFICATE_DIRECTORY_INDEX = 4
_MIN_CERTIFICATE_SIZE = 8
_WIN_CERTIFICATE_HEADER = struct.Struct("<IHH")
_VALID_CERTIFICATE_REVISIONS = frozenset((0x0100, 0x0200))
_VALID_CERTIFICATE_TYPES = frozenset((0x0001, 0x0002, 0x0003, 0x0004))
_MAX_CERTIFICATE_RECORDS = 4096
_HIGH_ENTROPY_THRESHOLD = 7.2
_ELEVATED_ENTROPY_THRESHOLD = 6.5
_LARGE_OVERLAY_THRESHOLD = 1024 * 1024


class FileHashesInfo(TypedDict):
    md5: str
    sha1: str
    sha256: str
    sha512: str


@dataclass(frozen=True, slots=True)
class FileHashes:
    """Common whole-file cryptographic and compatibility digests."""

    md5: str
    sha1: str
    sha256: str
    sha512: str

    def to_dict(self) -> FileHashesInfo:
        return {
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "sha512": self.sha512,
        }


class SectionEntropyInfo(TypedDict):
    section_index: int
    section_name: str
    file_offset: int
    declared_size: int
    analyzed_size: int
    entropy: float | None
    color: EntropyColor
    suspicious: bool
    explanation: str


@dataclass(frozen=True, slots=True)
class SectionEntropy:
    """Bounded Shannon-entropy assessment for one section's raw bytes."""

    section_index: int
    section_name: str
    file_offset: int
    declared_size: int
    analyzed_size: int
    entropy: float | None
    color: EntropyColor
    suspicious: bool
    explanation: str

    def to_dict(self) -> SectionEntropyInfo:
        return {
            "section_index": self.section_index,
            "section_name": self.section_name,
            "file_offset": self.file_offset,
            "declared_size": self.declared_size,
            "analyzed_size": self.analyzed_size,
            "entropy": self.entropy,
            "color": self.color,
            "suspicious": self.suspicious,
            "explanation": self.explanation,
        }


class OverlayRegionInfo(TypedDict):
    file_offset: int
    size: int
    end_offset: int


@dataclass(frozen=True, slots=True)
class OverlayRegion:
    """One contiguous non-certificate byte range after the PE image."""

    file_offset: int
    size: int

    @property
    def end_offset(self) -> int:
        return self.file_offset + self.size

    def to_dict(self) -> OverlayRegionInfo:
        return {
            "file_offset": self.file_offset,
            "size": self.size,
            "end_offset": self.end_offset,
        }


class OverlayInfoDict(TypedDict):
    present: bool
    image_end_offset: int
    start_offset: int | None
    total_size: int
    regions: list[OverlayRegionInfo]
    certificate_offset: int | None
    certificate_size: int
    certificate_valid: bool
    entropy: float | None
    suspicious: bool
    suspicion_level: OverlaySuspicionLevel
    explanation: str


@dataclass(frozen=True, slots=True)
class OverlayInfo:
    """Overlay ranges after the final section, excluding a valid certificate."""

    present: bool
    image_end_offset: int
    start_offset: int | None
    total_size: int
    regions: tuple[OverlayRegion, ...]
    certificate_offset: int | None
    certificate_size: int
    certificate_valid: bool
    entropy: float | None
    suspicious: bool
    suspicion_level: OverlaySuspicionLevel
    explanation: str

    def to_dict(self) -> OverlayInfoDict:
        return {
            "present": self.present,
            "image_end_offset": self.image_end_offset,
            "start_offset": self.start_offset,
            "total_size": self.total_size,
            "regions": [region.to_dict() for region in self.regions],
            "certificate_offset": self.certificate_offset,
            "certificate_size": self.certificate_size,
            "certificate_valid": self.certificate_valid,
            "entropy": self.entropy,
            "suspicious": self.suspicious,
            "suspicion_level": self.suspicion_level,
            "explanation": self.explanation,
        }


class FileAnalysisInfo(TypedDict):
    hashes: FileHashesInfo
    sections: list[SectionEntropyInfo]
    overlay: OverlayInfoDict


@dataclass(frozen=True, slots=True)
class FileAnalysis:
    """Complete file-level analysis suitable for a GUI details panel."""

    hashes: FileHashes
    sections: tuple[SectionEntropy, ...]
    overlay: OverlayInfo

    def to_dict(self) -> FileAnalysisInfo:
        return {
            "hashes": self.hashes.to_dict(),
            "sections": [section.to_dict() for section in self.sections],
            "overlay": self.overlay.to_dict(),
        }


class FileAnalyzer:
    """Analyze immutable PE bytes without reparsing PE structures."""

    def __init__(
        self,
        data: bytes,
        optional_header: OptionalHeader,
        sections: tuple[SectionHeader, ...],
    ) -> None:
        self._data = data
        self._optional_header = optional_header
        self._sections = sections

    def analyze(self) -> FileAnalysis:
        return FileAnalysis(
            hashes=self.calculate_hashes(),
            sections=self.analyze_section_entropy(),
            overlay=self.detect_overlay(),
        )

    def calculate_hashes(self) -> FileHashes:
        """Calculate MD5, SHA-1, SHA-256, and SHA-512 over the whole file."""

        return FileHashes(
            md5=hashlib.md5(  # noqa: S324 - file identity, not security
                self._data,
                usedforsecurity=False,
            ).hexdigest(),
            sha1=hashlib.sha1(  # noqa: S324 - file identity, not security
                self._data,
                usedforsecurity=False,
            ).hexdigest(),
            sha256=hashlib.sha256(self._data).hexdigest(),
            sha512=hashlib.sha512(self._data).hexdigest(),
        )

    def analyze_section_entropy(self) -> tuple[SectionEntropy, ...]:
        """Calculate entropy with deterministic file-size aggregate work.

        A valid PE's file-backed sections do not collectively contain more raw
        bytes than the file.  Using the file size as a shared budget therefore
        preserves ordinary results while preventing overlapping or duplicated
        malicious section ranges from multiplying work by the section count.
        Sections consume the budget in their stable table order.
        """

        remaining_budget = len(self._data)
        results: list[SectionEntropy] = []
        for section in self._sections:
            result = self._section_entropy(section, remaining_budget)
            results.append(result)
            remaining_budget -= result.analyzed_size
        return tuple(results)

    def detect_overlay(self) -> OverlayInfo:
        """Find non-certificate bytes following all file-backed sections."""

        declared_image_end = min(
            max(0, self._optional_header.size_of_headers),
            len(self._data),
        )
        for section in self._sections:
            raw_end = section.pointer_to_raw_data + section.size_of_raw_data
            declared_image_end = max(declared_image_end, raw_end)

        sections_extend_past_file = declared_image_end > len(self._data)
        image_end = min(declared_image_end, len(self._data))
        certificate_offset, certificate_size = self._declared_certificate()
        certificate_valid = self._valid_tail_certificate(
            certificate_offset,
            certificate_size,
            image_end,
        )

        regions: list[OverlayRegion] = []
        if image_end < len(self._data):
            if certificate_valid and certificate_offset is not None:
                certificate_end = certificate_offset + certificate_size
                if certificate_offset > image_end:
                    regions.append(
                        OverlayRegion(image_end, certificate_offset - image_end)
                    )
                if certificate_end < len(self._data):
                    regions.append(
                        OverlayRegion(
                            certificate_end,
                            len(self._data) - certificate_end,
                        )
                    )
            else:
                regions.append(
                    OverlayRegion(image_end, len(self._data) - image_end)
                )

        total_size = sum(region.size for region in regions)
        present = total_size > 0
        overlay_entropy = self._region_entropy(tuple(regions)) if present else None
        if not present:
            suspicious = False
            suspicion_level: OverlaySuspicionLevel = "None"
            suspicion_reason = "No unexplained overlay bytes require review."
        elif (
            total_size >= _LARGE_OVERLAY_THRESHOLD
            or overlay_entropy is not None
            and overlay_entropy >= _HIGH_ENTROPY_THRESHOLD
        ):
            suspicious = True
            suspicion_level = "High"
            reasons: list[str] = []
            if total_size >= _LARGE_OVERLAY_THRESHOLD:
                reasons.append("its size is at least 1 MiB")
            if (
                overlay_entropy is not None
                and overlay_entropy >= _HIGH_ENTROPY_THRESHOLD
            ):
                reasons.append(
                    f"its entropy is {overlay_entropy:.3f} bits/byte"
                )
            suspicion_reason = (
                "Suspicion is High because " + " and ".join(reasons) + "."
            )
        else:
            suspicious = True
            suspicion_level = "Review"
            entropy_text = (
                f"{overlay_entropy:.3f} bits/byte"
                if overlay_entropy is not None
                else "unavailable"
            )
            suspicion_reason = (
                "Suspicion is Review because unexplained trailing bytes exist; "
                f"their entropy is {entropy_text} and their size is below 1 MiB."
            )

        if present and certificate_valid:
            explanation = (
                f"{total_size} non-certificate byte(s) remain after the final "
                "file-backed section; the structurally valid Certificate Table "
                f"range was excluded. {suspicion_reason}"
            )
        elif present and certificate_offset is not None and certificate_size:
            explanation = (
                f"{total_size} byte(s) remain after the final file-backed "
                "section. The declared Certificate Table is not an aligned, "
                "structurally valid, complete, non-overlapping tail range and "
                "was not excluded. "
                f"{suspicion_reason}"
            )
        elif present:
            explanation = (
                f"{total_size} byte(s) follow the final file-backed section and "
                f"no valid Certificate Table accounts for them. {suspicion_reason}"
            )
        elif certificate_valid:
            explanation = (
                "All bytes after the final file-backed section belong to the "
                "structurally valid Certificate Table, so no overlay remains. "
                f"{suspicion_reason}"
            )
        elif sections_extend_past_file:
            explanation = (
                "A section's declared raw range extends beyond the file; there "
                "are no bytes after the bounded image end to classify as overlay. "
                f"{suspicion_reason}"
            )
        else:
            explanation = (
                "The file ends at the final file-backed section, so no overlay "
                f"is present. {suspicion_reason}"
            )

        return OverlayInfo(
            present=present,
            image_end_offset=image_end,
            start_offset=regions[0].file_offset if regions else None,
            total_size=total_size,
            regions=tuple(regions),
            certificate_offset=certificate_offset,
            certificate_size=certificate_size,
            certificate_valid=certificate_valid,
            entropy=overlay_entropy,
            suspicious=suspicious,
            suspicion_level=suspicion_level,
            explanation=explanation,
        )

    def _section_entropy(
        self,
        section: SectionHeader,
        remaining_budget: int,
    ) -> SectionEntropy:
        start = section.pointer_to_raw_data
        declared_size = section.size_of_raw_data
        if declared_size == 0:
            return SectionEntropy(
                section_index=section.index,
                section_name=section.name,
                file_offset=start,
                declared_size=0,
                analyzed_size=0,
                entropy=None,
                color="gray",
                suspicious=False,
                explanation="The section has no raw file data to analyze.",
            )

        if declared_size < 0:
            return SectionEntropy(
                section_index=section.index,
                section_name=section.name,
                file_offset=start,
                declared_size=declared_size,
                analyzed_size=0,
                entropy=None,
                color="gray",
                suspicious=False,
                explanation=(
                    "The section's declared raw-data size is negative, so "
                    "entropy cannot be calculated safely."
                ),
            )

        if start < 0 or start >= len(self._data):
            return SectionEntropy(
                section_index=section.index,
                section_name=section.name,
                file_offset=start,
                declared_size=declared_size,
                analyzed_size=0,
                entropy=None,
                color="gray",
                suspicious=False,
                explanation=(
                    "The section's raw-data pointer is outside the file, so "
                    "entropy cannot be calculated safely."
                ),
            )

        available_size = min(declared_size, len(self._data) - start)
        analyzed_size = min(available_size, remaining_budget)
        if analyzed_size == 0:
            return SectionEntropy(
                section_index=section.index,
                section_name=section.name,
                file_offset=start,
                declared_size=declared_size,
                analyzed_size=0,
                entropy=None,
                color="gray",
                suspicious=False,
                explanation=(
                    "Entropy analysis was skipped because earlier sections "
                    f"consumed the shared aggregate budget of {len(self._data)} "
                    "byte(s), equal to the file size. This bounds work from "
                    "overlapping or duplicated raw ranges."
                ),
            )

        end = start + analyzed_size
        sample = self._data[start:end]
        entropy = self._shannon_entropy(sample)
        file_truncated = available_size != declared_size
        budget_truncated = analyzed_size != available_size

        if entropy >= _HIGH_ENTROPY_THRESHOLD:
            color: EntropyColor = "red"
            suspicious = True
            conclusion = (
                f"Entropy is {entropy:.3f} bits/byte, at or above the "
                f"{_HIGH_ENTROPY_THRESHOLD:.1f} high-entropy threshold; "
                "compression, encryption, or packing may be present."
            )
        elif entropy >= _ELEVATED_ENTROPY_THRESHOLD:
            color = "amber"
            suspicious = False
            conclusion = (
                f"Entropy is {entropy:.3f} bits/byte, elevated but below the "
                f"{_HIGH_ENTROPY_THRESHOLD:.1f} suspicious threshold."
            )
        else:
            color = "green"
            suspicious = False
            conclusion = (
                f"Entropy is {entropy:.3f} bits/byte, below the "
                f"{_ELEVATED_ENTROPY_THRESHOLD:.1f} elevated threshold."
            )

        if file_truncated:
            conclusion += (
                f" Only {available_size} of {declared_size} declared raw byte(s) "
                "were available; analysis was bounded to the file."
            )
        if budget_truncated:
            conclusion += (
                f" Only {analyzed_size} of {available_size} available raw "
                "byte(s) were analyzed because earlier sections consumed the "
                f"rest of the shared aggregate budget of {len(self._data)} "
                "byte(s), equal to the file size. This bounds work from "
                "overlapping or duplicated raw ranges."
            )

        return SectionEntropy(
            section_index=section.index,
            section_name=section.name,
            file_offset=start,
            declared_size=declared_size,
            analyzed_size=analyzed_size,
            entropy=entropy,
            color=color,
            suspicious=suspicious,
            explanation=conclusion,
        )

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        frequencies = [0] * 256
        for byte in data:
            frequencies[byte] += 1
        length = len(data)
        entropy = 0.0
        for count in frequencies:
            if count:
                probability = count / length
                entropy -= probability * math.log2(probability)
        return entropy

    def _declared_certificate(self) -> tuple[int | None, int]:
        for directory in self._optional_header.data_directories:
            if directory.index == _CERTIFICATE_DIRECTORY_INDEX:
                return (
                    directory.virtual_address or None,
                    directory.size,
                )
        return None, 0

    def _region_entropy(self, regions: tuple[OverlayRegion, ...]) -> float:
        frequencies = [0] * 256
        total_size = 0
        for region in regions:
            sample = self._data[region.file_offset:region.end_offset]
            total_size += len(sample)
            for byte in sample:
                frequencies[byte] += 1
        if total_size == 0:
            return 0.0
        entropy = 0.0
        for count in frequencies:
            if count:
                probability = count / total_size
                entropy -= probability * math.log2(probability)
        return entropy

    def _valid_tail_certificate(
        self,
        offset: int | None,
        size: int,
        image_end: int,
    ) -> bool:
        if offset is None or size < _MIN_CERTIFICATE_SIZE:
            return False
        if offset % 8 != 0:
            return False
        if offset < image_end or offset > len(self._data):
            return False
        if size > len(self._data) - offset:
            return False

        table_end = offset + size
        cursor = offset
        record_count = 0
        while cursor < table_end:
            if record_count >= _MAX_CERTIFICATE_RECORDS:
                return False
            if table_end - cursor < _WIN_CERTIFICATE_HEADER.size:
                return False

            length, revision, certificate_type = _WIN_CERTIFICATE_HEADER.unpack_from(
                self._data,
                cursor,
            )
            if length < _MIN_CERTIFICATE_SIZE:
                return False
            if revision not in _VALID_CERTIFICATE_REVISIONS:
                return False
            if certificate_type not in _VALID_CERTIFICATE_TYPES:
                return False

            aligned_length = (length + 7) & ~7
            if aligned_length > table_end - cursor:
                return False
            cursor += aligned_length
            record_count += 1

        return record_count > 0 and cursor == table_end
