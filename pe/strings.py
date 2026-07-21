"""Fast extraction of printable ASCII and UTF-16LE strings."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
import heapq
import re
from typing import Literal, TypedDict

from pe.addressing import AddressingService
from pe.errors import PEFormatError


StringEncoding = Literal["ASCII", "UTF-16LE"]
_DEFAULT_MAXIMUM_STRING_BYTES = 64 * 1024


class ExtractedStringInfo(TypedDict):
    offset: int
    rva: int | None
    length: int
    encoding: StringEncoding
    value: str
    section: str | None
    byte_length: int


@dataclass(frozen=True, slots=True)
class ExtractedString:
    """One printable string found in the file image."""

    offset: int
    rva: int | None
    length: int
    encoding: StringEncoding
    value: str
    section: str | None
    byte_length: int

    def to_dict(self) -> ExtractedStringInfo:
        return {
            "offset": self.offset,
            "rva": self.rva,
            "length": self.length,
            "encoding": self.encoding,
            "value": self.value,
            "section": self.section,
            "byte_length": self.byte_length,
        }


@dataclass(frozen=True, slots=True)
class StringExtractionResult:
    """Strings returned by one extraction and its limiting metadata."""

    strings: tuple[ExtractedString, ...]
    truncated: bool
    limit: int | None


class StringExtractor:
    """Extract displayable strings from an immutable byte image.

    The implementation uses the standard-library regular-expression engine,
    avoiding a Python-level loop over every byte.  ASCII strings use bytes in
    the conventional 0x20..0x7E range.  UTF-16LE extraction recognizes those
    same displayable characters as little-endian code units, matching the
    established ``strings -el`` behavior while avoiding false positives from
    arbitrary binary words.
    """

    def __init__(
        self,
        data: bytes,
        minimum_length: int = 4,
        mapper: AddressingService | None = None,
        *,
        maximum_string_bytes: int | None = _DEFAULT_MAXIMUM_STRING_BYTES,
    ) -> None:
        if isinstance(minimum_length, bool) or not isinstance(minimum_length, int):
            raise TypeError("minimum_length must be an integer")
        if minimum_length <= 0:
            raise ValueError("minimum_length must be positive")
        if maximum_string_bytes is not None:
            if isinstance(maximum_string_bytes, bool) or not isinstance(
                maximum_string_bytes,
                int,
            ):
                raise TypeError(
                    "maximum_string_bytes must be an integer or None"
                )
            minimum_safe_limit = minimum_length * 4
            if maximum_string_bytes < minimum_safe_limit:
                raise ValueError(
                    "maximum_string_bytes must be at least four times "
                    "minimum_length"
                )

        self._data = data
        self._minimum_length = minimum_length
        self._mapper = mapper
        self._maximum_string_bytes = maximum_string_bytes
        count = str(minimum_length).encode("ascii")
        self._ascii_pattern = re.compile(rb"[\x20-\x7E]{" + count + rb",}")
        self._utf16le_pattern = re.compile(
            rb"(?:[\x20-\x7E]\x00){" + count + rb",}"
        )

    @property
    def minimum_length(self) -> int:
        return self._minimum_length

    @property
    def maximum_string_bytes(self) -> int | None:
        """Maximum bytes retained per record, or ``None`` when unlimited."""

        return self._maximum_string_bytes

    def extract(
        self,
        *,
        include_ascii: bool = True,
        include_utf16le: bool = True,
        maximum_strings: int | None = None,
    ) -> tuple[ExtractedString, ...]:
        """Return selected strings ordered by file position then encoding.

        ``maximum_strings=None`` preserves the original unlimited behavior.
        A nonnegative limit stops the lazy merge after at most one additional
        match, which is required to report truncation accurately through
        :meth:`extract_result`.
        """

        return self.extract_result(
            include_ascii=include_ascii,
            include_utf16le=include_utf16le,
            maximum_strings=maximum_strings,
        ).strings

    def extract_result(
        self,
        *,
        include_ascii: bool = True,
        include_utf16le: bool = True,
        maximum_strings: int | None = None,
    ) -> StringExtractionResult:
        """Return strings plus exact limit and truncation metadata.

        ASCII and UTF-16LE scanners are individually ordered generators.
        ``heapq.merge`` combines them without building either complete result
        set, preserving the historic ``(offset, encoding)`` order while
        allowing a capped caller to stop scanning early.
        """

        self._validate_maximum_strings(maximum_strings)
        iterators: list[Iterator[ExtractedString]] = []
        if include_ascii:
            iterators.append(self._iter_ascii())
        if include_utf16le:
            iterators.append(self._iter_utf16le())

        merged = heapq.merge(
            *iterators,
            key=lambda item: (item.offset, item.encoding),
        )
        if maximum_strings is None:
            return StringExtractionResult(
                strings=tuple(merged),
                truncated=False,
                limit=None,
            )

        strings: list[ExtractedString] = []
        truncated = False
        for item in merged:
            if len(strings) >= maximum_strings:
                truncated = True
                break
            strings.append(item)
        return StringExtractionResult(
            strings=tuple(strings),
            truncated=truncated,
            limit=maximum_strings,
        )

    def extract_ascii(self) -> tuple[ExtractedString, ...]:
        """Return all printable ASCII runs meeting ``minimum_length``."""

        return tuple(self._iter_ascii())

    def _iter_ascii(self) -> Iterator[ExtractedString]:
        """Yield ASCII strings in increasing file-offset order."""

        for match in self._ascii_pattern.finditer(self._data):
            for start, end in self._chunk_ranges(
                match.start(),
                match.end(),
                code_unit_size=1,
            ):
                rva, section = self._address_details(start)
                length = end - start
                yield ExtractedString(
                    offset=start,
                    rva=rva,
                    length=length,
                    encoding="ASCII",
                    value=self._data[start:end].decode("ascii"),
                    section=section,
                    byte_length=length,
                )

    def extract_utf16le(self) -> tuple[ExtractedString, ...]:
        """Return printable UTF-16LE runs meeting ``minimum_length``."""

        return tuple(self._iter_utf16le())

    def _iter_utf16le(self) -> Iterator[ExtractedString]:
        """Yield UTF-16LE strings in increasing file-offset order."""

        cursor = 0
        while match := self._utf16le_pattern.search(self._data, cursor):
            # Avoid treating the final byte of an adjacent ASCII string as the
            # first UTF-16LE code unit.  A rejected match may overlap the real
            # aligned run, so advance one byte and search again.
            preceding_byte = (
                self._data[match.start() - 1] if match.start() > 0 else None
            )
            if preceding_byte is not None and 0x20 <= preceding_byte <= 0x7E:
                cursor = match.start() + 1
                continue

            for start, end in self._chunk_ranges(
                match.start(),
                match.end(),
                code_unit_size=2,
            ):
                byte_length = end - start
                value = self._data[start:end].decode("utf-16le")
                rva, section = self._address_details(start)
                yield ExtractedString(
                    offset=start,
                    rva=rva,
                    length=byte_length // 2,
                    encoding="UTF-16LE",
                    value=value,
                    section=section,
                    byte_length=byte_length,
                )
            cursor = match.end()

    def _chunk_ranges(
        self,
        start: int,
        end: int,
        *,
        code_unit_size: int,
    ) -> Iterator[tuple[int, int]]:
        """Split pathological runs without copying an unbounded string."""

        maximum_bytes = self._maximum_string_bytes
        if maximum_bytes is None or end - start <= maximum_bytes:
            yield start, end
            return

        total_units = (end - start) // code_unit_size
        maximum_units = maximum_bytes // code_unit_size
        chunk_count = (total_units + maximum_units - 1) // maximum_units
        base_units, extra_chunks = divmod(total_units, chunk_count)
        cursor = start
        for chunk_index in range(chunk_count):
            units = base_units + (chunk_index < extra_chunks)
            chunk_end = cursor + units * code_unit_size
            yield cursor, chunk_end
            cursor = chunk_end

    @staticmethod
    def _validate_maximum_strings(maximum_strings: int | None) -> None:
        if maximum_strings is None:
            return
        if isinstance(maximum_strings, bool) or not isinstance(
            maximum_strings,
            int,
        ):
            raise TypeError("maximum_strings must be an integer or None")
        if maximum_strings < 0:
            raise ValueError("maximum_strings cannot be negative")

    def _address_details(self, offset: int) -> tuple[int | None, str | None]:
        if self._mapper is None:
            return None, None
        try:
            mapping = self._mapper.file_offset_to_mapping(offset)
        except PEFormatError:
            # Strings in file gaps, certificates, and overlays are still
            # useful even though the loader does not assign them an RVA.
            return None, None
        return mapping.rva, mapping.section_name


def extract_strings(
    data: bytes,
    minimum_length: int = 4,
    *,
    include_ascii: bool = True,
    include_utf16le: bool = True,
    mapper: AddressingService | None = None,
    maximum_strings: int | None = None,
    maximum_string_bytes: int | None = _DEFAULT_MAXIMUM_STRING_BYTES,
) -> tuple[ExtractedString, ...]:
    """Convenience wrapper for one-shot string extraction."""

    return StringExtractor(
        data,
        minimum_length,
        mapper,
        maximum_string_bytes=maximum_string_bytes,
    ).extract(
        include_ascii=include_ascii,
        include_utf16le=include_utf16le,
        maximum_strings=maximum_strings,
    )


__all__ = [
    "ExtractedString",
    "ExtractedStringInfo",
    "StringEncoding",
    "StringExtractionResult",
    "StringExtractor",
    "extract_strings",
]
