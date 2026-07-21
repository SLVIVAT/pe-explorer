"""Binary and address search services for parsed PE images."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Literal, TypedDict, cast

from pe.addressing import AddressMapping, AddressingService
from pe.errors import PEFormatError


SearchMode = Literal["ascii", "utf-16le", "hex", "rva", "va", "file-offset"]
_SEARCH_MODES = frozenset({"ascii", "utf-16le", "hex", "rva", "va", "file-offset"})
_HEX_SEPARATORS = re.compile(r"[\s,:_-]+")
_HEX_DIGITS = re.compile(r"^[0-9A-Fa-f]+$")


class SearchQueryError(ValueError):
    """Raised when a user-facing search query is invalid or unmappable."""


class SearchResultInfo(TypedDict):
    offset: int | None
    rva: int | None
    va: int | None
    section: str | None
    preview: str
    length: int
    mode: SearchMode


@dataclass(frozen=True, slots=True)
class SearchResult:
    """One binary match or exact-address lookup result."""

    offset: int | None
    rva: int | None
    va: int | None
    section: str | None
    preview: str
    length: int
    mode: SearchMode

    def to_dict(self) -> SearchResultInfo:
        return {
            "offset": self.offset,
            "rva": self.rva,
            "va": self.va,
            "section": self.section,
            "preview": self.preview,
            "length": self.length,
            "mode": self.mode,
        }


class SearchService:
    """Search immutable file bytes or resolve exact PE addresses."""

    def __init__(
        self,
        data: bytes,
        mapper: AddressingService,
        preview_bytes: int = 12,
    ) -> None:
        if (
            isinstance(preview_bytes, bool)
            or not isinstance(preview_bytes, int)
        ):
            raise TypeError("preview_bytes must be an integer")
        if preview_bytes < 0:
            raise ValueError("preview_bytes cannot be negative")
        self._data = data
        self._mapper = mapper
        self._preview_bytes = preview_bytes

    def search(
        self,
        query: str,
        mode: SearchMode | str,
        *,
        max_results: int = 1000,
    ) -> tuple[SearchResult, ...]:
        """Execute a byte-pattern search or one exact-address lookup.

        Unprefixed addresses are hexadecimal, matching conventional PE-tool
        displays.  ``0x`` hexadecimal and ``0d`` decimal prefixes are also
        accepted.
        """

        normalized_mode = self._validate_mode(mode)
        if isinstance(max_results, bool) or not isinstance(max_results, int):
            raise TypeError("max_results must be an integer")
        if max_results <= 0:
            raise ValueError("max_results must be positive")

        if normalized_mode == "ascii":
            pattern = self._ascii_pattern(query)
        elif normalized_mode == "utf-16le":
            pattern = self._utf16le_pattern(query)
        elif normalized_mode == "hex":
            pattern = self._hex_pattern(query)
        else:
            return (
                self._address_result(query, normalized_mode),
            )

        return self._find_pattern(
            pattern,
            normalized_mode,
            max_results=max_results,
        )

    @staticmethod
    def _validate_mode(mode: SearchMode | str) -> SearchMode:
        if mode not in _SEARCH_MODES:
            choices = ", ".join(sorted(_SEARCH_MODES))
            raise SearchQueryError(
                f"Unsupported search mode {mode!r}; expected one of {choices}."
            )
        return cast(SearchMode, mode)

    @staticmethod
    def _ascii_pattern(query: str) -> bytes:
        if not query:
            raise SearchQueryError("ASCII search query cannot be empty.")
        try:
            return query.encode("ascii")
        except UnicodeEncodeError as exc:
            raise SearchQueryError(
                "ASCII search query contains non-ASCII characters."
            ) from exc

    @staticmethod
    def _utf16le_pattern(query: str) -> bytes:
        if not query:
            raise SearchQueryError("UTF-16LE search query cannot be empty.")
        try:
            return query.encode("utf-16le")
        except UnicodeEncodeError as exc:
            raise SearchQueryError("UTF-16LE search query is not encodable.") from exc

    @staticmethod
    def _hex_pattern(query: str) -> bytes:
        text = query.strip()
        if not text:
            raise SearchQueryError("Hex search query cannot be empty.")
        text = re.sub(r"0[xX]", "", text)
        compact = _HEX_SEPARATORS.sub("", text)
        if not compact or not _HEX_DIGITS.fullmatch(compact):
            raise SearchQueryError(
                "Hex query may contain only hexadecimal byte pairs and separators."
            )
        if len(compact) % 2:
            raise SearchQueryError("Hex query must contain complete byte pairs.")
        return bytes.fromhex(compact)

    def _address_result(
        self,
        query: str,
        mode: Literal["rva", "va", "file-offset"],
    ) -> SearchResult:
        address = self._parse_address(query)
        if mode == "file-offset":
            if address >= len(self._data):
                raise SearchQueryError(
                    f"File offset 0x{address:X} is outside the file."
                )
            try:
                mapping = self._mapper.file_offset_to_mapping(address)
            except PEFormatError:
                # Physical overlay, certificate, and gap bytes remain valid
                # exact file-offset results even without loader addresses.
                mapping = None
            return self._result_for_location(
                offset=address,
                mapping=mapping,
                length=1,
                mode=mode,
            )

        try:
            mapping = (
                self._mapper.rva_to_mapping(address)
                if mode == "rva"
                else self._mapper.va_to_mapping(address)
            )
        except PEFormatError as exc:
            raise SearchQueryError(str(exc)) from exc
        return self._result_for_location(
            offset=mapping.file_offset,
            mapping=mapping,
            length=1 if mapping.file_offset is not None else 0,
            mode=mode,
        )

    @staticmethod
    def _parse_address(query: str) -> int:
        text = query.strip().replace("_", "")
        if not text:
            raise SearchQueryError("Address query cannot be empty.")
        if text.startswith("-"):
            raise SearchQueryError("Address cannot be negative.")
        try:
            if text.lower().startswith("0d"):
                value = int(text[2:], 10)
            elif text.lower().startswith("0x"):
                value = int(text[2:], 16)
            else:
                value = int(text, 16)
        except ValueError as exc:
            raise SearchQueryError(
                f"Invalid address {query!r}; use hexadecimal or 0d-prefixed decimal."
            ) from exc
        if value < 0:
            raise SearchQueryError("Address cannot be negative.")
        return value

    def _find_pattern(
        self,
        pattern: bytes,
        mode: Literal["ascii", "utf-16le", "hex"],
        *,
        max_results: int,
    ) -> tuple[SearchResult, ...]:
        results: list[SearchResult] = []
        cursor = 0
        while len(results) < max_results:
            offset = self._data.find(pattern, cursor)
            if offset == -1:
                break
            try:
                mapping = self._mapper.file_offset_to_mapping(offset)
            except PEFormatError:
                mapping = None
            results.append(
                self._result_for_location(
                    offset=offset,
                    mapping=mapping,
                    length=len(pattern),
                    mode=mode,
                )
            )
            # One-byte advancement preserves overlapping matches.
            cursor = offset + 1
        return tuple(results)

    def _result_for_location(
        self,
        *,
        offset: int | None,
        mapping: AddressMapping | None,
        length: int,
        mode: SearchMode,
    ) -> SearchResult:
        return SearchResult(
            offset=offset,
            rva=mapping.rva if mapping is not None else None,
            va=mapping.va if mapping is not None else None,
            section=mapping.section_name if mapping is not None else None,
            preview=self._preview(offset, length),
            length=length,
            mode=mode,
        )

    def _preview(self, offset: int | None, length: int) -> str:
        if offset is None:
            return "No file-backed bytes are available for this address."
        start = max(0, offset - self._preview_bytes)
        match_end = min(len(self._data), offset + max(length, 1))
        end = min(len(self._data), match_end + self._preview_bytes)
        sample = self._data[start:end]
        hex_text = " ".join(f"{byte:02X}" for byte in sample)
        ascii_text = "".join(
            chr(byte) if 0x20 <= byte <= 0x7E else "." for byte in sample
        )
        return f"0x{start:08X}: {hex_text} |{ascii_text}|"


__all__ = [
    "SearchMode",
    "SearchQueryError",
    "SearchResult",
    "SearchResultInfo",
    "SearchService",
]
