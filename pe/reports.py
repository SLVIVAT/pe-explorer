"""Deterministic JSON, Markdown, and HTML reports for parsed PE metadata."""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import html
import json
import math
from pathlib import Path
from typing import Any, Final, Mapping

from pe.models import PEInfo


_FORMAT_BY_SUFFIX: Final[dict[str, str]] = {
    ".html": "html",
    ".htm": "html",
    ".json": "json",
    ".md": "markdown",
    ".markdown": "markdown",
}

_FORMAT_ALIASES: Final[dict[str, str]] = {
    "html": "html",
    "htm": "html",
    "json": "json",
    "md": "markdown",
    "markdown": "markdown",
}


@dataclass(frozen=True, slots=True)
class ReportSection:
    """One stable top-level section in a generated report."""

    key: str
    title: str
    data: Any

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "data": _normalize(self.data),
        }


@dataclass(frozen=True, slots=True)
class ReportDocument:
    """Normalized, serialization-ready report model."""

    title: str
    sections: tuple[ReportSection, ...]
    format_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "title": self.title,
            "sections": [section.to_dict() for section in self.sections],
        }


class ReportGenerator:
    """Render complete PE information into safe deterministic reports."""

    def __init__(
        self,
        pe_info: PEInfo | Mapping[str, Any],
        extension_mapping: Mapping[str, Any] | None = None,
        *,
        title: str | None = None,
    ) -> None:
        normalized = _normalize(pe_info)
        if not isinstance(normalized, dict):
            raise TypeError("pe_info must normalize to a mapping")
        extensions = _normalize(extension_mapping or {})
        if not isinstance(extensions, dict):
            raise TypeError("extension_mapping must normalize to a mapping")
        self._info: dict[str, Any] = normalized
        self._extensions: dict[str, Any] = extensions
        file_name = str(normalized.get("file_name") or "Portable Executable")
        self._title = title or f"PE Explorer Report - {file_name}"
        self._document = self._build_document()

    @property
    def document(self) -> ReportDocument:
        return self._document

    def to_json(self, *, indent: int = 2) -> str:
        """Return a stable UTF-8-friendly JSON report."""

        if indent < 0:
            raise ValueError("indent cannot be negative")
        return (
            json.dumps(
                self._document.to_dict(),
                ensure_ascii=False,
                indent=indent,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        )

    def to_markdown(self) -> str:
        """Return a Markdown report with every scalar represented in tables."""

        lines = [f"# {_escape_markdown(self._document.title)}", ""]
        for section in self._document.sections:
            lines.extend(
                (
                    f"## {_escape_markdown(section.title)}",
                    "",
                    "| Field | Value |",
                    "|---|---|",
                )
            )
            for path, value in _flatten(section.data):
                lines.append(
                    f"| {_escape_markdown(path)} | "
                    f"{_escape_markdown(_scalar_text(value))} |"
                )
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def to_html(self) -> str:
        """Return a standalone HTML report with safely escaped content."""

        parts = [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>{html.escape(self._document.title, quote=True)}</title>",
            "<style>",
            "body{background:#11151b;color:#e7edf5;font-family:Segoe UI,Arial,"
            "sans-serif;margin:0;padding:28px;line-height:1.45}",
            "main{max-width:1280px;margin:auto}",
            "h1{font-size:28px;margin:0 0 28px}h2{font-size:20px;margin:30px 0 10px}",
            "table{border-collapse:collapse;width:100%;table-layout:fixed;"
            "background:#181e27}",
            "th,td{border:1px solid #303a49;padding:8px 10px;text-align:left;"
            "vertical-align:top;overflow-wrap:anywhere;white-space:pre-wrap}",
            "th{background:#222b38;color:#9fc7ff}th:first-child{width:36%}",
            "tr:nth-child(even) td{background:#151b23}",
            "</style>",
            "</head>",
            "<body><main>",
            f"<h1>{html.escape(self._document.title, quote=True)}</h1>",
        ]
        for section in self._document.sections:
            parts.append(
                f"<section><h2>{html.escape(section.title, quote=True)}</h2>"
            )
            parts.append(
                "<table><thead><tr><th>Field</th><th>Value</th></tr>"
                "</thead><tbody>"
            )
            for path, value in _flatten(section.data):
                escaped_path = html.escape(path, quote=True)
                escaped_value = html.escape(_scalar_text(value), quote=True)
                parts.append(
                    f"<tr><td>{escaped_path}</td><td>{escaped_value}</td></tr>"
                )
            parts.append("</tbody></table></section>")
        parts.extend(("</main></body>", "</html>"))
        return "\n".join(parts) + "\n"

    def render(self, report_format: str) -> str:
        """Render one of ``html``, ``json``, or ``markdown``."""

        normalized_format = _normalize_format(report_format)
        if normalized_format == "html":
            return self.to_html()
        if normalized_format == "json":
            return self.to_json()
        return self.to_markdown()

    def write(
        self,
        path: str | Path,
        report_format: str | None = None,
    ) -> Path:
        """Write a report, inferring its format from the file suffix by default."""

        output_path = Path(path)
        if report_format is None:
            try:
                normalized_format = _FORMAT_BY_SUFFIX[output_path.suffix.lower()]
            except KeyError as error:
                raise ValueError(
                    "Cannot infer report format; use .html, .json, .md, or "
                    "provide report_format."
                ) from error
        else:
            normalized_format = _normalize_format(report_format)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            self.render(normalized_format),
            encoding="utf-8",
            newline="\n",
        )
        return output_path

    def _build_document(self) -> ReportDocument:
        optional_header = self._mapping("optional_header")
        directories = self._info.get("data_directories")
        if directories is None:
            directories = optional_header.get("data_directories", [])
        optional_without_directories = {
            key: value
            for key, value in optional_header.items()
            if key != "data_directories"
        }

        overview_keys = (
            "file_name",
            "file_path",
            "file_size",
            "mz_signature",
            "pe_offset",
            "pe_signature",
            "machine",
            "number_of_sections",
            "timestamp",
            "characteristics",
        )
        overview = {
            key: self._info.get(key)
            for key in overview_keys
        }
        sections: list[ReportSection] = [
            ReportSection("overview", "Overview", overview),
            ReportSection("coff_header", "COFF Header", self._mapping("coff_header")),
            ReportSection(
                "optional_header",
                "Optional Header",
                optional_without_directories,
            ),
            ReportSection("data_directories", "Data Directories", directories or []),
            ReportSection("sections", "Sections", self._info.get("sections") or []),
            ReportSection("imports", "Imports", self._info.get("imports") or []),
            ReportSection("exports", "Exports", self._info.get("exports")),
            ReportSection("resources", "Resources", self._info.get("resources")),
            ReportSection(
                "analysis",
                "Security Analysis",
                self._info.get("analysis"),
            ),
        ]

        consumed = set(overview_keys) | {
            "coff_header",
            "optional_header",
            "data_directories",
            "sections",
            "imports",
            "exports",
            "resources",
            "analysis",
            "pointer_to_symbol_table",
            "number_of_symbols",
            "optional_header_size",
        }
        additional = {
            key: value
            for key, value in self._info.items()
            if key not in consumed
        }
        if additional:
            sections.append(
                ReportSection("additional", "Additional Fields", additional)
            )

        for key in sorted(self._extensions, key=str.casefold):
            sections.append(
                ReportSection(
                    key=f"extension:{key}",
                    title=_humanize(key),
                    data=self._extensions[key],
                )
            )
        return ReportDocument(title=self._title, sections=tuple(sections))

    def _mapping(self, key: str) -> dict[str, Any]:
        value = self._info.get(key)
        return value if isinstance(value, dict) else {}


def _normalize(
    value: Any,
    *,
    _active: set[int] | None = None,
    _depth: int = 0,
) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, bytes):
        return "0x" + value.hex().upper()
    if isinstance(value, (Path, Enum)):
        return str(value.value if isinstance(value, Enum) else value)
    if _depth > 64:
        return "<maximum depth reached>"

    active = _active if _active is not None else set()
    identity = id(value)
    if identity in active:
        return "<cycle>"
    active.add(identity)
    try:
        converter = getattr(value, "to_dict", None)
        if callable(converter):
            return _normalize(
                converter(),
                _active=active,
                _depth=_depth + 1,
            )
        if is_dataclass(value) and not isinstance(value, type):
            return _normalize(
                asdict(value),
                _active=active,
                _depth=_depth + 1,
            )
        if isinstance(value, Mapping):
            normalized_items = sorted(
                ((str(key), item) for key, item in value.items()),
                key=lambda pair: pair[0],
            )
            return {
                key: _normalize(
                    item,
                    _active=active,
                    _depth=_depth + 1,
                )
                for key, item in normalized_items
            }
        if isinstance(value, (list, tuple)):
            return [
                _normalize(item, _active=active, _depth=_depth + 1)
                for item in value
            ]
        if isinstance(value, (set, frozenset)):
            normalized = [
                _normalize(item, _active=active, _depth=_depth + 1)
                for item in value
            ]
            return sorted(
                normalized,
                key=lambda item: json.dumps(
                    item,
                    ensure_ascii=False,
                    sort_keys=True,
                    default=str,
                ),
            )
        return str(value)
    finally:
        active.remove(identity)


def _flatten(value: Any, path: str = "") -> tuple[tuple[str, Any], ...]:
    normalized = _normalize(value)
    rows: list[tuple[str, Any]] = []

    def visit(item: Any, current_path: str) -> None:
        if isinstance(item, dict):
            if not item:
                rows.append((current_path or "Value", {}))
                return
            for key, child in item.items():
                child_path = f"{current_path}.{key}" if current_path else key
                visit(child, child_path)
            return
        if isinstance(item, list):
            if not item:
                rows.append((current_path or "Value", []))
                return
            for index, child in enumerate(item):
                visit(child, f"{current_path}[{index}]")
            return
        rows.append((current_path or "Value", item))

    visit(normalized, path)
    return tuple(rows)


def _scalar_text(value: Any) -> str:
    if value is None:
        return "Not available"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _escape_markdown(value: str) -> str:
    escaped = value.replace("&", "&amp;")
    escaped = escaped.replace("<", "&lt;").replace(">", "&gt;")
    escaped = escaped.replace("\\", "\\\\").replace("|", "\\|")
    for marker in ("`", "*", "_", "[", "]"):
        escaped = escaped.replace(marker, "\\" + marker)
    return escaped.replace("\r\n", "<br>").replace("\n", "<br>").replace("\r", "<br>")


def _humanize(value: str) -> str:
    words = value.replace("_", " ").replace("-", " ").strip()
    return words.title() if words else "Extension"


def _normalize_format(value: str) -> str:
    try:
        return _FORMAT_ALIASES[value.strip().lower().lstrip(".")]
    except (AttributeError, KeyError) as error:
        raise ValueError(
            "Unsupported report format; expected html, json, or markdown."
        ) from error


def generate_html_report(
    pe_info: PEInfo | Mapping[str, Any],
    extension_mapping: Mapping[str, Any] | None = None,
) -> str:
    return ReportGenerator(pe_info, extension_mapping).to_html()


def generate_json_report(
    pe_info: PEInfo | Mapping[str, Any],
    extension_mapping: Mapping[str, Any] | None = None,
) -> str:
    return ReportGenerator(pe_info, extension_mapping).to_json()


def generate_markdown_report(
    pe_info: PEInfo | Mapping[str, Any],
    extension_mapping: Mapping[str, Any] | None = None,
) -> str:
    return ReportGenerator(pe_info, extension_mapping).to_markdown()


__all__ = [
    "ReportDocument",
    "ReportGenerator",
    "ReportSection",
    "generate_html_report",
    "generate_json_report",
    "generate_markdown_report",
]
