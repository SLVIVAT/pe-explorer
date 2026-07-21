from __future__ import annotations

from dataclasses import dataclass, FrozenInstanceError
import json
from pathlib import Path
import tempfile
import unittest

from pe.reports import (
    ReportGenerator,
    generate_html_report,
    generate_json_report,
    generate_markdown_report,
)


@dataclass(frozen=True)
class _ExtensionValue:
    label: str
    raw: bytes
    conversion_count: list[int]

    def to_dict(self) -> dict[str, object]:
        self.conversion_count[0] += 1
        return {"label": self.label, "raw": self.raw}


def _pe_info() -> dict[str, object]:
    return {
        "file_name": "unsafe<script>.exe",
        "file_path": "C:/samples/a|b.exe",
        "file_size": 4096,
        "mz_signature": "MZ",
        "pe_offset": 128,
        "pe_signature": "PE",
        "machine": "x64",
        "number_of_sections": 1,
        "timestamp": 0x5E2A5C00,
        "pointer_to_symbol_table": 0,
        "number_of_symbols": 0,
        "optional_header_size": 240,
        "characteristics": 0x22,
        "coff_header": {
            "machine": 0x8664,
            "machine_name": "x64",
            "number_of_sections": 1,
            "timestamp": 0x5E2A5C00,
            "pointer_to_symbol_table": 0,
            "number_of_symbols": 0,
            "optional_header_size": 240,
            "characteristics": 0x22,
        },
        "optional_header": {
            "magic": 0x20B,
            "format": "PE32+",
            "image_base": 0x140000000,
            "data_directories": [
                {
                    "index": 0,
                    "name": "Export Table",
                    "virtual_address": 0x2000,
                    "size": 40,
                    "status": "Present",
                }
            ],
        },
        "sections": [
            {
                "index": 1,
                "name": ".text",
                "raw_name": b".text\x00\x00\x00",
                "virtual_address": 0x1000,
                "size_of_raw_data": 512,
                "characteristics": 0x60000020,
            }
        ],
        "imports": [
            {
                "dll_name": "KERNEL32.dll",
                "functions": [{"name": "CreateFileW", "ordinal": None}],
            }
        ],
        "exports": {
            "dll_name": "unsafe<script>.exe",
            "functions": [
                {"ordinal": 1, "name": "Exported|Name", "rva": 0x1010}
            ],
        },
        "resources": {
            "name": "Resources",
            "children": [
                {
                    "name": "RT_MANIFEST (24)",
                    "data": {"content": "<assembly>& dangerous"},
                }
            ],
        },
        "data_directories": [
            {
                "index": 0,
                "name": "Export Table",
                "virtual_address": 0x2000,
                "size": 40,
                "status": "Present",
            }
        ],
        "analysis": {
            "overall_risk": "Low",
            "risk_score": 5,
            "findings": [
                {
                    "label": "ASLR",
                    "value": "Enabled",
                    "explanation": "Flag <0x40> is set.",
                }
            ],
        },
        "future_field": {"supported": True},
    }


class ReportGeneratorTests(unittest.TestCase):
    REQUIRED_TITLES = (
        "Overview",
        "COFF Header",
        "Optional Header",
        "Data Directories",
        "Sections",
        "Imports",
        "Exports",
        "Resources",
        "Security Analysis",
    )

    def test_json_is_deterministic_complete_and_normalizes_extensions(self) -> None:
        conversion_count = [0]
        extension = _ExtensionValue(
            label="Certificate <metadata>",
            raw=b"\x01\xAB",
            conversion_count=conversion_count,
        )
        generator = ReportGenerator(
            _pe_info(),
            {"version_info": {"company": "Acme"}, "certificates": extension},
        )
        first = generator.to_json()
        second = generator.to_json()
        self.assertEqual(first, second)
        self.assertEqual(conversion_count, [1])

        document = json.loads(first)
        self.assertEqual(document["format_version"], 1)
        sections = document["sections"]
        titles = [section["title"] for section in sections]
        for title in self.REQUIRED_TITLES:
            self.assertIn(title, titles)
        self.assertIn("Additional Fields", titles)
        self.assertEqual(titles[-2:], ["Certificates", "Version Info"])

        section_data = {section["key"]: section["data"] for section in sections}
        self.assertEqual(
            section_data["sections"][0]["raw_name"],
            "0x2E74657874000000",
        )
        self.assertEqual(
            section_data["extension:certificates"]["raw"],
            "0x01AB",
        )
        self.assertEqual(
            section_data["additional"],
            {"future_field": {"supported": True}},
        )

    def test_html_escapes_untrusted_values_and_contains_all_sections(self) -> None:
        report = generate_html_report(
            _pe_info(),
            {"version_info": {"company": "A&B <Corp>"}},
        )
        self.assertTrue(report.startswith("<!doctype html>"))
        self.assertNotIn("<script>", report)
        self.assertIn("unsafe&lt;script&gt;.exe", report)
        self.assertIn("&lt;assembly&gt;&amp; dangerous", report)
        self.assertIn("A&amp;B &lt;Corp&gt;", report)
        for title in self.REQUIRED_TITLES:
            self.assertIn(f"<h2>{title}</h2>", report)

    def test_markdown_escapes_table_markup_and_is_deterministic(self) -> None:
        first = generate_markdown_report(_pe_info())
        second = generate_markdown_report(_pe_info())
        self.assertEqual(first, second)
        self.assertIn("a\\|b.exe", first)
        self.assertIn("Exported\\|Name", first)
        self.assertIn("unsafe&lt;script&gt;.exe", first)
        for title in self.REQUIRED_TITLES:
            self.assertIn(f"## {title}", first)

    def test_writes_all_formats_and_validates_format_selection(self) -> None:
        generator = ReportGenerator(_pe_info())
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            html_path = generator.write(root / "nested" / "report.html")
            json_path = generator.write(root / "report.json")
            markdown_path = generator.write(root / "report.md")
            explicit_path = generator.write(
                root / "report.txt",
                report_format="markdown",
            )

            self.assertEqual(
                html_path.read_text(encoding="utf-8"),
                generator.to_html(),
            )
            self.assertEqual(
                json_path.read_text(encoding="utf-8"),
                generator.to_json(),
            )
            self.assertEqual(
                markdown_path.read_text(encoding="utf-8"),
                generator.to_markdown(),
            )
            self.assertEqual(
                explicit_path.read_text(encoding="utf-8"),
                generator.to_markdown(),
            )

            with self.assertRaisesRegex(ValueError, "infer"):
                generator.write(root / "unknown.bin")
            with self.assertRaisesRegex(ValueError, "Unsupported"):
                generator.render("pdf")

    def test_document_models_are_immutable_and_helpers_match_generator(self) -> None:
        generator = ReportGenerator(_pe_info())
        with self.assertRaises(FrozenInstanceError):
            generator.document.title = "Changed"  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            generator.document.sections[0].title = "Changed"  # type: ignore[misc]

        value = generator.document.to_dict()
        self.assertEqual(value["sections"][0]["key"], "overview")
        self.assertEqual(generate_json_report(_pe_info()), generator.to_json())


if __name__ == "__main__":
    unittest.main()
