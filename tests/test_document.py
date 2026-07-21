from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from pe.document import PEInspectionDocument
from tests.test_parser import build_pe_fixture


class PEInspectionDocumentTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)

    def _fixture_path(self, *, pe32_plus: bool) -> Path:
        path = Path(self._temporary_directory.name) / (
            "sample64.exe" if pe32_plus else "sample32.exe"
        )
        path.write_bytes(build_pe_fixture(pe32_plus=pe32_plus))
        return path

    def test_loads_complete_pe32_and_pe32_plus_documents(self) -> None:
        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus):
                progress: list[str] = []
                document = PEInspectionDocument.load(
                    self._fixture_path(pe32_plus=pe32_plus),
                    progress=progress.append,
                )

                expected_format = "PE32+" if pe32_plus else "PE32"
                self.assertEqual(
                    document.image.optional_header.format,
                    expected_format,
                )
                self.assertEqual(document.data[:2], b"MZ")
                self.assertEqual(progress[0], "Parsing PE structures")
                self.assertEqual(progress[-1], "Ready")
                self.assertEqual(
                    len(document.file_analysis.sections),
                    len(document.image.sections),
                )
                self.assertEqual(len(document.file_analysis.hashes.sha256), 64)
                self.assertEqual(
                    document.search.search("MZ", "ascii")[0].offset,
                    0,
                )

    def test_serialization_excludes_raw_bytes_and_reports_all_extensions(self) -> None:
        document = PEInspectionDocument.load(
            self._fixture_path(pe32_plus=True)
        )
        info = document.to_dict()
        self.assertNotIn("data", info)
        self.assertIn("strings", info)
        self.assertFalse(info["strings_truncated"])
        self.assertEqual(info["string_limit"], 250_000)
        self.assertIn("entropy", info)
        self.assertIn("overlay", info)
        self.assertIn("hashes", info)
        self.assertIn("certificate", info)
        self.assertIn("version_information", info)

        report = json.loads(document.report_generator().to_json())
        titles = {section["title"] for section in report["sections"]}
        self.assertTrue(
            {
                "Overview",
                "COFF Header",
                "Optional Header",
                "Sections",
                "Imports",
                "Exports",
                "Resources",
                "Data Directories",
                "Security Analysis",
                "Entropy",
                "Overlay",
                "Hashes",
                "Digital Signature",
                "Version Information",
            }.issubset(titles)
        )

    def test_string_limit_is_deterministic_and_none_restores_unlimited_mode(
        self,
    ) -> None:
        values = (
            "Overlay-String-Number-0001",
            "Overlay-String-Number-0002",
            "Overlay-String-Number-0003",
            "Overlay-String-Number-0004",
        )
        path = Path(self._temporary_directory.name) / "string-heavy.exe"
        overlay = b"\x00".join(value.encode("ascii") for value in values) + b"\x00"
        path.write_bytes(build_pe_fixture(pe32_plus=True) + overlay)

        limited = PEInspectionDocument.load(
            path,
            minimum_string_length=16,
            maximum_strings=2,
        )
        self.assertEqual(
            tuple(item.value for item in limited.strings),
            values[:2],
        )
        self.assertTrue(limited.strings_truncated)
        self.assertEqual(limited.string_limit, 2)
        limited_info = limited.to_dict()
        self.assertTrue(limited_info["strings_truncated"])
        self.assertEqual(limited_info["string_limit"], 2)
        self.assertEqual(len(limited_info["strings"]), 2)

        unlimited = PEInspectionDocument.load(
            path,
            minimum_string_length=16,
            maximum_strings=None,
        )
        self.assertEqual(
            tuple(item.value for item in unlimited.strings),
            values,
        )
        self.assertFalse(unlimited.strings_truncated)
        self.assertIsNone(unlimited.string_limit)
        unlimited_info = unlimited.to_dict()
        self.assertFalse(unlimited_info["strings_truncated"])
        self.assertIsNone(unlimited_info["string_limit"])

    def test_document_accepts_zero_limit_and_rejects_invalid_limits(self) -> None:
        path = Path(self._temporary_directory.name) / "limited.exe"
        path.write_bytes(
            build_pe_fixture(pe32_plus=False) + b"LongOverlayString\x00"
        )

        empty = PEInspectionDocument.load(
            path,
            maximum_strings=0,
        )
        self.assertEqual(empty.strings, ())
        self.assertTrue(empty.strings_truncated)
        self.assertEqual(empty.string_limit, 0)

        with self.assertRaisesRegex(ValueError, "cannot be negative"):
            PEInspectionDocument.load(path, maximum_strings=-1)
        for value in (True, 1.5, "2"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(TypeError, "integer or None"):
                    PEInspectionDocument.load(
                        path,
                        maximum_strings=value,  # type: ignore[arg-type]
                    )

    def test_missing_file_preserves_parser_error_contract(self) -> None:
        missing = Path(self._temporary_directory.name) / "missing.exe"
        with self.assertRaises(FileNotFoundError):
            PEInspectionDocument.load(missing)


if __name__ == "__main__":
    unittest.main()
