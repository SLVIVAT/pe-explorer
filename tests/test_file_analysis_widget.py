from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from gui.file_analysis_widget import FileAnalysisWidget
from pe.document import PEInspectionDocument
from tests.test_parser import build_pe_fixture


class FileAnalysisWidgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def test_displays_all_results_navigates_and_clears(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "sample.exe"
            path.write_bytes(build_pe_fixture(pe32_plus=True))
            document = PEInspectionDocument.load(path)

            widget = FileAnalysisWidget()
            offsets: list[tuple[int, int]] = []
            widget.fileOffsetNavigationRequested.connect(
                lambda offset, length: offsets.append((offset, length))
            )
            widget.set_results(
                document.file_analysis,
                document.certificate,
                document.version_information,
            )

            self.assertEqual(
                widget.entropy_model.rowCount(),
                len(document.image.sections),
            )
            self.assertEqual(widget.hash_model.rowCount(), 4)
            self.assertEqual(widget.certificate_model.rowCount(), 11)
            self.assertEqual(widget.version_model.rowCount(), 10)
            self.assertIn("Overlay:", widget.overlay_label.text())

            widget.entropy_table.setCurrentIndex(
                widget.entropy_proxy.index(0, 0)
            )
            self.application.processEvents()
            self.assertTrue(offsets)
            self.assertEqual(
                offsets[-1][0],
                document.file_analysis.sections[0].file_offset,
            )

            widget.clear_results()
            self.assertEqual(widget.entropy_model.rowCount(), 0)
            self.assertEqual(widget.overlay_model.rowCount(), 0)
            self.assertEqual(widget.hash_model.rowCount(), 0)


if __name__ == "__main__":
    unittest.main()
