from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from gui.main_window import MainWindow
from gui.theme import DARK_STYLESHEET, apply_dark_theme
from pe.parser import PEParser
from tests.test_parser import build_pe_fixture


class ApplicationThemeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def test_dark_theme_and_responsive_main_window_smoke(self) -> None:
        apply_dark_theme(self.application)
        self.assertEqual(self.application.styleSheet(), DARK_STYLESHEET)
        self.assertEqual(self.application.font().family(), "Segoe UI")

        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "sample.exe"
            path.write_bytes(build_pe_fixture(pe32_plus=True))
            info = PEParser(path).parse()

            window = MainWindow()
            self.addCleanup(window.close)
            window.show_pe_information(info)

            self.assertGreaterEqual(window.minimumWidth(), 900)
            self.assertGreaterEqual(window.minimumHeight(), 600)
            self.assertFalse(window.open_button.icon().isNull())
            self.assertEqual(window.pe_info.count(), 12)
            self.assertIn("PE32+", window.status_details.text())
            self.assertIn("2 sections", window.status_details.text())


if __name__ == "__main__":
    unittest.main()
