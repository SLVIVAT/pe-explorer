from __future__ import annotations

from collections.abc import Callable, Sequence
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QMimeData, QSettings, QUrl
from PySide6.QtWidgets import QApplication

from gui.main_window import MainWindow
from gui.pe_info_widget import PEInfoWidget
from pe.document import PEInspectionDocument
from tests.test_parser import OPTIONAL_HEADER_OFFSET, build_pe_fixture


TAB_NAMES: tuple[str, ...] = (
    "Overview",
    "Optional Header",
    "Sections",
    "Imports",
    "Exports",
    "Resources",
    "Data Directories",
    "Analysis",
    "Hex",
    "Search",
    "Strings",
    "File Analysis",
)


class _DropEventProbe:
    """Small event double that exercises drag/drop policy without a GUI drag."""

    def __init__(self, urls: Sequence[QUrl]) -> None:
        self._mime_data = QMimeData()
        self._mime_data.setUrls(list(urls))
        self.accepted = False
        self.ignored = False

    def mimeData(self) -> QMimeData:
        return self._mime_data

    def acceptProposedAction(self) -> None:
        self.accepted = True

    def ignore(self) -> None:
        self.ignored = True


class ProfessionalMainWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self._root = Path(self._temporary_directory.name)
        self._windows: list[MainWindow] = []
        self._views: list[PEInfoWidget] = []

    def tearDown(self) -> None:
        for widget in (*self._views, *self._windows):
            widget.close()
        self.application.processEvents()
        self._temporary_directory.cleanup()

    def _fixture_path(
        self,
        name: str = "sample64.exe",
        *,
        pe32_plus: bool = True,
    ) -> Path:
        path = self._root / name
        path.write_bytes(build_pe_fixture(pe32_plus=pe32_plus))
        return path

    def _document(self) -> PEInspectionDocument:
        return PEInspectionDocument.load(self._fixture_path())

    def _view(self) -> PEInfoWidget:
        view = PEInfoWidget()
        self._views.append(view)
        return view

    def _window(self) -> MainWindow:
        window = MainWindow()
        window._settings = QSettings(
            str(self._root / f"settings-{len(self._windows)}.ini"),
            QSettings.Format.IniFormat,
        )
        window._settings.clear()
        window._rebuild_recent_menu()
        self._windows.append(window)
        return window

    def _wait_until(
        self,
        predicate: Callable[[], bool],
        *,
        timeout: float = 5.0,
    ) -> None:
        deadline = time.monotonic() + timeout
        while not predicate():
            self.application.processEvents()
            if time.monotonic() >= deadline:
                self.fail("Timed out waiting for asynchronous GUI work")
            time.sleep(0.005)
        self.application.processEvents()

    def test_set_document_populates_all_twelve_professional_tabs(self) -> None:
        document = self._document()
        view = self._view()
        view.set_document(document)

        self.assertEqual(view.count(), len(TAB_NAMES))
        self.assertEqual(
            tuple(view.tabText(index) for index in range(view.count())),
            TAB_NAMES,
        )
        expected_widgets = (
            view.summary_output,
            view.optional_tree,
            view.sections_table,
            view.imports_widget,
            view.exports_widget,
            view.resources_widget,
            view.data_directories_widget,
            view.analysis_widget,
            view.hex_widget,
            view.search_widget,
            view.strings_widget,
            view.file_analysis_widget,
        )
        self.assertEqual(
            tuple(view.widget(index) for index in range(view.count())),
            expected_widgets,
        )
        self.assertTrue(
            all(not view.tabIcon(index).isNull() for index in range(view.count()))
        )

        self.assertEqual(view.hex_widget.model.byte_count, len(document.data))
        self.assertEqual(
            view.strings_widget.model.rowCount(),
            len(document.strings),
        )
        self.assertEqual(view.search_widget.status_label.text(), "Ready to search")
        self.assertEqual(
            view.file_analysis_widget.entropy_model.rowCount(),
            len(document.file_analysis.sections),
        )
        self.assertEqual(view.file_analysis_widget.hash_model.rowCount(), 4)
        self.assertEqual(view.file_analysis_widget.certificate_model.rowCount(), 11)
        self.assertEqual(view.file_analysis_widget.version_model.rowCount(), 10)
        self.assertEqual(view.file_analysis_widget.tabs.count(), 5)

        view.set_information(document.structural_info)
        self.assertEqual(view.hex_widget.model.byte_count, 0)
        self.assertEqual(view.strings_widget.model.rowCount(), 0)
        self.assertEqual(view.file_analysis_widget.entropy_model.rowCount(), 0)
        self.assertFalse(view.search_widget.search_button.isEnabled())
        self.assertTrue(view.summary_output.toPlainText())

    def test_structural_and_search_navigation_synchronize_hex_view(self) -> None:
        document = self._document()
        view = self._view()
        view.set_document(document)

        magic_item = view.optional_tree.topLevelItem(0).child(0)
        view.optional_tree.setCurrentItem(magic_item)
        self.application.processEvents()
        self.assertEqual(
            view.hex_widget.model.highlight_range,
            (OPTIONAL_HEADER_OFFSET, OPTIONAL_HEADER_OFFSET + 2),
        )

        mz_result = next(
            result
            for result in document.search.search("MZ", "ascii")
            if result.offset == 0
        )
        view.search_widget.model.set_results((mz_result,))
        view.setCurrentWidget(view.search_widget)
        result_index = view.search_widget.proxy_model.index(0, 0)
        self.assertTrue(result_index.isValid())
        view.search_widget.table.doubleClicked.emit(result_index)
        self.application.processEvents()

        self.assertIs(view.currentWidget(), view.hex_widget)
        self.assertEqual(view.hex_widget.model.highlight_range, (0, 2))
        self.assertEqual(view.hex_widget.address_input.text(), "0x0")

    def test_toolbar_focus_helpers_and_shortcuts_target_search_and_hex(self) -> None:
        window = self._window()
        window.show_document(self._document())
        window.show()
        self.application.processEvents()

        query = window.pe_info.search_widget.query_edit
        query.setText("MZ")
        window.search_button.click()
        self.application.processEvents()
        self.assertIs(
            window.pe_info.currentWidget(),
            window.pe_info.search_widget,
        )
        self.assertEqual(query.selectedText(), "MZ")
        self.assertTrue(query.hasFocus())

        address = window.pe_info.hex_widget.address_input
        address.setText("400")
        window._focus_hex_jump()
        self.application.processEvents()
        self.assertIs(window.pe_info.currentWidget(), window.pe_info.hex_widget)
        self.assertEqual(address.selectedText(), "400")
        self.assertTrue(address.hasFocus())

        shortcuts = {
            shortcut.key().toString() for shortcut in window._shortcuts
        }
        self.assertEqual(
            shortcuts,
            {"Ctrl+O", "Ctrl+F", "Ctrl+G", "Ctrl+Shift+S"},
        )

    def test_report_action_writes_selected_format_without_dialog_blocking(self) -> None:
        window = self._window()
        document = self._document()
        window.show_document(document)
        output_without_suffix = self._root / "inspection-report"

        with patch(
            "gui.main_window.QFileDialog.getSaveFileName",
            return_value=(
                str(output_without_suffix),
                "Markdown Report (*.md)",
            ),
        ):
            window.generate_report()

        output = output_without_suffix.with_suffix(".md")
        self.assertTrue(output.is_file())
        report = output.read_text(encoding="utf-8")
        self.assertIn("# PE Explorer Report", report)
        self.assertIn("## Security Analysis", report)
        self.assertIn("## Digital Signature", report)
        self.assertIn(str(output), window.statusBar().currentMessage())

    def test_recent_files_and_drag_drop_work_without_native_dialogs(self) -> None:
        window = self._window()
        first = self._fixture_path("first.exe", pe32_plus=False)
        second = self._fixture_path("second.exe")

        window._add_recent_file(first)
        window._add_recent_file(second)
        window._add_recent_file(first)
        self.assertEqual(
            window._recent_files(),
            [str(first.resolve()), str(second.resolve())],
        )
        action_text = [
            action.text()
            for action in window.recent_menu.actions()
            if not action.isSeparator()
        ]
        self.assertEqual(
            action_text,
            [first.name, second.name, "Clear recent files"],
        )
        self.assertTrue(window.recent_button.isEnabled())

        drag = _DropEventProbe((QUrl.fromLocalFile(str(second)),))
        window.dragEnterEvent(drag)  # type: ignore[arg-type]
        self.assertTrue(drag.accepted)
        self.assertFalse(drag.ignored)

        drop = _DropEventProbe((QUrl.fromLocalFile(str(second)),))
        with patch.object(window, "load_file") as load_file:
            window.dropEvent(drop)  # type: ignore[arg-type]
        self.assertTrue(drop.accepted)
        load_file.assert_called_once_with(second)

        remote = _DropEventProbe((QUrl("https://example.invalid/file.exe"),))
        window.dragEnterEvent(remote)  # type: ignore[arg-type]
        self.assertTrue(remote.ignored)

        window._clear_recent_files()
        self.assertEqual(window._recent_files(), [])
        self.assertFalse(window.recent_button.isEnabled())

    def test_load_file_completes_through_non_blocking_worker_shell(self) -> None:
        window = self._window()
        path = self._fixture_path()

        window.load_file(path)
        self.assertFalse(window.open_button.isEnabled())
        self.assertFalse(window.loading_progress.isHidden())
        self.assertIsNone(window.current_document)
        generation = window._load_generation
        window.load_file(path)
        self.assertEqual(window._load_generation, generation)
        self.assertEqual(len(window._load_tasks), 1)
        self.assertIn("additional load ignored", window.statusBar().currentMessage())

        self._wait_until(
            lambda: window.current_document is not None
            and not window._load_tasks
        )
        document = window.current_document
        assert document is not None
        self.assertEqual(document.path, path)
        self.assertTrue(window.open_button.isEnabled())
        self.assertTrue(window.loading_progress.isHidden())
        self.assertTrue(window.report_button.isEnabled())
        self.assertEqual(window.pe_info.count(), len(TAB_NAMES))
        self.assertEqual(window._recent_files(), [str(path.resolve())])
        self.assertEqual(window.statusBar().currentMessage(), "PE inspection completed")


if __name__ == "__main__":
    unittest.main()
