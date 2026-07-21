from __future__ import annotations

import os
from threading import Event
import time
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QThreadPool, Qt
from PySide6.QtWidgets import QApplication

from gui.search_widget import SearchResultTableModel, SearchWidget
from pe.search import SearchResult
from tests.test_search import _service


class _DelayedService:
    def __init__(self, release: Event, result_offset: int) -> None:
        self.started = Event()
        self.release = release
        self.result_offset = result_offset

    def search(
        self,
        query: str,
        mode: str,
        *,
        max_results: int,
    ) -> tuple[SearchResult, ...]:
        del query, mode, max_results
        self.started.set()
        self.release.wait(2.0)
        return (
            SearchResult(
                offset=self.result_offset,
                rva=None,
                va=None,
                section=None,
                preview="delayed",
                length=1,
                mode="ascii",
            ),
        )


class SearchWidgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.pool = QThreadPool()
        self.pool.setMaxThreadCount(2)
        self.widget = SearchWidget(self.pool)
        self.addCleanup(self._cleanup)

    def _cleanup(self) -> None:
        self.pool.waitForDone(3000)
        self.application.processEvents()
        self.widget.close()

    def _wait(self, timeout: float = 3.0) -> None:
        deadline = time.monotonic() + timeout
        while self.widget.is_busy and time.monotonic() < deadline:
            self.application.processEvents()
            time.sleep(0.005)
        self.pool.waitForDone(max(1, int(timeout * 1000)))
        for _ in range(4):
            self.application.processEvents()
        self.assertFalse(self.widget.is_busy)

    def test_model_formats_and_sorts_nullable_address_columns(self) -> None:
        model = SearchResultTableModel()
        model.set_results(
            (
                SearchResult(
                    0x220,
                    0x1020,
                    0x401020,
                    ".text",
                    "preview one",
                    5,
                    "ascii",
                ),
                SearchResult(
                    0x700,
                    None,
                    None,
                    None,
                    "overlay",
                    4,
                    "hex",
                ),
            )
        )
        self.assertEqual(model.rowCount(), 2)
        self.assertEqual(model.columnCount(), 5)
        self.assertEqual(model.data(model.index(0, 0)), "0x00000220")
        self.assertEqual(model.data(model.index(0, 2)), "0x00401020")
        self.assertEqual(model.data(model.index(1, 1)), "")
        self.assertEqual(
            model.data(model.index(0, 0), Qt.ItemDataRole.UserRole),
            0x220,
        )
        self.assertIn(
            "Match length: 5",
            str(model.data(model.index(0, 4), Qt.ItemDataRole.ToolTipRole)),
        )

    def test_all_modes_run_asynchronously_with_real_search_service(self) -> None:
        self.widget.set_service(_service())
        cases = (
            ("ascii", "Hello", 0x220),
            ("utf-16le", "World", 0x250),
            ("hex", "DE AD BE EF", 0x280),
            ("rva", "1020", 0x220),
            ("va", "401020", 0x220),
            ("file-offset", "220", 0x220),
        )
        for mode, query, expected_offset in cases:
            with self.subTest(mode=mode):
                self.widget.mode_combo.setCurrentIndex(
                    self.widget.mode_combo.findData(mode)
                )
                self.widget.query_edit.setText(query)
                before = time.monotonic()
                self.widget.start_search()
                self.assertLess(time.monotonic() - before, 0.2)
                self._wait()
                self.assertGreaterEqual(self.widget.model.rowCount(), 1)
                self.assertEqual(
                    self.widget.model.result(0).offset,
                    expected_offset,
                )
                self.assertIn("result", self.widget.status_label.text())

    def test_error_status_and_limit_are_user_visible(self) -> None:
        self.widget.set_service(_service())
        errors: list[str] = []
        self.widget.errorOccurred.connect(errors.append)
        self.widget.mode_combo.setCurrentIndex(
            self.widget.mode_combo.findData("hex")
        )
        self.widget.query_edit.setText("ABC")
        self.widget.start_search()
        self._wait()
        self.assertEqual(self.widget.model.rowCount(), 0)
        self.assertTrue(self.widget.status_label.text().startswith("Error:"))
        self.assertIn("complete byte pairs", errors[0])

        self.widget.mode_combo.setCurrentIndex(
            self.widget.mode_combo.findData("hex")
        )
        self.widget.query_edit.setText("DE AD BE EF")
        self.widget.limit_spin.setValue(1)
        self.widget.start_search()
        self._wait()
        self.assertEqual(self.widget.model.rowCount(), 1)
        self.assertIn("limit reached", self.widget.status_label.text())

    def test_stale_background_results_cannot_replace_new_service_state(self) -> None:
        release = Event()
        delayed = _DelayedService(release, 0x111)
        self.widget.set_service(delayed)  # type: ignore[arg-type]
        self.widget.query_edit.setText("old")
        self.widget.start_search()
        self.assertTrue(delayed.started.wait(1.0))
        old_generation = self.widget.generation
        self.widget.start_search()
        self.assertEqual(self.widget.generation, old_generation)
        self.assertEqual(len(self.widget._tasks), 1)
        self.assertIn("previous search", self.widget.status_label.text())

        self.widget.set_service(_service())
        self.assertGreater(self.widget.generation, old_generation)
        self.assertEqual(self.widget.model.rowCount(), 0)
        release.set()
        self.pool.waitForDone(3000)
        for _ in range(5):
            self.application.processEvents()
        self.assertEqual(self.widget.model.rowCount(), 0)
        self.assertEqual(self.widget.status_label.text(), "Ready to search")

    def test_copy_double_click_navigation_focus_and_clear(self) -> None:
        self.widget.set_service(_service())
        self.widget.query_edit.setText("Hello")
        self.widget.start_search()
        self._wait()

        index = self.widget.proxy_model.index(0, 4)
        self.widget.table.setCurrentIndex(index)
        self.widget.table_actions.copy_column_value(0)
        self.assertEqual(QApplication.clipboard().text(), "0x00000220")

        navigations: list[tuple[int, int]] = []
        self.widget.fileOffsetNavigationRequested.connect(
            lambda offset, length: navigations.append((offset, length))
        )
        self.widget.table.doubleClicked.emit(index)
        self.assertEqual(navigations, [(0x220, 5)])

        self.widget.show()
        self.widget.focus_search()
        self.application.processEvents()
        self.assertTrue(self.widget.query_edit.hasFocus())
        self.assertEqual(self.widget.query_edit.selectedText(), "Hello")

        self.widget.clear()
        self.assertEqual(self.widget.model.rowCount(), 0)
        self.assertFalse(self.widget.search_button.isEnabled())
        self.assertEqual(
            self.widget.status_label.text(),
            "Search service unavailable",
        )


if __name__ == "__main__":
    unittest.main()
