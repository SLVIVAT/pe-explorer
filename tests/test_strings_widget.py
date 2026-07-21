from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from gui.strings_widget import StringTableModel, StringsWidget
from pe.strings import ExtractedString, StringExtractor


def _items() -> tuple[ExtractedString, ...]:
    return (
        ExtractedString(
            offset=0x40,
            rva=0x1040,
            length=5,
            encoding="ASCII",
            value="Alpha",
            section=".rdata",
            byte_length=5,
        ),
        ExtractedString(
            offset=0x20,
            rva=0x1020,
            length=9,
            encoding="ASCII",
            value="literal[a",
            section=".text",
            byte_length=9,
        ),
        ExtractedString(
            offset=0x90,
            rva=None,
            length=4,
            encoding="UTF-16LE",
            value="Beta",
            section=None,
            byte_length=8,
        ),
    )


class StringsWidgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.widget = StringsWidget()
        self.addCleanup(self.widget.close)

    def test_model_exposes_display_sort_and_tooltip_roles(self) -> None:
        model = StringTableModel()
        model.set_strings(_items())

        self.assertEqual(model.rowCount(), 3)
        self.assertEqual(model.columnCount(), 5)
        self.assertEqual(
            [
                model.headerData(
                    column,
                    Qt.Orientation.Horizontal,
                    Qt.ItemDataRole.DisplayRole,
                )
                for column in range(5)
            ],
            ["Offset", "RVA", "Length", "Encoding", "Value"],
        )
        self.assertEqual(model.data(model.index(0, 0)), "0x00000040")
        self.assertEqual(model.data(model.index(0, 1)), "0x00001040")
        self.assertEqual(model.data(model.index(2, 1)), "")
        self.assertEqual(
            model.data(model.index(1, 2), Qt.ItemDataRole.UserRole),
            9,
        )
        self.assertIn(
            ".rdata",
            str(model.data(model.index(0, 4), Qt.ItemDataRole.ToolTipRole)),
        )

    def test_literal_filter_and_sort_use_underlying_typed_values(self) -> None:
        self.widget.set_strings(_items())
        self.assertEqual(self.widget.proxy_model.rowCount(), 3)

        # An unmatched '[' would be invalid as a regular expression; the
        # literal proxy must treat it as ordinary text.
        self.widget.filter_edit.setText("AL[")
        self.assertEqual(self.widget.proxy_model.rowCount(), 1)
        source = self.widget.proxy_model.mapToSource(
            self.widget.proxy_model.index(0, 4)
        )
        self.assertEqual(self.widget.model.string(source.row()).value, "literal[a")
        self.assertIn("1 of 3", self.widget.status_label.text())

        self.widget.filter_edit.clear()
        self.widget.proxy_model.sort(2, Qt.SortOrder.DescendingOrder)
        source = self.widget.proxy_model.mapToSource(
            self.widget.proxy_model.index(0, 2)
        )
        self.assertEqual(self.widget.model.string(source.row()).length, 9)

    def test_set_service_copy_and_clear_preserve_expected_behavior(self) -> None:
        data = b"\x00Alpha.exe\x00" + "World".encode("utf-16le") + b"\x00\x00"
        self.widget.set_service(StringExtractor(data, minimum_length=5))
        self.assertEqual(self.widget.model.rowCount(), 2)
        self.assertIn("2 extracted", self.widget.status_label.text())

        value_index = self.widget.proxy_model.index(0, 4)
        self.widget.table.setCurrentIndex(value_index)
        self.widget.table_actions.copy_value()
        self.assertEqual(QApplication.clipboard().text(), "Alpha.exe")
        self.widget.table_actions.copy_column_value(0)
        self.assertEqual(QApplication.clipboard().text(), "0x00000001")

        self.widget.set_service(_items())
        self.assertEqual(self.widget.model.rowCount(), 3)
        self.assertIn("3 extracted", self.widget.status_label.text())

        self.widget.clear()
        self.assertEqual(self.widget.model.rowCount(), 0)
        self.assertEqual(self.widget.filter_edit.text(), "")
        self.assertEqual(self.widget.status_label.text(), "No strings loaded")

    def test_selection_and_double_click_emit_file_navigation(self) -> None:
        self.widget.set_strings(_items())
        navigations: list[tuple[int, int]] = []
        self.widget.fileOffsetNavigationRequested.connect(
            lambda offset, length: navigations.append((offset, length))
        )

        index = self.widget.proxy_model.index(0, 4)
        source = self.widget.proxy_model.mapToSource(index)
        expected = self.widget.model.string(source.row())
        assert expected is not None
        self.widget.table.setCurrentIndex(index)
        self.application.processEvents()
        self.assertIn((expected.offset, expected.byte_length), navigations)

        navigations.clear()
        self.widget.table.doubleClicked.emit(index)
        self.assertEqual(
            navigations,
            [(expected.offset, expected.byte_length)],
        )

    def test_focus_search_focuses_and_selects_filter_text(self) -> None:
        self.widget.show()
        self.widget.filter_edit.setText("Alpha")
        self.widget.focus_search()
        self.application.processEvents()
        self.assertTrue(self.widget.filter_edit.hasFocus())
        self.assertEqual(self.widget.filter_edit.selectedText(), "Alpha")

    def test_truncated_extraction_limit_is_explained(self) -> None:
        self.widget.set_strings(_items(), truncated=True, limit=3)

        self.assertIn("extraction limit of 3 reached", self.widget.status_label.text())
        self.assertIn("Global Search", self.widget.status_label.text())


if __name__ == "__main__":
    unittest.main()
