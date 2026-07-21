from __future__ import annotations

from collections.abc import Iterator, Sequence
import os
import time
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QApplication, QWidget

from gui.hex_widget import (
    ASCII_COLUMN,
    BYTE_OFFSET_ROLE,
    BYTE_VALUE_ROLE,
    BYTES_PER_ROW,
    FIRST_BYTE_COLUMN,
    HexTableModel,
    HexWidget,
    OFFSET_COLUMN,
)
from tests.test_addressing import _optional_header, _section


class _SparseBytes(Sequence[int]):
    """Constant-memory logical byte source used to exercise huge models."""

    def __init__(self, size: int) -> None:
        self._size = size

    def __len__(self) -> int:
        return self._size

    def __getitem__(self, index: int | slice) -> int | bytes:
        if isinstance(index, slice):
            start, stop, step = index.indices(self._size)
            return bytes(value & 0xFF for value in range(start, stop, step))
        if index < 0:
            index += self._size
        if not 0 <= index < self._size:
            raise IndexError(index)
        return index & 0xFF

    def __iter__(self) -> Iterator[int]:
        return (index & 0xFF for index in range(self._size))


class HexTableModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def test_formats_rows_ascii_roles_flags_and_highlights_on_demand(
        self,
    ) -> None:
        source = bytes(range(20)) + b"ABC\x00"
        model = HexTableModel()
        model.set_bytes(source)

        self.assertIs(model.data_source, source)
        self.assertEqual(model.byte_count, len(source))
        self.assertEqual(model.rowCount(), 2)
        self.assertEqual(model.columnCount(), 18)
        self.assertEqual(
            model.headerData(
                OFFSET_COLUMN,
                Qt.Orientation.Horizontal,
                Qt.ItemDataRole.DisplayRole,
            ),
            "Offset",
        )
        self.assertEqual(
            model.headerData(
                FIRST_BYTE_COLUMN + 15,
                Qt.Orientation.Horizontal,
                Qt.ItemDataRole.DisplayRole,
            ),
            "0F",
        )
        self.assertEqual(
            model.data(model.index(0, OFFSET_COLUMN)),
            "00000000",
        )
        self.assertEqual(
            model.data(model.index(1, OFFSET_COLUMN)),
            "00000010",
        )
        self.assertEqual(
            model.data(model.index(0, FIRST_BYTE_COLUMN + 10)),
            "0A",
        )
        self.assertEqual(
            model.data(model.index(0, ASCII_COLUMN)),
            "." * 16,
        )
        self.assertEqual(
            model.data(model.index(1, ASCII_COLUMN)),
            "....ABC.",
        )

        byte_index = model.index(1, FIRST_BYTE_COLUMN + 2)
        self.assertEqual(model.data(byte_index, BYTE_OFFSET_ROLE), 0x12)
        self.assertEqual(model.data(byte_index, BYTE_VALUE_ROLE), 0x12)
        self.assertTrue(
            model.flags(byte_index) & Qt.ItemFlag.ItemIsSelectable
        )
        self.assertFalse(
            model.flags(model.index(1, OFFSET_COLUMN))
            & Qt.ItemFlag.ItemIsSelectable
        )
        self.assertFalse(
            model.flags(model.index(1, FIRST_BYTE_COLUMN + 15))
            & Qt.ItemFlag.ItemIsSelectable
        )

        model.set_highlight(0x11, 3)
        self.assertEqual(model.highlight_range, (0x11, 0x14))
        self.assertIsInstance(
            model.data(
                model.index(1, FIRST_BYTE_COLUMN + 1),
                Qt.ItemDataRole.BackgroundRole,
            ),
            QColor,
        )
        self.assertIsNone(
            model.data(
                model.index(1, FIRST_BYTE_COLUMN + 4),
                Qt.ItemDataRole.BackgroundRole,
            )
        )
        model.set_highlight(None)
        self.assertIsNone(model.highlight_range)


class HexWidgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self._widgets: list[HexWidget] = []

    def tearDown(self) -> None:
        for widget in self._widgets:
            widget.close()
        self.application.processEvents()

    def _widget(
        self,
        data: Sequence[int] = bytes(range(256)) * 6,
        *,
        pe32_plus: bool = False,
        virtual_size: int = 0x200,
        raw_size: int = 0x200,
    ) -> HexWidget:
        widget = HexWidget()
        self._widgets.append(widget)
        loaded = widget.set_image(
            data,
            _optional_header(pe32_plus=pe32_plus),
            (
                _section(
                    virtual_size=virtual_size,
                    raw_size=raw_size,
                ),
            ),
        )
        self.assertTrue(loaded)
        return widget

    def test_navigates_selects_highlights_copies_and_clears(self) -> None:
        data = bytes(range(256)) * 6
        widget = self._widget(data)
        navigation_events: list[tuple[int, int]] = []
        errors: list[str] = []
        widget.navigation_changed.connect(
            lambda offset, length: navigation_events.append((offset, length))
        )
        widget.error_occurred.connect(errors.append)

        self.assertTrue(widget.navigate_to_offset(0x210, 20))
        self.assertEqual(navigation_events, [(0x210, 20)])
        self.assertEqual(widget.model.highlight_range, (0x210, 0x224))
        selected = widget.table.selectionModel().selectedIndexes()
        self.assertEqual(len(selected), 20)
        self.assertEqual(
            widget.model.offset_for_index(widget.table.currentIndex()),
            0x210,
        )
        expected = " ".join(f"{value:02X}" for value in range(0x10, 0x24))
        self.assertEqual(widget.copy_selection(), expected)
        self.assertEqual(QApplication.clipboard().text(), expected)
        self.assertTrue(widget.copy_action.isEnabled())
        self.assertIn("RVA 0x00001010", widget.status_label.text())

        for offset in (0x210, 0x21F, 0x223):
            index = widget.model.index_for_offset(offset)
            self.assertIsNone(widget.table.indexWidget(index))

        self.assertFalse(widget.navigate_to_offset(len(data), 1))
        self.assertTrue(errors)
        self.assertIn("outside file size", errors[-1])

        widget.clear()
        self.assertEqual(widget.model.byte_count, 0)
        self.assertEqual(widget.model.rowCount(), 0)
        self.assertIsNone(widget.model.highlight_range)
        self.assertFalse(widget.jump_button.isEnabled())
        self.assertFalse(widget.copy_action.isEnabled())
        self.assertEqual(widget.status_label.text(), "No image loaded")

    def test_jumps_between_file_rva_and_pe32_or_pe32_plus_va(self) -> None:
        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus):
                widget = self._widget(pe32_plus=pe32_plus)
                events: list[tuple[int, int]] = []
                widget.navigation_changed.connect(
                    lambda offset, length: events.append((offset, length))
                )

                self.assertTrue(widget.jump_to_rva(0x1010, 4))
                self.assertEqual(events[-1], (0x210, 4))
                self.assertEqual(widget.address_kind.currentData(), "rva")
                self.assertEqual(widget.address_input.text(), "0x1010")

                image_base = 0x140000000 if pe32_plus else 0x400000
                va = image_base + 0x1020
                self.assertTrue(widget.jump_to_va(va, 2))
                self.assertEqual(events[-1], (0x220, 2))
                self.assertEqual(widget.address_kind.currentData(), "va")
                self.assertEqual(widget.address_input.text(), f"0x{va:X}")
                self.assertIn(f"VA 0x{va:X}", widget.status_label.text())

                self.assertTrue(widget.navigate_to_offset(0x500))
                self.assertIn("not mapped to an RVA", widget.status_label.text())

        virtual_only = self._widget(virtual_size=0x300, raw_size=0x100)
        errors: list[str] = []
        virtual_only.error_occurred.connect(errors.append)
        self.assertFalse(virtual_only.jump_to_rva(0x1150))
        self.assertIn("virtual-only", errors[-1])

    def test_jump_controls_parse_hex_and_emit_errors(self) -> None:
        widget = self._widget()
        events: list[tuple[int, int]] = []
        errors: list[str] = []
        widget.navigation_changed.connect(
            lambda offset, length: events.append((offset, length))
        )
        widget.error_occurred.connect(errors.append)

        widget.address_kind.setCurrentIndex(widget.address_kind.findData("rva"))
        widget.address_input.setText("1_010")
        widget.jump_button.click()
        self.assertEqual(events[-1], (0x210, 1))

        widget.address_input.setText("not-hex")
        widget.jump_button.click()
        self.assertTrue(errors)
        self.assertIn("Invalid hexadecimal address", errors[-1])

        widget.address_input.clear()
        widget.jump_button.click()
        self.assertIn("Enter a hexadecimal address", errors[-1])

    def test_gigabyte_logical_model_constructs_and_scrolls_in_constant_space(
        self,
    ) -> None:
        logical_size = 1 << 30
        source = _SparseBytes(logical_size)
        widget = HexWidget()
        self._widgets.append(widget)
        child_widgets_before = len(
            widget.table.findChildren(
                QWidget,
            )
        )

        started = time.perf_counter()
        loaded = widget.set_image(
            source,
            _optional_header(),
            (_section(),),
        )
        construction_seconds = time.perf_counter() - started

        self.assertTrue(loaded)
        self.assertLess(construction_seconds, 1.0)
        self.assertIs(widget.model.data_source, source)
        self.assertEqual(widget.model.byte_count, logical_size)
        self.assertEqual(
            widget.model.rowCount(),
            logical_size // BYTES_PER_ROW,
        )
        last_row = widget.model.rowCount() - 1
        self.assertEqual(
            widget.model.data(widget.model.index(last_row, OFFSET_COLUMN)),
            "3FFFFFF0",
        )
        self.assertEqual(
            widget.model.data(
                widget.model.index(last_row, FIRST_BYTE_COLUMN + 15)
            ),
            "FF",
        )

        started = time.perf_counter()
        self.assertTrue(widget.navigate_to_offset(logical_size - 1))
        self.application.processEvents()
        navigation_seconds = time.perf_counter() - started
        self.assertLess(navigation_seconds, 1.0)
        self.assertEqual(
            widget.model.highlight_range,
            (logical_size - 1, logical_size),
        )
        self.assertGreater(widget.table.verticalScrollBar().maximum(), 1_000_000)

        child_widgets_after = len(
            widget.table.findChildren(
                QWidget,
            )
        )
        self.assertLessEqual(child_widgets_after, child_widgets_before + 2)
        for offset in (0, logical_size // 2, logical_size - 1):
            self.assertIsNone(
                widget.table.indexWidget(widget.model.index_for_offset(offset))
            )

        errors: list[str] = []
        widget.error_occurred.connect(errors.append)
        started = time.perf_counter()
        widget.table.selectAll()
        self.application.processEvents()
        self.assertEqual(widget.copy_selection(), "")
        selection_seconds = time.perf_counter() - started
        self.assertLess(selection_seconds, 1.0)
        self.assertIn("too large to copy", errors[-1])


if __name__ == "__main__":
    unittest.main()
