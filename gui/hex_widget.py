"""Virtualized hexadecimal file viewer with PE-aware address navigation."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import TypeAlias

from PySide6.QtCore import (
    QAbstractTableModel,
    QItemSelection,
    QItemSelectionModel,
    QModelIndex,
    Qt,
    Signal,
)
from PySide6.QtGui import QAction, QColor, QFontDatabase, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from pe.addressing import AddressingService
from pe.errors import PEFormatError
from pe.models import OptionalHeader, SectionHeader


ByteSource: TypeAlias = bytes | bytearray | memoryview | Sequence[int]

BYTES_PER_ROW = 16
OFFSET_COLUMN = 0
FIRST_BYTE_COLUMN = 1
LAST_BYTE_COLUMN = BYTES_PER_ROW
ASCII_COLUMN = BYTES_PER_ROW + 1
BYTE_OFFSET_ROLE = int(Qt.ItemDataRole.UserRole) + 1
BYTE_VALUE_ROLE = int(Qt.ItemDataRole.UserRole) + 2


class HexTableModel(QAbstractTableModel):
    """On-demand table model over a byte source.

    The model stores one source reference and a pair of highlight offsets.  It
    never materializes rows, formatted cells, or per-byte Qt objects, so model
    reset cost is independent of the file size.
    """

    _HIGHLIGHT_COLOR = QColor("#5a4b20")

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._source: ByteSource = b""
        self._byte_count = 0
        self._offset_digits = 8
        self._highlight_start: int | None = None
        self._highlight_end = 0

    @property
    def byte_count(self) -> int:
        """Number of physical bytes represented by the model."""

        return self._byte_count

    @property
    def data_source(self) -> ByteSource:
        """Return the retained source, primarily for zero-copy integrations."""

        return self._source

    @property
    def highlight_range(self) -> tuple[int, int] | None:
        """Return the highlighted half-open file-offset range."""

        if self._highlight_start is None:
            return None
        return self._highlight_start, self._highlight_end

    def set_bytes(self, source: ByteSource) -> None:
        """Replace the source without expanding it into rows or cells."""

        byte_count = len(source)
        if byte_count < 0:
            raise ValueError("byte source length cannot be negative")

        self.beginResetModel()
        self._source = source
        self._byte_count = byte_count
        highest_offset = max(0, byte_count - 1)
        self._offset_digits = max(8, (highest_offset.bit_length() + 3) // 4)
        self._highlight_start = None
        self._highlight_end = 0
        self.endResetModel()

    def clear(self) -> None:
        """Reset the model to an empty byte source."""

        self.set_bytes(b"")

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return (self._byte_count + BYTES_PER_ROW - 1) // BYTES_PER_ROW

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else ASCII_COLUMN + 1

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object | None:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Vertical:
            return None
        if section == OFFSET_COLUMN:
            return "Offset"
        if FIRST_BYTE_COLUMN <= section <= LAST_BYTE_COLUMN:
            return f"{section - FIRST_BYTE_COLUMN:02X}"
        if section == ASCII_COLUMN:
            return "ASCII"
        return None

    def data(
        self,
        index: QModelIndex,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object | None:
        if not index.isValid() or not 0 <= index.row() < self.rowCount():
            return None

        row_offset = index.row() * BYTES_PER_ROW
        column = index.column()
        byte_offset = self.offset_for_index(index)

        if role == Qt.ItemDataRole.DisplayRole:
            if column == OFFSET_COLUMN:
                return f"{row_offset:0{self._offset_digits}X}"
            if FIRST_BYTE_COLUMN <= column <= LAST_BYTE_COLUMN:
                if byte_offset is None:
                    return ""
                return f"{self.byte_at(byte_offset):02X}"
            if column == ASCII_COLUMN:
                end = min(row_offset + BYTES_PER_ROW, self._byte_count)
                return "".join(
                    chr(value) if 0x20 <= value <= 0x7E else "."
                    for value in (
                        self.byte_at(offset)
                        for offset in range(row_offset, end)
                    )
                )

        if role == BYTE_OFFSET_ROLE:
            return byte_offset
        if role == BYTE_VALUE_ROLE and byte_offset is not None:
            return self.byte_at(byte_offset)
        if role == Qt.ItemDataRole.TextAlignmentRole:
            if column == ASCII_COLUMN:
                return Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft
            return Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignCenter
        if (
            role == Qt.ItemDataRole.BackgroundRole
            and byte_offset is not None
            and self._highlight_start is not None
            and self._highlight_start <= byte_offset < self._highlight_end
        ):
            return self._HIGHLIGHT_COLOR
        if role == Qt.ItemDataRole.ToolTipRole and byte_offset is not None:
            return (
                f"File offset 0x{byte_offset:0{self._offset_digits}X}  |  "
                f"Byte 0x{self.byte_at(byte_offset):02X}"
            )
        return None

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        flags = Qt.ItemFlag.ItemIsEnabled
        if self.offset_for_index(index) is not None:
            flags |= Qt.ItemFlag.ItemIsSelectable
        return flags

    def byte_at(self, offset: int) -> int:
        """Return one byte without constructing a row object."""

        if not 0 <= offset < self._byte_count:
            raise IndexError(offset)
        value = self._source[offset]
        if not isinstance(value, int) or not 0 <= value <= 0xFF:
            raise ValueError(f"Byte source returned invalid value {value!r}.")
        return value

    def bytes_for_range(self, start: int, end: int) -> bytes:
        """Copy a validated half-open range for clipboard export."""

        if not 0 <= start <= end <= self._byte_count:
            raise IndexError((start, end))
        raw = self._source[start:end]
        if isinstance(raw, int):
            return bytes((raw,))
        return bytes(raw)

    def offset_for_index(self, index: QModelIndex) -> int | None:
        """Map a byte-cell index to its physical file offset."""

        if (
            not index.isValid()
            or not FIRST_BYTE_COLUMN <= index.column() <= LAST_BYTE_COLUMN
        ):
            return None
        offset = (
            index.row() * BYTES_PER_ROW
            + index.column()
            - FIRST_BYTE_COLUMN
        )
        return offset if offset < self._byte_count else None

    def index_for_offset(self, offset: int) -> QModelIndex:
        """Return the byte-cell index for a valid file offset."""

        if not 0 <= offset < self._byte_count:
            return QModelIndex()
        row, column_offset = divmod(offset, BYTES_PER_ROW)
        return self.index(row, FIRST_BYTE_COLUMN + column_offset)

    def set_highlight(self, start: int | None, length: int = 0) -> None:
        """Set a highlighted byte range with O(1) retained state."""

        if start is None:
            new_range: tuple[int, int] | None = None
        else:
            if length <= 0 or not 0 <= start < self._byte_count:
                raise ValueError("highlight range must contain physical bytes")
            end = start + length
            if end > self._byte_count:
                raise ValueError("highlight range extends beyond the byte source")
            new_range = (start, end)

        old_range = self.highlight_range
        if old_range == new_range:
            return
        if new_range is None:
            self._highlight_start = None
            self._highlight_end = 0
        else:
            self._highlight_start, self._highlight_end = new_range

        for changed_range in (old_range, new_range):
            if changed_range is not None:
                self._emit_highlight_changed(*changed_range)

    def _emit_highlight_changed(self, start: int, end: int) -> None:
        if start >= end or self.rowCount() == 0:
            return
        top = self.index(start // BYTES_PER_ROW, FIRST_BYTE_COLUMN)
        bottom = self.index((end - 1) // BYTES_PER_ROW, LAST_BYTE_COLUMN)
        self.dataChanged.emit(
            top,
            bottom,
            [Qt.ItemDataRole.BackgroundRole],
        )


class HexWidget(QWidget):
    """Virtualized hex viewer with file-offset, RVA, and VA navigation."""

    navigation_changed = Signal(object, object)
    error_occurred = Signal(str)

    _MAX_SELECTION_ROWS = 4096
    _MAX_COPY_BYTES = 16 * 1024 * 1024

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._addressing: AddressingService | None = None

        self.address_kind = QComboBox()
        self.address_kind.addItem("File offset", "offset")
        self.address_kind.addItem("RVA", "rva")
        self.address_kind.addItem("VA", "va")
        self.address_input = QLineEdit()
        self.address_input.setPlaceholderText("Hex address, for example 0x401000")
        self.address_input.setClearButtonEnabled(True)
        self.jump_button = QPushButton("Jump")
        self.jump_button.setDefault(False)

        self.model = HexTableModel(self)
        self.table = QTableView()
        self.table.setModel(self.model)
        self._configure_table()

        self.status_label = QLabel("No image loaded")
        self.status_label.setObjectName("summaryBanner")
        self.status_label.setWordWrap(True)

        self.copy_action = QAction("Copy selected bytes", self)
        self.copy_action.setShortcut(QKeySequence.StandardKey.Copy)
        self.copy_action.setShortcutContext(
            Qt.ShortcutContext.WidgetWithChildrenShortcut
        )
        self.copy_action.setEnabled(False)
        self.copy_action.triggered.connect(self.copy_selection)
        self.addAction(self.copy_action)
        self.table.addAction(self.copy_action)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.ActionsContextMenu)

        controls = QHBoxLayout()
        controls.setContentsMargins(0, 0, 0, 0)
        controls.setSpacing(8)
        controls.addWidget(QLabel("Address:"))
        controls.addWidget(self.address_kind)
        controls.addWidget(self.address_input, 1)
        controls.addWidget(self.jump_button)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addLayout(controls)
        layout.addWidget(self.table, 1)
        layout.addWidget(self.status_label)

        self.jump_button.clicked.connect(self._jump_from_controls)
        self.address_input.returnPressed.connect(self._jump_from_controls)
        self.table.selectionModel().selectionChanged.connect(
            self._selection_changed
        )
        self._set_navigation_enabled(False)

    def set_image(
        self,
        data: ByteSource,
        optional_header: OptionalHeader,
        sections: Sequence[SectionHeader],
    ) -> bool:
        """Load a PE byte source and its parsed addressing metadata."""

        try:
            addressing = AddressingService(
                optional_header,
                sections,
                file_size=len(data),
            )
        except (PEFormatError, ValueError) as error:
            self.clear()
            self._report_error(str(error))
            return False

        self._addressing = addressing
        self.model.set_bytes(data)
        self.address_input.clear()
        self.address_kind.setCurrentIndex(0)
        self._set_navigation_enabled(bool(len(data)))
        self.copy_action.setEnabled(False)
        self.status_label.setText(f"{len(data):,} bytes loaded")
        return True

    def clear(self) -> None:
        """Release the image and reset controls, selection, and highlights."""

        self._addressing = None
        self.table.clearSelection()
        self.model.clear()
        self.address_input.clear()
        self.address_kind.setCurrentIndex(0)
        self.status_label.setText("No image loaded")
        self.copy_action.setEnabled(False)
        self._set_navigation_enabled(False)

    def navigate_to_offset(self, offset: int, length: int = 1) -> bool:
        """Select and reveal a physical file range."""

        if not self._validate_physical_range(offset, length):
            return False

        self._apply_navigation(offset, length)
        self.address_kind.setCurrentIndex(
            self.address_kind.findData("offset")
        )
        self.address_input.setText(f"0x{offset:X}")
        return True

    def jump_to_rva(self, rva: int, length: int = 1) -> bool:
        """Resolve a file-backed RVA, then select its physical bytes."""

        if self._addressing is None:
            self._report_error("No PE image is loaded.")
            return False
        try:
            offset = self._addressing.rva_to_file_offset(rva, length)
        except (PEFormatError, ValueError) as error:
            self._report_error(str(error))
            return False

        self._apply_navigation(offset, length)
        self.address_kind.setCurrentIndex(self.address_kind.findData("rva"))
        self.address_input.setText(f"0x{rva:X}")
        return True

    def jump_to_va(self, va: int, length: int = 1) -> bool:
        """Resolve a PE32/PE32+ VA, then select its physical bytes."""

        if self._addressing is None:
            self._report_error("No PE image is loaded.")
            return False
        try:
            rva = self._addressing.va_to_rva(va)
            offset = self._addressing.rva_to_file_offset(rva, length)
        except (PEFormatError, ValueError) as error:
            self._report_error(str(error))
            return False

        self._apply_navigation(offset, length)
        self.address_kind.setCurrentIndex(self.address_kind.findData("va"))
        self.address_input.setText(f"0x{va:X}")
        return True

    def copy_selection(self) -> str:
        """Copy selected bytes as an uppercase, space-separated hex string."""

        highlight = self.model.highlight_range
        if highlight is not None:
            start, end = highlight
            byte_count = end - start
            if byte_count > self._MAX_COPY_BYTES:
                self._report_error(
                    f"Selection is too large to copy ({byte_count:,} bytes; "
                    f"maximum {self._MAX_COPY_BYTES:,})."
                )
                return ""
            copied = self.model.bytes_for_range(start, end)
        else:
            first_offset, byte_count, _ = self._selection_summary()
            if first_offset is None or byte_count == 0:
                self._report_error("No bytes are selected.")
                return ""
            if byte_count > self._MAX_COPY_BYTES:
                self._report_error(
                    f"Selection is too large to copy ({byte_count:,} bytes; "
                    f"maximum {self._MAX_COPY_BYTES:,})."
                )
                return ""
            buffer = bytearray()
            for start, end in self._selection_intervals():
                buffer.extend(self.model.bytes_for_range(start, end))
            copied = bytes(buffer)

        text = copied.hex(" ").upper()
        QApplication.clipboard().setText(text)
        return text

    def _configure_table(self) -> None:
        self.table.setAlternatingRowColors(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectItems
        )
        self.table.setSelectionMode(
            QAbstractItemView.SelectionMode.ExtendedSelection
        )
        self.table.setSortingEnabled(False)
        self.table.setWordWrap(False)
        self.table.setShowGrid(False)
        self.table.setFont(
            QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        )
        self.table.setVerticalScrollMode(
            QAbstractItemView.ScrollMode.ScrollPerItem
        )
        self.table.setHorizontalScrollMode(
            QAbstractItemView.ScrollMode.ScrollPerPixel
        )
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Fixed
        )
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Fixed
        )
        self.table.horizontalHeader().setSectionResizeMode(
            ASCII_COLUMN,
            QHeaderView.ResizeMode.Stretch,
        )

        metrics = self.table.fontMetrics()
        byte_width = max(30, metrics.horizontalAdvance("FF") + 14)
        offset_width = max(105, metrics.horizontalAdvance("0000000000000000") + 18)
        self.table.setColumnWidth(OFFSET_COLUMN, offset_width)
        for column in range(FIRST_BYTE_COLUMN, LAST_BYTE_COLUMN + 1):
            self.table.setColumnWidth(column, byte_width)
        self.table.setColumnWidth(
            ASCII_COLUMN,
            metrics.horizontalAdvance("................") + 22,
        )

    def _validate_physical_range(self, offset: int, length: int) -> bool:
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            self._report_error(f"Invalid file offset {offset!r}.")
            return False
        if not isinstance(length, int) or isinstance(length, bool) or length <= 0:
            self._report_error("Navigation length must be a positive integer.")
            return False
        if self.model.byte_count == 0:
            self._report_error("No PE image bytes are loaded.")
            return False
        if offset >= self.model.byte_count:
            self._report_error(
                f"File offset 0x{offset:X} is outside file size "
                f"0x{self.model.byte_count:X}."
            )
            return False
        if length > self.model.byte_count - offset:
            self._report_error(
                f"File range 0x{offset:X}+0x{length:X} exceeds file size "
                f"0x{self.model.byte_count:X}."
            )
            return False
        return True

    def _apply_navigation(self, offset: int, length: int) -> None:
        self.model.set_highlight(offset, length)
        first_index = self.model.index_for_offset(offset)
        self._select_byte_range(offset, length)
        self.table.scrollTo(
            first_index,
            QAbstractItemView.ScrollHint.PositionAtCenter,
        )
        self.copy_action.setEnabled(True)
        self.status_label.setText(self._navigation_status(offset, length))
        self.navigation_changed.emit(offset, length)

    def _select_byte_range(self, offset: int, length: int) -> None:
        selection_model = self.table.selectionModel()
        if selection_model is None:
            return

        old_blocked = selection_model.blockSignals(True)
        try:
            start_row = offset // BYTES_PER_ROW
            end_offset = offset + length - 1
            end_row = end_offset // BYTES_PER_ROW
            if end_row - start_row + 1 > self._MAX_SELECTION_ROWS:
                selection_model.setCurrentIndex(
                    self.model.index_for_offset(offset),
                    QItemSelectionModel.SelectionFlag.ClearAndSelect,
                )
                return

            selection = QItemSelection()
            for row in range(start_row, end_row + 1):
                row_start = max(offset, row * BYTES_PER_ROW)
                row_end = min(end_offset, row * BYTES_PER_ROW + 15)
                selection.select(
                    self.model.index_for_offset(row_start),
                    self.model.index_for_offset(row_end),
                )
            selection_model.select(
                selection,
                QItemSelectionModel.SelectionFlag.ClearAndSelect,
            )
            selection_model.setCurrentIndex(
                self.model.index_for_offset(offset),
                QItemSelectionModel.SelectionFlag.NoUpdate,
            )
        finally:
            selection_model.blockSignals(old_blocked)

    def _selection_changed(self, *_: object) -> None:
        first_offset, byte_count, contiguous = self._selection_summary()
        self.copy_action.setEnabled(first_offset is not None)
        if first_offset is None or byte_count == 0:
            self.model.set_highlight(None)
            return

        if contiguous:
            self.model.set_highlight(first_offset, byte_count)
        else:
            self.model.set_highlight(None)
        self.navigation_changed.emit(first_offset, byte_count)

    def _selection_summary(self) -> tuple[int | None, int, bool]:
        """Summarize selected bytes without materializing model indexes."""

        selection_model = self.table.selectionModel()
        if selection_model is None:
            return None, 0, False

        first_offset: int | None = None
        byte_count = 0
        compact_intervals: list[tuple[int, int]] = []
        can_be_contiguous = True
        last_row = self.model.rowCount() - 1
        last_column = (
            FIRST_BYTE_COLUMN
            + (self.model.byte_count - 1) % BYTES_PER_ROW
            if self.model.byte_count
            else FIRST_BYTE_COLUMN - 1
        )

        for selected_range in selection_model.selection():
            top = max(0, selected_range.top())
            bottom = min(last_row, selected_range.bottom())
            left = max(FIRST_BYTE_COLUMN, selected_range.left())
            right = min(LAST_BYTE_COLUMN, selected_range.right())
            if top > bottom or left > right:
                continue

            width = right - left + 1
            rows = bottom - top + 1
            range_count = rows * width
            if bottom == last_row and right > last_column:
                range_count -= right - max(left - 1, last_column)
            if range_count <= 0:
                continue

            range_first = top * BYTES_PER_ROW + left - FIRST_BYTE_COLUMN
            first_offset = (
                range_first
                if first_offset is None
                else min(first_offset, range_first)
            )
            byte_count += range_count

            full_rows = left == FIRST_BYTE_COLUMN and right == LAST_BYTE_COLUMN
            if rows == 1 or full_rows:
                range_end = min(
                    self.model.byte_count,
                    bottom * BYTES_PER_ROW + right - FIRST_BYTE_COLUMN + 1,
                )
                compact_intervals.append((range_first, range_end))
            else:
                can_be_contiguous = False

        if first_offset is None or not can_be_contiguous:
            return first_offset, byte_count, False

        compact_intervals.sort()
        expected = compact_intervals[0][0] if compact_intervals else 0
        unique_count = 0
        for start, end in compact_intervals:
            if start != expected:
                return first_offset, byte_count, False
            unique_count += end - start
            expected = end
        return first_offset, byte_count, unique_count == byte_count

    def _selection_intervals(self) -> Iterator[tuple[int, int]]:
        """Yield selected byte runs using bounded Qt selection ranges."""

        selection_model = self.table.selectionModel()
        if selection_model is None:
            return
        ranges = sorted(
            selection_model.selection(),
            key=lambda item: (item.top(), item.left()),
        )
        last_row = self.model.rowCount() - 1
        for selected_range in ranges:
            top = max(0, selected_range.top())
            bottom = min(last_row, selected_range.bottom())
            left = max(FIRST_BYTE_COLUMN, selected_range.left())
            right = min(LAST_BYTE_COLUMN, selected_range.right())
            if top > bottom or left > right:
                continue
            if left == FIRST_BYTE_COLUMN and right == LAST_BYTE_COLUMN:
                start = top * BYTES_PER_ROW
                end = min(self.model.byte_count, (bottom + 1) * BYTES_PER_ROW)
                yield start, end
                continue
            for row in range(top, bottom + 1):
                start = row * BYTES_PER_ROW + left - FIRST_BYTE_COLUMN
                end = min(
                    self.model.byte_count,
                    row * BYTES_PER_ROW + right - FIRST_BYTE_COLUMN + 1,
                )
                if start < end:
                    yield start, end

    def _navigation_status(self, offset: int, length: int) -> str:
        parts = [
            f"Offset 0x{offset:X}",
            f"{length:,} byte{'s' if length != 1 else ''}",
        ]
        if self._addressing is not None:
            try:
                mapping = self._addressing.resolve_file_offset(offset)
            except PEFormatError:
                parts.append("not mapped to an RVA")
            else:
                parts.extend(
                    (
                        f"RVA 0x{mapping.rva:08X}",
                        f"VA 0x{mapping.va:X}",
                    )
                )
                if mapping.section_name:
                    parts.append(mapping.section_name)
        return "  |  ".join(parts)

    def _jump_from_controls(self) -> None:
        try:
            address = self._parse_address(self.address_input.text())
        except ValueError as error:
            self._report_error(str(error))
            return

        address_kind = self.address_kind.currentData()
        if address_kind == "rva":
            self.jump_to_rva(address)
        elif address_kind == "va":
            self.jump_to_va(address)
        else:
            self.navigate_to_offset(address)

    @staticmethod
    def _parse_address(text: str) -> int:
        normalized = text.strip().replace("_", "")
        if not normalized:
            raise ValueError("Enter a hexadecimal address.")
        if normalized.lower().startswith("0x"):
            normalized = normalized[2:]
        if not normalized:
            raise ValueError("Enter a hexadecimal address.")
        try:
            address = int(normalized, 16)
        except ValueError as error:
            raise ValueError(f"Invalid hexadecimal address {text!r}.") from error
        if address < 0:
            raise ValueError(f"Invalid hexadecimal address {text!r}.")
        return address

    def _set_navigation_enabled(self, enabled: bool) -> None:
        self.address_kind.setEnabled(enabled)
        self.address_input.setEnabled(enabled)
        self.jump_button.setEnabled(enabled)

    def _report_error(self, message: str) -> None:
        self.status_label.setText(f"Error: {message}")
        self.error_occurred.emit(message)


# Descriptive alias for callers that prefer the longer component name.
HexViewerWidget = HexWidget


__all__ = [
    "ASCII_COLUMN",
    "BYTE_OFFSET_ROLE",
    "BYTE_VALUE_ROLE",
    "BYTES_PER_ROW",
    "ByteSource",
    "FIRST_BYTE_COLUMN",
    "HexTableModel",
    "HexViewerWidget",
    "HexWidget",
    "LAST_BYTE_COLUMN",
    "OFFSET_COLUMN",
]
