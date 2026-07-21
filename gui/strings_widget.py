"""Efficient sortable and filterable presentation of extracted strings."""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
    Signal,
)
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLabel,
    QLineEdit,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from gui.table_actions import TableActionController, install_table_actions
from pe.strings import ExtractedString, StringExtractor
from utils.file_utils import format_hex


STRING_HEADERS: tuple[str, ...] = (
    "Offset",
    "RVA",
    "Length",
    "Encoding",
    "Value",
)


class StringTableModel(QAbstractTableModel):
    """Read-only table model retaining typed string records for navigation."""

    def __init__(self) -> None:
        super().__init__()
        self._strings: tuple[ExtractedString, ...] = ()

    def set_strings(self, strings: Sequence[ExtractedString]) -> None:
        self.beginResetModel()
        self._strings = tuple(strings)
        self.endResetModel()

    def string(self, row: int) -> ExtractedString | None:
        if 0 <= row < len(self._strings):
            return self._strings[row]
        return None

    def sort(
        self,
        column: int,
        order: Qt.SortOrder = Qt.SortOrder.AscendingOrder,
    ) -> None:
        """Sort records in Python to avoid slow per-cell proxy comparisons."""

        key_functions = (
            lambda item: item.offset,
            lambda item: (item.rva is None, item.rva or 0),
            lambda item: item.length,
            lambda item: item.encoding,
            lambda item: item.value.casefold(),
        )
        if not 0 <= column < len(key_functions):
            return
        self.beginResetModel()
        self._strings = tuple(
            sorted(
                self._strings,
                key=key_functions[column],
                reverse=order == Qt.SortOrder.DescendingOrder,
            )
        )
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._strings)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(STRING_HEADERS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object | None:
        if (
            orientation == Qt.Orientation.Horizontal
            and role == Qt.ItemDataRole.DisplayRole
            and 0 <= section < len(STRING_HEADERS)
        ):
            return STRING_HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = 0) -> object | None:
        item = self.string(index.row())
        if item is None or not index.isValid():
            return None

        display_values = (
            format_hex(item.offset),
            "" if item.rva is None else format_hex(item.rva),
            str(item.length),
            item.encoding,
            item.value,
        )
        sort_values: tuple[object, ...] = (
            item.offset,
            -1 if item.rva is None else item.rva,
            item.length,
            item.encoding.casefold(),
            item.value.casefold(),
        )
        if role == Qt.ItemDataRole.DisplayRole:
            return display_values[index.column()]
        if role == Qt.ItemDataRole.UserRole:
            return sort_values[index.column()]
        if role == Qt.ItemDataRole.TextAlignmentRole:
            horizontal = (
                Qt.AlignmentFlag.AlignLeft
                if index.column() in {3, 4}
                else Qt.AlignmentFlag.AlignRight
            )
            return Qt.AlignmentFlag.AlignVCenter | horizontal
        if role == Qt.ItemDataRole.ToolTipRole:
            location = (
                f"Section: {item.section}"
                if item.section is not None
                else "No mapped PE section"
            )
            return (
                f"{location}\nByte length: {item.byte_length}\n"
                f"{item.value}"
            )
        if role == Qt.ItemDataRole.ForegroundRole and item.rva is None:
            return QColor("#aab2c0")
        return None


class LiteralStringFilterProxyModel(QSortFilterProxyModel):
    """Case-insensitive literal substring filter over string values."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._literal = ""
        self.setSortRole(Qt.ItemDataRole.UserRole)
        self.setDynamicSortFilter(True)

    @property
    def literal_filter(self) -> str:
        return self._literal

    def set_literal_filter(self, value: str) -> None:
        normalized = value.casefold()
        if normalized == self._literal:
            return
        self.beginFilterChange()
        self._literal = normalized
        self.endFilterChange(QSortFilterProxyModel.Direction.Rows)

    def filterAcceptsRow(
        self,
        source_row: int,
        source_parent: QModelIndex,
    ) -> bool:
        if not self._literal:
            return True
        model = self.sourceModel()
        if not isinstance(model, StringTableModel):
            return False
        item = model.string(source_row)
        return item is not None and self._literal in item.value.casefold()

    def sort(
        self,
        column: int,
        order: Qt.SortOrder = Qt.SortOrder.AscendingOrder,
    ) -> None:
        """Delegate typed sorting to the source model's optimized path."""

        model = self.sourceModel()
        if isinstance(model, StringTableModel):
            model.sort(column, order)


class StringsWidget(QWidget):
    """Professional string browser with literal filtering and navigation."""

    fileOffsetNavigationRequested = Signal(int, int)

    def __init__(self) -> None:
        super().__init__()
        self._service: StringExtractor | Sequence[ExtractedString] | None = None
        self._truncated = False
        self._limit: int | None = None

        self.filter_edit = QLineEdit()
        self.filter_edit.setObjectName("stringsFilterEdit")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.setPlaceholderText("Filter string values (literal text)")
        # Compatibility-friendly alias for callers that use search terminology.
        self.search_edit = self.filter_edit

        self.status_label = QLabel("No strings loaded")
        self.status_label.setObjectName("summaryBanner")

        self.model = StringTableModel()
        self.proxy_model = LiteralStringFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.model)

        self.table = QTableView()
        self.table.setObjectName("stringsTable")
        self.table.setModel(self.proxy_model)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive
        )
        self.table.horizontalHeader().setSectionResizeMode(
            4,
            QHeaderView.ResizeMode.Stretch,
        )
        self.table.setColumnWidth(0, 120)
        self.table.setColumnWidth(1, 120)
        self.table.setColumnWidth(2, 80)
        self.table.setColumnWidth(3, 105)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(self.filter_edit)
        layout.addWidget(self.status_label)
        layout.addWidget(self.table)

        self.filter_edit.textChanged.connect(self._filter_changed)
        self.table.selectionModel().currentChanged.connect(
            self._navigate_current
        )
        self.table.doubleClicked.connect(self._navigate_index)
        self.table_actions: TableActionController = install_table_actions(
            self.table,
            {"Copy file offset": 0, "Copy RVA": 1},
        )

    def set_service(
        self,
        service: StringExtractor | Sequence[ExtractedString] | None,
    ) -> None:
        """Display strings supplied by an extractor or an immutable sequence."""

        self._service = service
        if service is None:
            self.clear()
            return
        if isinstance(service, StringExtractor):
            try:
                strings = service.extract()
            except Exception as error:
                self.model.set_strings(())
                self.status_label.setText(f"String extraction failed: {error}")
                self.status_label.setProperty("state", "error")
                return
        else:
            strings = service
        self.set_strings(strings)

    def set_strings(
        self,
        strings: Sequence[ExtractedString],
        *,
        truncated: bool = False,
        limit: int | None = None,
    ) -> None:
        """Populate pre-extracted records and disclose any safety limit."""

        self._truncated = truncated
        self._limit = limit
        self.model.set_strings(strings)
        self.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.status_label.setProperty("state", "ready")
        self._update_status()

    def clear(self) -> None:
        """Clear service, rows, and filter state."""

        self._service = None
        self._truncated = False
        self._limit = None
        self.filter_edit.clear()
        self.model.set_strings(())
        self.status_label.setProperty("state", "empty")
        self.status_label.setText("No strings loaded")

    def focus_search(self) -> None:
        """Focus and select the literal-filter field."""

        self.filter_edit.setFocus(Qt.FocusReason.ShortcutFocusReason)
        self.filter_edit.selectAll()

    def _filter_changed(self, value: str) -> None:
        self.proxy_model.set_literal_filter(value)
        self._update_status()

    def _update_status(self) -> None:
        total = self.model.rowCount()
        visible = self.proxy_model.rowCount()
        limit_value = self._limit if self._limit is not None else total
        limit_note = (
            f"; extraction limit of {limit_value:,} reached — "
            "use Global Search for other values"
            if self._truncated
            else ""
        )
        if self.filter_edit.text():
            self.status_label.setText(
                f"Showing {visible:,} of {total:,} extracted strings{limit_note}"
            )
        else:
            self.status_label.setText(
                f"{total:,} extracted strings{limit_note}"
            )

    def _navigate_current(
        self,
        current: QModelIndex,
        previous: QModelIndex = QModelIndex(),
    ) -> None:
        del previous
        self._navigate_index(current)

    def _navigate_index(self, proxy_index: QModelIndex) -> None:
        if not proxy_index.isValid():
            return
        source = self.proxy_model.mapToSource(proxy_index)
        item = self.model.string(source.row())
        if item is not None:
            self.fileOffsetNavigationRequested.emit(
                item.offset,
                max(1, item.byte_length),
            )


__all__ = [
    "LiteralStringFilterProxyModel",
    "STRING_HEADERS",
    "StringTableModel",
    "StringsWidget",
]
