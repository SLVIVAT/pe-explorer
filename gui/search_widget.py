"""Responsive global binary/address search widget."""

from __future__ import annotations

from collections.abc import Sequence
from typing import cast

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    QThreadPool,
    Qt,
    Signal,
)
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from gui.table_actions import TableActionController, install_table_actions
from gui.workers import BackgroundTask, ProgressCallback
from pe.search import SearchMode, SearchResult, SearchService
from utils.file_utils import format_hex


SEARCH_HEADERS: tuple[str, ...] = (
    "Offset",
    "RVA",
    "VA",
    "Section",
    "Preview",
)

SEARCH_MODES: tuple[tuple[str, SearchMode], ...] = (
    ("ASCII", "ascii"),
    ("UTF-16LE", "utf-16le"),
    ("Hex bytes", "hex"),
    ("RVA", "rva"),
    ("VA", "va"),
    ("File offset", "file-offset"),
)


class SearchResultTableModel(QAbstractTableModel):
    """Sortable read-only model for global-search results."""

    def __init__(self) -> None:
        super().__init__()
        self._results: tuple[SearchResult, ...] = ()

    def set_results(self, results: Sequence[SearchResult]) -> None:
        self.beginResetModel()
        self._results = tuple(results)
        self.endResetModel()

    def result(self, row: int) -> SearchResult | None:
        if 0 <= row < len(self._results):
            return self._results[row]
        return None

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._results)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(SEARCH_HEADERS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object | None:
        if (
            orientation == Qt.Orientation.Horizontal
            and role == Qt.ItemDataRole.DisplayRole
            and 0 <= section < len(SEARCH_HEADERS)
        ):
            return SEARCH_HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = 0) -> object | None:
        result = self.result(index.row())
        if result is None or not index.isValid():
            return None
        values: tuple[object | None, ...] = (
            result.offset,
            result.rva,
            result.va,
            result.section,
            result.preview,
        )
        value = values[index.column()]
        if role == Qt.ItemDataRole.DisplayRole:
            if index.column() in {0, 1, 2}:
                return "" if value is None else format_hex(cast(int, value))
            return "" if value is None else str(value)
        if role == Qt.ItemDataRole.UserRole:
            if index.column() in {0, 1, 2}:
                return -1 if value is None else value
            return "" if value is None else str(value).casefold()
        if role == Qt.ItemDataRole.TextAlignmentRole:
            horizontal = (
                Qt.AlignmentFlag.AlignRight
                if index.column() in {0, 1, 2}
                else Qt.AlignmentFlag.AlignLeft
            )
            return Qt.AlignmentFlag.AlignVCenter | horizontal
        if role == Qt.ItemDataRole.ToolTipRole:
            return (
                f"Mode: {result.mode}\nMatch length: {result.length}\n"
                f"{result.preview}"
            )
        if role == Qt.ItemDataRole.ForegroundRole and result.offset is None:
            return QColor("#f6c177")
        return None


class SearchWidget(QWidget):
    """Asynchronous global search with generation-safe result delivery."""

    fileOffsetNavigationRequested = Signal(int, int)
    errorOccurred = Signal(str)

    def __init__(self, thread_pool: QThreadPool | None = None) -> None:
        super().__init__()
        self._service: SearchService | None = None
        self._thread_pool = thread_pool or QThreadPool.globalInstance()
        self._generation = 0
        self._busy_generation: int | None = None
        self._tasks: dict[int, BackgroundTask] = {}
        self._task_limits: dict[int, int] = {}

        self.mode_combo = QComboBox()
        self.mode_combo.setObjectName("globalSearchMode")
        for label, mode in SEARCH_MODES:
            self.mode_combo.addItem(label, mode)

        self.query_edit = QLineEdit()
        self.query_edit.setObjectName("globalSearchQuery")
        self.query_edit.setClearButtonEnabled(True)
        self.query_edit.setPlaceholderText("Text to find")
        self.search_edit = self.query_edit

        self.limit_spin = QSpinBox()
        self.limit_spin.setObjectName("globalSearchLimit")
        self.limit_spin.setRange(1, 100_000)
        self.limit_spin.setValue(1_000)
        self.limit_spin.setPrefix("Limit: ")

        self.search_button = QPushButton("Search")
        self.search_button.setObjectName("globalSearchButton")
        self.search_button.setEnabled(False)

        controls = QHBoxLayout()
        controls.setContentsMargins(0, 0, 0, 0)
        controls.setSpacing(8)
        controls.addWidget(self.mode_combo)
        controls.addWidget(self.query_edit, 1)
        controls.addWidget(self.limit_spin)
        controls.addWidget(self.search_button)

        self.status_label = QLabel("Search service unavailable")
        self.status_label.setObjectName("summaryBanner")
        self.status_label.setWordWrap(True)

        self.model = SearchResultTableModel()
        self.proxy_model = QSortFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.model)
        self.proxy_model.setSortRole(Qt.ItemDataRole.UserRole)
        self.proxy_model.setDynamicSortFilter(True)

        self.table = QTableView()
        self.table.setObjectName("globalSearchResults")
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
        self.table.setColumnWidth(2, 145)
        self.table.setColumnWidth(3, 110)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addLayout(controls)
        layout.addWidget(self.status_label)
        layout.addWidget(self.table)

        self.search_button.clicked.connect(self.start_search)
        self.query_edit.returnPressed.connect(self.start_search)
        self.mode_combo.currentIndexChanged.connect(self._mode_changed)
        self.table.doubleClicked.connect(self._navigate_result)
        self.table_actions: TableActionController = install_table_actions(
            self.table,
            {
                "Copy file offset": 0,
                "Copy RVA": 1,
                "Copy VA": 2,
            },
        )

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def is_busy(self) -> bool:
        return self._busy_generation == self._generation

    def set_service(self, service: SearchService | None) -> None:
        """Install a service and invalidate results from all older searches."""

        self._invalidate_generation()
        self._service = service
        self.model.set_results(())
        self.query_edit.clear()
        self._set_busy(bool(self._tasks))
        if service is None:
            self.status_label.setText("Search service unavailable")
            self.status_label.setProperty("state", "empty")
        else:
            self.status_label.setText("Ready to search")
            self.status_label.setProperty("state", "ready")

    def clear(self) -> None:
        """Invalidate pending work and clear the installed service and UI."""

        self._invalidate_generation()
        self._service = None
        self.model.set_results(())
        self.query_edit.clear()
        self._set_busy(False)
        self.status_label.setProperty("state", "empty")
        self.status_label.setText("Search service unavailable")

    def focus_search(self) -> None:
        """Focus and select the query field."""

        self.query_edit.setFocus(Qt.FocusReason.ShortcutFocusReason)
        self.query_edit.selectAll()

    def start_search(self) -> None:
        """Capture the current query and execute it outside the GUI thread."""

        service = self._service
        if service is None:
            self._show_error("Search service unavailable.")
            return
        if self._tasks:
            self.status_label.setProperty("state", "busy")
            self.status_label.setText(
                "A previous search is still finishing; please wait."
            )
            return

        self._generation += 1
        generation = self._generation
        query = self.query_edit.text()
        mode = cast(SearchMode, self.mode_combo.currentData())
        limit = self.limit_spin.value()
        self._busy_generation = generation
        self._set_busy(True)
        self.status_label.setProperty("state", "busy")
        mode_name = self.mode_combo.currentText()
        self.status_label.setText(f"Searching in {mode_name} mode…")

        def execute(progress: ProgressCallback) -> tuple[SearchResult, ...]:
            progress("Searching")
            return service.search(query, mode, max_results=limit)

        task = BackgroundTask(generation, execute)
        task.signals.progress.connect(self._task_progress)
        task.signals.succeeded.connect(self._task_succeeded)
        task.signals.failed.connect(self._task_failed)
        task.signals.finished.connect(self._task_finished)
        self._tasks[generation] = task
        self._task_limits[generation] = limit
        self._thread_pool.start(task)

    # Useful semantic alias for callers wiring a generic search action.
    search = start_search

    def _task_progress(self, generation: int, message: str) -> None:
        if generation != self._generation:
            return
        self.status_label.setText(message or "Searching…")

    def _task_succeeded(self, generation: int, value: object) -> None:
        if generation != self._generation:
            return
        try:
            results = tuple(cast(Sequence[SearchResult], value))
        except TypeError:
            self._show_error("Search returned an invalid result collection.")
            return
        if not all(isinstance(item, SearchResult) for item in results):
            self._show_error("Search returned an invalid result item.")
            return
        self.model.set_results(results)
        self.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        count = len(results)
        limit = self._task_limits.get(generation, self.limit_spin.value())
        suffix = " (limit reached)" if count == limit else ""
        self.status_label.setProperty("state", "ready")
        self.status_label.setText(
            f"{count:,} result{'s' if count != 1 else ''}{suffix}"
        )

    def _task_failed(
        self,
        generation: int,
        message: str,
        details: str,
    ) -> None:
        del details
        if generation == self._generation:
            self.model.set_results(())
            self._show_error(message or "Search failed.")

    def _task_finished(self, generation: int) -> None:
        self._tasks.pop(generation, None)
        self._task_limits.pop(generation, None)
        if generation == self._generation:
            self._busy_generation = None
        if not self._tasks:
            self._set_busy(False)

    def _show_error(self, message: str) -> None:
        self.status_label.setProperty("state", "error")
        self.status_label.setText(f"Error: {message}")
        self.errorOccurred.emit(message)

    def _set_busy(self, busy: bool) -> None:
        self.search_button.setText("Searching…" if busy else "Search")
        self.search_button.setEnabled(self._service is not None and not busy)

    def _invalidate_generation(self) -> None:
        self._generation += 1
        self._busy_generation = None

    def _mode_changed(self, index: int) -> None:
        del index
        mode = self.mode_combo.currentData()
        placeholders = {
            "ascii": "ASCII text to find",
            "utf-16le": "UTF-16LE text to find",
            "hex": "Hex bytes, e.g. 4D 5A 90 00",
            "rva": "RVA in hex, e.g. 1000",
            "va": "Virtual address in hex",
            "file-offset": "File offset in hex",
        }
        self.query_edit.setPlaceholderText(placeholders.get(mode, "Search query"))

    def _navigate_result(self, proxy_index: QModelIndex) -> None:
        if not proxy_index.isValid():
            return
        source = self.proxy_model.mapToSource(proxy_index)
        result = self.model.result(source.row())
        if result is not None and result.offset is not None:
            self.fileOffsetNavigationRequested.emit(
                result.offset,
                max(1, result.length),
            )


__all__ = [
    "SEARCH_HEADERS",
    "SEARCH_MODES",
    "SearchResultTableModel",
    "SearchWidget",
]
