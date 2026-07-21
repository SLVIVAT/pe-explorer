"""Sortable Qt table view for IMAGE_DATA_DIRECTORY entries."""

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
    QTableView,
    QVBoxLayout,
    QWidget,
)

from pe.models import DataDirectoryInfo
from gui.table_actions import install_table_actions
from utils.file_utils import format_hex


DIRECTORY_HEADERS: tuple[str, ...] = (
    "#",
    "Directory",
    "RVA / File Offset",
    "Size",
    "Status",
)


class DataDirectoryTableModel(QAbstractTableModel):
    """Read-only model that preserves raw directory values and status."""

    def __init__(self) -> None:
        super().__init__()
        self._directories: tuple[DataDirectoryInfo, ...] = ()

    def set_directories(self, directories: Sequence[DataDirectoryInfo]) -> None:
        self.beginResetModel()
        self._directories = tuple(directories)
        self.endResetModel()

    def directory(self, row: int) -> DataDirectoryInfo | None:
        if 0 <= row < len(self._directories):
            return self._directories[row]
        return None

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._directories)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(DIRECTORY_HEADERS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object | None:
        if (
            orientation == Qt.Orientation.Horizontal
            and role == Qt.ItemDataRole.DisplayRole
            and 0 <= section < len(DIRECTORY_HEADERS)
        ):
            return DIRECTORY_HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = 0) -> object | None:
        if not index.isValid() or not 0 <= index.row() < len(self._directories):
            return None

        directory = self._directories[index.row()]
        raw_values: tuple[object, ...] = (
            directory["index"],
            directory["name"],
            directory["virtual_address"],
            directory["size"],
            directory["status"],
        )

        if role == Qt.ItemDataRole.DisplayRole:
            values = (
                str(directory["index"]),
                directory["name"],
                format_hex(directory["virtual_address"]),
                format_hex(directory["size"]),
                directory["status"],
            )
            return values[index.column()]

        if role == Qt.ItemDataRole.UserRole:
            return raw_values[index.column()]

        if role == Qt.ItemDataRole.TextAlignmentRole:
            horizontal = (
                Qt.AlignmentFlag.AlignLeft
                if index.column() in {1, 4}
                else Qt.AlignmentFlag.AlignRight
            )
            return Qt.AlignmentFlag.AlignVCenter | horizontal

        if role == Qt.ItemDataRole.ForegroundRole and index.column() == 4:
            status = directory["status"]
            if status.startswith("Present"):
                return QColor("#6ee7a8")
            if status.startswith("Invalid"):
                return QColor("#ff7b8b")
            if status.startswith("Unexpected"):
                return QColor("#f6c177")
            return QColor("#8b95a7")

        if role == Qt.ItemDataRole.ToolTipRole:
            return directory["status"]
        return None


class DataDirectoriesWidget(QWidget):
    """Responsive sortable table of every declared data directory."""

    addressNavigationRequested = Signal(str, int, int)

    def __init__(self) -> None:
        super().__init__()
        self.model = DataDirectoryTableModel()
        self.proxy_model = QSortFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.model)
        self.proxy_model.setSortRole(Qt.ItemDataRole.UserRole)

        self.table = QTableView()
        self.table.setModel(self.proxy_model)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setSortingEnabled(True)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive
        )
        self.table.horizontalHeader().setSectionResizeMode(
            1,
            QHeaderView.ResizeMode.ResizeToContents,
        )
        self.table.horizontalHeader().setSectionResizeMode(
            4,
            QHeaderView.ResizeMode.Stretch,
        )
        self.table.setColumnWidth(0, 50)
        self.table.setColumnWidth(2, 140)
        self.table.setColumnWidth(3, 110)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.table)

        self.table.selectionModel().currentChanged.connect(
            self._navigate_selected_directory
        )
        install_table_actions(
            self.table,
            {"Copy RVA / file offset": 2},
        )

    def set_directories(self, directories: Sequence[DataDirectoryInfo]) -> None:
        self.model.set_directories(directories)
        self.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)

    def clear_directories(self) -> None:
        self.model.set_directories(())

    def _navigate_selected_directory(
        self,
        current: QModelIndex,
        previous: QModelIndex = QModelIndex(),
    ) -> None:
        del previous
        source = self.proxy_model.mapToSource(current)
        directory = self.model.directory(source.row())
        if (
            directory is None
            or directory["virtual_address"] == 0
            or not directory["status"].startswith("Present")
        ):
            return
        kind = "file_offset" if directory["index"] == 4 else "rva"
        self.addressNavigationRequested.emit(
            kind,
            directory["virtual_address"],
            max(1, directory["size"]),
        )
