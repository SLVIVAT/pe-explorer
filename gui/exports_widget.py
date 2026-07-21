"""Sortable Qt model/view presentation for PE exports."""

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
    QTableView,
    QVBoxLayout,
    QWidget,
)

from pe.models import ExportDirectoryInfo, ExportedFunctionInfo
from gui.table_actions import install_table_actions
from utils.file_utils import format_hex


EXPORT_HEADERS: tuple[str, ...] = (
    "#",
    "Ordinal",
    "Name / Aliases",
    "RVA",
    "Type",
    "Forwarder",
)


class ExportTableModel(QAbstractTableModel):
    """Read-only sortable representation of Export Address Table entries."""

    def __init__(self) -> None:
        super().__init__()
        self._functions: tuple[ExportedFunctionInfo, ...] = ()

    def set_functions(self, functions: Sequence[ExportedFunctionInfo]) -> None:
        self.beginResetModel()
        self._functions = tuple(functions)
        self.endResetModel()

    def function(self, row: int) -> ExportedFunctionInfo | None:
        if 0 <= row < len(self._functions):
            return self._functions[row]
        return None

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._functions)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(EXPORT_HEADERS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object | None:
        if (
            orientation == Qt.Orientation.Horizontal
            and role == Qt.ItemDataRole.DisplayRole
            and 0 <= section < len(EXPORT_HEADERS)
        ):
            return EXPORT_HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = 0) -> object | None:
        if not index.isValid() or not 0 <= index.row() < len(self._functions):
            return None

        function = self._functions[index.row()]
        if function["rva"] == 0:
            export_type = "Unused"
            sort_type = 0
        elif function["is_forwarder"]:
            export_type = "Forwarder"
            sort_type = 2
        else:
            export_type = "Function"
            sort_type = 1
        display_values = (
            str(function["index"]),
            str(function["ordinal"]),
            ", ".join(function["names"]),
            format_hex(function["rva"]),
            export_type,
            function["forwarder"] or "",
        )
        sort_values: tuple[object, ...] = (
            function["index"],
            function["ordinal"],
            function["name"] or "",
            function["rva"],
            sort_type,
            function["forwarder"] or "",
        )

        if role == Qt.ItemDataRole.DisplayRole:
            return display_values[index.column()]
        if role == Qt.ItemDataRole.UserRole:
            return sort_values[index.column()]
        if role == Qt.ItemDataRole.TextAlignmentRole:
            horizontal = (
                Qt.AlignmentFlag.AlignLeft
                if index.column() in {2, 4, 5}
                else Qt.AlignmentFlag.AlignRight
            )
            return Qt.AlignmentFlag.AlignVCenter | horizontal
        if role == Qt.ItemDataRole.ForegroundRole and function["is_forwarder"]:
            return QColor("#c4a7e7")
        if role == Qt.ItemDataRole.ForegroundRole and function["rva"] == 0:
            return QColor("#8b95a7")
        if role == Qt.ItemDataRole.ToolTipRole:
            if function["rva"] == 0:
                return "Unused gap in the Export Address Table"
            if function["is_forwarder"]:
                return f"Forwarded to {function['forwarder']}"
            return f"Export RVA {format_hex(function['rva'])}"
        return None


class ExportsWidget(QWidget):
    """Export-directory summary and sortable exported-function table."""

    rvaNavigationRequested = Signal(int, int)

    def __init__(self) -> None:
        super().__init__()
        self.summary_label = QLabel("No export directory")
        self.summary_label.setObjectName("summaryBanner")
        self.summary_label.setWordWrap(True)

        self.model = ExportTableModel()
        self.proxy_model = QSortFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.model)
        self.proxy_model.setSortRole(Qt.ItemDataRole.UserRole)

        self.table = QTableView()
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
            2,
            QHeaderView.ResizeMode.Stretch,
        )
        self.table.setColumnWidth(0, 50)
        self.table.setColumnWidth(1, 85)
        self.table.setColumnWidth(3, 115)
        self.table.setColumnWidth(4, 100)
        self.table.setColumnWidth(5, 220)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(self.summary_label)
        layout.addWidget(self.table)

        self.table.selectionModel().currentChanged.connect(
            self._navigate_selected_export
        )
        install_table_actions(self.table, {"Copy RVA": 3})

    def set_exports(self, exports: ExportDirectoryInfo | None) -> None:
        if exports is None:
            self.clear_exports()
            return

        self.model.set_functions(exports["functions"])
        self.table.sortByColumn(1, Qt.SortOrder.AscendingOrder)
        active_exports = sum(
            function["rva"] != 0 for function in exports["functions"]
        )
        self.summary_label.setText(
            f"{exports['dll_name']}  |  {active_exports} exports  |  "
            f"{len(exports['functions'])} EAT entries  |  "
            f"Ordinal base {exports['ordinal_base']}  |  "
            f"EAT {format_hex(exports['export_address_table_rva'])}"
        )
        self.summary_label.setToolTip(
            "\n".join(
                (
                    f"Characteristics: {format_hex(exports['characteristics'])}",
                    f"TimeDateStamp: {format_hex(exports['timestamp'])}",
                    (
                        "Version: "
                        f"{exports['major_version']}.{exports['minor_version']}"
                    ),
                    f"Name RVA: {format_hex(exports['name_rva'])}",
                    f"Address table entries: {exports['address_table_entries']}",
                    f"Name pointers: {exports['number_of_name_pointers']}",
                    f"Name pointer RVA: {format_hex(exports['name_pointer_rva'])}",
                    f"Ordinal table RVA: {format_hex(exports['ordinal_table_rva'])}",
                )
            )
        )

    def clear_exports(self) -> None:
        self.summary_label.setText("No export directory")
        self.summary_label.setToolTip("")
        self.model.set_functions(())

    def _navigate_selected_export(
        self,
        current: QModelIndex,
        previous: QModelIndex = QModelIndex(),
    ) -> None:
        del previous
        source = self.proxy_model.mapToSource(current)
        function = self.model.function(source.row())
        if function is not None and function["rva"] != 0:
            self.rvaNavigationRequested.emit(function["rva"], 1)
