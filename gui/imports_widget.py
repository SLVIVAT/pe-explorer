"""Qt table models and views for parsed PE imports."""

from collections.abc import Sequence

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QGroupBox,
    QHeaderView,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from pe.models import ImportDescriptorInfo, ImportedFunctionInfo
from gui.table_actions import install_table_actions
from utils.file_utils import format_hex


DESCRIPTOR_HEADERS: tuple[str, ...] = (
    "#",
    "DLL",
    "OriginalFirstThunk",
    "TimeDateStamp",
    "ForwarderChain",
    "Name RVA",
    "FirstThunk",
    "Symbols",
)

SYMBOL_HEADERS: tuple[str, ...] = (
    "#",
    "Kind",
    "Name",
    "Ordinal",
    "Hint",
    "Lookup Entry RVA",
    "IAT Entry RVA",
    "Name RVA",
    "Raw Value",
)


class ImportDescriptorTableModel(QAbstractTableModel):
    """Read-only table model for IMAGE_IMPORT_DESCRIPTOR values."""

    def __init__(self) -> None:
        super().__init__()
        self._imports: tuple[ImportDescriptorInfo, ...] = ()

    def set_imports(self, imports: Sequence[ImportDescriptorInfo]) -> None:
        self.beginResetModel()
        self._imports = tuple(imports)
        self.endResetModel()

    def descriptor(self, row: int) -> ImportDescriptorInfo | None:
        if 0 <= row < len(self._imports):
            return self._imports[row]
        return None

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._imports)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(DESCRIPTOR_HEADERS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object | None:
        if (
            role == Qt.ItemDataRole.DisplayRole
            and orientation == Qt.Orientation.Horizontal
            and 0 <= section < len(DESCRIPTOR_HEADERS)
        ):
            return DESCRIPTOR_HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = 0) -> object | None:
        if not index.isValid() or not 0 <= index.row() < len(self._imports):
            return None

        descriptor = self._imports[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            values = (
                str(descriptor["index"]),
                descriptor["dll_name"],
                format_hex(descriptor["original_first_thunk"]),
                format_hex(descriptor["timestamp"]),
                format_hex(descriptor["forwarder_chain"]),
                format_hex(descriptor["name_rva"]),
                format_hex(descriptor["first_thunk"]),
                str(len(descriptor["functions"])),
            )
            return values[index.column()]

        if role == Qt.ItemDataRole.TextAlignmentRole:
            horizontal = (
                Qt.AlignmentFlag.AlignLeft
                if index.column() == 1
                else Qt.AlignmentFlag.AlignRight
            )
            return Qt.AlignmentFlag.AlignVCenter | horizontal

        if role == Qt.ItemDataRole.ToolTipRole and index.column() == 1:
            return descriptor["dll_name"]
        return None


class ImportedFunctionTableModel(QAbstractTableModel):
    """Read-only table model for imports belonging to one descriptor."""

    def __init__(self) -> None:
        super().__init__()
        self._functions: tuple[ImportedFunctionInfo, ...] = ()
        self._raw_digits = 8

    def set_functions(
        self,
        functions: Sequence[ImportedFunctionInfo],
        pe_format: str,
    ) -> None:
        self.beginResetModel()
        self._functions = tuple(functions)
        self._raw_digits = 16 if pe_format == "PE32+" else 8
        self.endResetModel()

    def function(self, row: int) -> ImportedFunctionInfo | None:
        if 0 <= row < len(self._functions):
            return self._functions[row]
        return None

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._functions)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(SYMBOL_HEADERS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object | None:
        if (
            role == Qt.ItemDataRole.DisplayRole
            and orientation == Qt.Orientation.Horizontal
            and 0 <= section < len(SYMBOL_HEADERS)
        ):
            return SYMBOL_HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = 0) -> object | None:
        if not index.isValid() or not 0 <= index.row() < len(self._functions):
            return None

        function = self._functions[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            kind_labels = {
                "name": "Name",
                "ordinal": "Ordinal",
                "bound_address": "Bound address",
            }
            kind = function.get(
                "kind",
                "ordinal" if function["is_ordinal"] else "name",
            )
            values = (
                str(function["index"]),
                kind_labels[kind],
                function["name"] or "",
                "" if function["ordinal"] is None else str(function["ordinal"]),
                "" if function["hint"] is None else str(function["hint"]),
                format_hex(function["lookup_table_rva"]),
                format_hex(function["import_address_table_rva"]),
                (
                    ""
                    if function["name_rva"] is None
                    else format_hex(function["name_rva"])
                ),
                format_hex(function["raw_value"], self._raw_digits),
            )
            return values[index.column()]

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if index.column() in {1, 2}:
                horizontal = Qt.AlignmentFlag.AlignLeft
            else:
                horizontal = Qt.AlignmentFlag.AlignRight
            return Qt.AlignmentFlag.AlignVCenter | horizontal

        if role == Qt.ItemDataRole.ToolTipRole and index.column() == 2:
            return function["name"]
        return None


class ImportsWidget(QWidget):
    """Master/detail Qt-table view of imported DLLs and their symbols."""

    rvaNavigationRequested = Signal(int, int)

    def __init__(self) -> None:
        super().__init__()
        self._pe_format = "PE32"
        self._import_directory_rva: int | None = None

        self.descriptor_model = ImportDescriptorTableModel()
        self.symbol_model = ImportedFunctionTableModel()
        self.descriptor_table = self._create_table()
        self.symbol_table = self._create_table()
        self.descriptor_table.setModel(self.descriptor_model)
        self.symbol_table.setModel(self.symbol_model)

        self._configure_columns()

        self.descriptor_group = QGroupBox("Imported DLLs (0)")
        descriptor_layout = QVBoxLayout(self.descriptor_group)
        descriptor_layout.addWidget(self.descriptor_table)

        self.symbol_group = QGroupBox("Imported symbols (0)")
        symbol_layout = QVBoxLayout(self.symbol_group)
        symbol_layout.addWidget(self.symbol_table)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.descriptor_group)
        splitter.addWidget(self.symbol_group)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(splitter)

        self.descriptor_table.selectionModel().selectionChanged.connect(
            self._show_selected_descriptor
        )
        self.symbol_table.selectionModel().currentChanged.connect(
            self._navigate_selected_symbol
        )
        install_table_actions(
            self.descriptor_table,
            {
                "Copy name RVA": 5,
                "Copy first-thunk RVA": 6,
            },
        )
        install_table_actions(
            self.symbol_table,
            {
                "Copy lookup RVA": 5,
                "Copy IAT RVA": 6,
                "Copy name RVA": 7,
            },
        )

    def set_imports(
        self,
        imports: Sequence[ImportDescriptorInfo],
        pe_format: str,
        import_directory_rva: int | None = None,
    ) -> None:
        """Replace the descriptor and symbol models with a new import table."""

        self._pe_format = pe_format
        self._import_directory_rva = import_directory_rva
        self.symbol_model.set_functions((), pe_format)
        self.descriptor_model.set_imports(imports)
        self.descriptor_group.setTitle(f"Imported DLLs ({len(imports)})")
        self.symbol_group.setTitle("Imported symbols (0)")

        if imports:
            self.descriptor_table.selectRow(0)
            self._set_symbol_descriptor(0)

    def clear_imports(self) -> None:
        self.set_imports((), "PE32", None)

    def _show_selected_descriptor(self) -> None:
        selected_rows = self.descriptor_table.selectionModel().selectedRows()
        row = selected_rows[0].row() if selected_rows else -1
        self._set_symbol_descriptor(row)
        if self._import_directory_rva is not None and row >= 0:
            self.rvaNavigationRequested.emit(
                self._import_directory_rva + row * 20,
                20,
            )

    def _navigate_selected_symbol(
        self,
        current: QModelIndex,
        previous: QModelIndex = QModelIndex(),
    ) -> None:
        del previous
        function = self.symbol_model.function(current.row())
        if function is None:
            return
        name_rva = function["name_rva"]
        if name_rva is not None:
            self.rvaNavigationRequested.emit(name_rva, 2)
            return
        entry_size = 8 if self._pe_format == "PE32+" else 4
        self.rvaNavigationRequested.emit(
            function["lookup_table_rva"],
            entry_size,
        )

    def _set_symbol_descriptor(self, row: int) -> None:
        descriptor = self.descriptor_model.descriptor(row)
        functions = descriptor["functions"] if descriptor is not None else ()
        self.symbol_model.set_functions(functions, self._pe_format)
        dll_name = descriptor["dll_name"] if descriptor is not None else ""
        suffix = f" - {dll_name}" if dll_name else ""
        self.symbol_group.setTitle(
            f"Imported symbols ({len(functions)}){suffix}"
        )

    @staticmethod
    def _create_table() -> QTableView:
        table = QTableView()
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setWordWrap(False)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive
        )
        return table

    def _configure_columns(self) -> None:
        descriptor_widths = (45, 180, 145, 120, 125, 105, 105, 75)
        for column, width in enumerate(descriptor_widths):
            self.descriptor_table.setColumnWidth(column, width)
        self.descriptor_table.horizontalHeader().setSectionResizeMode(
            1,
            QHeaderView.ResizeMode.Stretch,
        )

        symbol_widths = (45, 75, 220, 75, 75, 130, 120, 105, 145)
        for column, width in enumerate(symbol_widths):
            self.symbol_table.setColumnWidth(column, width)
        self.symbol_table.horizontalHeader().setSectionResizeMode(
            2,
            QHeaderView.ResizeMode.Stretch,
        )
