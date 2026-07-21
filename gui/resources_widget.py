"""Tree-model presentation for the complete PE resource hierarchy."""

from dataclasses import dataclass, field

from PySide6.QtCore import QAbstractItemModel, QModelIndex, Qt, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QHeaderView,
    QPlainTextEdit,
    QSplitter,
    QStyle,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from pe.models import ResourceNodeInfo
from gui.table_actions import install_table_actions
from utils.file_utils import format_hex


RESOURCE_HEADERS: tuple[str, ...] = (
    "Resource",
    "Kind",
    "RVA",
    "File Offset",
    "Size",
    "Code Page",
    "Details",
)


@dataclass(slots=True)
class _ResourceItem:
    node: ResourceNodeInfo | None
    parent_item: _ResourceItem | None
    children: list[_ResourceItem] = field(default_factory=list)

    def row(self) -> int:
        if self.parent_item is None:
            return 0
        return self.parent_item.children.index(self)


class ResourceTreeModel(QAbstractItemModel):
    """Efficient read-only model over recursive ResourceNode dictionaries."""

    def __init__(self) -> None:
        super().__init__()
        self._root = _ResourceItem(None, None)
        style = QApplication.style()
        self._directory_icon: QIcon = style.standardIcon(
            QStyle.StandardPixmap.SP_DirIcon
        )
        self._file_icon: QIcon = style.standardIcon(QStyle.StandardPixmap.SP_FileIcon)

    def set_resource(self, resource: ResourceNodeInfo | None) -> None:
        self.beginResetModel()
        self._root = _ResourceItem(None, None)
        if resource is not None:
            self._root.children.append(self._build_item(resource, self._root))
        self.endResetModel()

    def resource_for_index(self, index: QModelIndex) -> ResourceNodeInfo | None:
        if not index.isValid():
            return None
        item = index.internalPointer()
        return item.node if isinstance(item, _ResourceItem) else None

    def index(
        self,
        row: int,
        column: int,
        parent: QModelIndex = QModelIndex(),
    ) -> QModelIndex:
        if row < 0 or column < 0 or column >= len(RESOURCE_HEADERS):
            return QModelIndex()
        parent_item = self._item(parent)
        if row >= len(parent_item.children):
            return QModelIndex()
        return self.createIndex(row, column, parent_item.children[row])

    def parent(self, index: QModelIndex) -> QModelIndex:
        if not index.isValid():
            return QModelIndex()
        item = self._item(index)
        parent_item = item.parent_item
        if parent_item is None or parent_item is self._root:
            return QModelIndex()
        return self.createIndex(parent_item.row(), 0, parent_item)

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid() and parent.column() != 0:
            return 0
        return len(self._item(parent).children)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(RESOURCE_HEADERS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object | None:
        if (
            orientation == Qt.Orientation.Horizontal
            and role == Qt.ItemDataRole.DisplayRole
            and 0 <= section < len(RESOURCE_HEADERS)
        ):
            return RESOURCE_HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = 0) -> object | None:
        node = self.resource_for_index(index)
        if node is None:
            return None

        data = node["data"]
        if role == Qt.ItemDataRole.DisplayRole:
            if node["is_directory"]:
                details = (
                    f"{node['number_of_named_entries']} named, "
                    f"{node['number_of_id_entries']} ID entries"
                )
                values = (
                    node["name"],
                    "Directory",
                    "",
                    "",
                    "",
                    "",
                    details,
                )
            else:
                values = (
                    node["name"],
                    data["resource_type"] if data is not None else "Data",
                    format_hex(data["rva"]) if data is not None else "",
                    (
                        format_hex(data["file_offset"])
                        if data is not None
                        and data["file_offset"] is not None
                        else ""
                    ),
                    format_hex(data["size"]) if data is not None else "",
                    str(data["code_page"]) if data is not None else "",
                    data["summary"] if data is not None else "",
                )
            return values[index.column()]

        if role == Qt.ItemDataRole.DecorationRole and index.column() == 0:
            return self._directory_icon if node["is_directory"] else self._file_icon

        if role == Qt.ItemDataRole.ToolTipRole:
            return self.details_text(node)
        return None

    @staticmethod
    def details_text(node: ResourceNodeInfo) -> str:
        if node["is_directory"]:
            return "\n".join(
                (
                    node["name"],
                    f"Characteristics: {format_hex(node['characteristics'] or 0)}",
                    f"TimeDateStamp: {format_hex(node['timestamp'] or 0)}",
                    f"Version: {node['major_version']}.{node['minor_version']}",
                    f"Named entries: {node['number_of_named_entries']}",
                    f"ID entries: {node['number_of_id_entries']}",
                )
            )

        data = node["data"]
        if data is None:
            return node["name"]
        file_offset = data["file_offset"]
        formatted_file_offset = (
            format_hex(file_offset) if file_offset is not None else "N/A"
        )
        metadata = "\n".join(
            (
                f"Type: {data['resource_type']}",
                f"RVA: {format_hex(data['rva'])}",
                f"File offset: {formatted_file_offset}",
                f"Size: {data['size']} bytes",
                f"Code page: {data['code_page']}",
                f"Reserved: {format_hex(data['reserved'])}",
                f"Summary: {data['summary']}",
            )
        )
        return f"{metadata}\n\n{data['content']}" if data["content"] else metadata

    def _build_item(
        self,
        node: ResourceNodeInfo,
        parent: _ResourceItem,
    ) -> _ResourceItem:
        item = _ResourceItem(node, parent)
        item.children = [self._build_item(child, item) for child in node["children"]]
        return item

    def _item(self, index: QModelIndex) -> _ResourceItem:
        if index.isValid():
            item = index.internalPointer()
            if isinstance(item, _ResourceItem):
                return item
        return self._root


class ResourcesWidget(QWidget):
    """Complete resource tree with decoded details for the selected leaf."""

    fileOffsetNavigationRequested = Signal(int, int)

    def __init__(self) -> None:
        super().__init__()
        self.model = ResourceTreeModel()
        self.tree = QTreeView()
        self.tree.setModel(self.model)
        self.tree.setAlternatingRowColors(True)
        self.tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tree.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tree.setUniformRowHeights(True)
        self.tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tree.setColumnWidth(1, 130)
        self.tree.setColumnWidth(2, 110)
        self.tree.setColumnWidth(3, 110)
        self.tree.setColumnWidth(4, 100)
        self.tree.setColumnWidth(5, 90)
        self.tree.setColumnWidth(6, 320)

        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText(
            "Select a resource to inspect decoded details."
        )

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.tree)
        splitter.addWidget(self.details)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(splitter)

        self.tree.selectionModel().currentChanged.connect(self._show_details)
        install_table_actions(
            self.tree,
            {
                "Copy RVA": 2,
                "Copy file offset": 3,
            },
        )

    def set_resource(self, resource: ResourceNodeInfo | None) -> None:
        self.details.clear()
        self.model.set_resource(resource)
        if resource is not None:
            self.tree.expandToDepth(1)
            first = self.model.index(0, 0)
            self.tree.setCurrentIndex(first)
            self._show_details(first)

    def clear_resource(self) -> None:
        self.set_resource(None)

    def _show_details(
        self,
        index: QModelIndex,
        previous: QModelIndex = QModelIndex(),
    ) -> None:
        del previous
        node = self.model.resource_for_index(index)
        self.details.setPlainText(
            self.model.details_text(node) if node is not None else ""
        )
        if node is not None and node["data"] is not None:
            data = node["data"]
            file_offset = data["file_offset"]
            if file_offset is not None:
                self.fileOffsetNavigationRequested.emit(
                    file_offset,
                    max(1, data["size"]),
                )
