"""Reusable clipboard and context-menu actions for item views."""

from __future__ import annotations

from collections.abc import Mapping

from PySide6.QtCore import QModelIndex, QPoint, Qt
from PySide6.QtGui import QAction, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QMenu,
)


class TableActionController:
    """Add consistent copy operations to a Qt item view.

    ``address_columns`` maps user-facing labels such as ``"Copy RVA"`` to
    model columns. This keeps address semantics explicit instead of guessing
    from presentation text.
    """

    def __init__(
        self,
        view: QAbstractItemView,
        address_columns: Mapping[str, int] | None = None,
    ) -> None:
        self.view = view
        self.address_columns = dict(address_columns or {})

        view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        view.customContextMenuRequested.connect(self._show_menu)
        self.copy_shortcut = QShortcut(QKeySequence.StandardKey.Copy, view)
        self.copy_shortcut.activated.connect(self.copy_selection)

    def copy_value(self) -> None:
        """Copy the current cell's display value."""

        index = self.view.currentIndex()
        if index.isValid():
            self._copy_text(self._display_index(index))

    def copy_row(self) -> None:
        """Copy the current model row as tab-separated text."""

        index = self.view.currentIndex()
        model = self.view.model()
        if not index.isValid() or model is None:
            return
        values = [
            self._display_index(
                model.index(index.row(), column, index.parent())
            )
            for column in range(model.columnCount())
        ]
        self._copy_text("\t".join(values))

    def copy_selection(self) -> None:
        """Copy selected cells in a stable rectangular row layout."""

        selection_model = self.view.selectionModel()
        if selection_model is None:
            self.copy_value()
            return
        indexes = sorted(
            selection_model.selectedIndexes(),
            key=lambda index: (index.row(), index.column()),
        )
        if not indexes:
            self.copy_value()
            return

        rows: dict[int, list[str]] = {}
        for index in indexes:
            rows.setdefault(index.row(), []).append(
                self._display_index(index)
            )
        self._copy_text(
            "\n".join("\t".join(values) for values in rows.values())
        )

    def copy_table(self) -> None:
        """Copy headers and the complete model as tab-separated text."""

        model = self.view.model()
        if model is None:
            return
        headers = [
            str(
                model.headerData(
                    column,
                    Qt.Orientation.Horizontal,
                    Qt.ItemDataRole.DisplayRole,
                )
                or ""
            )
            for column in range(model.columnCount())
        ]
        lines = ["\t".join(headers)]
        self._append_model_rows(lines, QModelIndex(), 0)
        self._copy_text("\n".join(lines))

    def copy_column_value(self, column: int) -> None:
        """Copy one semantic value from the current row."""

        index = self.view.currentIndex()
        model = self.view.model()
        if (
            index.isValid()
            and model is not None
            and 0 <= column < model.columnCount()
        ):
            self._copy_text(
                self._display_index(
                    model.index(index.row(), column, index.parent())
                )
            )

    def _show_menu(self, position: QPoint) -> None:
        menu = QMenu(self.view)
        has_current = self.view.currentIndex().isValid()

        value_action = menu.addAction("Copy value")
        value_action.setEnabled(has_current)
        value_action.triggered.connect(self.copy_value)

        row_action = menu.addAction("Copy row")
        row_action.setEnabled(has_current)
        row_action.triggered.connect(self.copy_row)

        selection_action = menu.addAction("Copy selection")
        selection_model = self.view.selectionModel()
        selection_action.setEnabled(
            selection_model is not None
            and bool(selection_model.selectedIndexes())
        )
        selection_action.triggered.connect(self.copy_selection)

        table_action = menu.addAction("Copy table")
        table_action.triggered.connect(self.copy_table)

        if self.address_columns:
            menu.addSeparator()
            for label, column in self.address_columns.items():
                action = QAction(label, menu)
                action.setEnabled(has_current)
                action.triggered.connect(
                    lambda checked=False, value=column: (
                        self.copy_column_value(value)
                    )
                )
                menu.addAction(action)

        menu.exec(self.view.viewport().mapToGlobal(position))

    def _append_model_rows(
        self,
        lines: list[str],
        parent: QModelIndex,
        depth: int,
    ) -> None:
        model = self.view.model()
        if model is None:
            return
        for row in range(model.rowCount(parent)):
            indexes = [
                model.index(row, column, parent)
                for column in range(model.columnCount(parent))
            ]
            values = [self._display_index(index) for index in indexes]
            if values and depth:
                values[0] = f"{'  ' * depth}{values[0]}"
            lines.append("\t".join(values))
            child_parent = model.index(row, 0, parent)
            if model.hasChildren(child_parent):
                self._append_model_rows(lines, child_parent, depth + 1)

    def _display_index(self, index: QModelIndex) -> str:
        model = self.view.model()
        if model is None or not index.isValid():
            return ""
        value = model.data(
            index,
            Qt.ItemDataRole.DisplayRole,
        )
        return "" if value is None else str(value)

    @staticmethod
    def _copy_text(value: str) -> None:
        QApplication.clipboard().setText(value)


def install_table_actions(
    view: QAbstractItemView,
    address_columns: Mapping[str, int] | None = None,
) -> TableActionController:
    """Install and return a view-owned clipboard action controller."""

    controller = TableActionController(view, address_columns)
    # Keep an explicit Python reference; Qt parent ownership alone does not
    # guarantee the Python wrapper survives for signal dispatch.
    setattr(view, "_table_action_controller", controller)
    return controller


__all__ = ["TableActionController", "install_table_actions"]
