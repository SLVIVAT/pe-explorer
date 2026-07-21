"""Explained security-analysis table and overall risk banner."""

from collections.abc import Sequence

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLabel,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from pe.models import AnalysisFindingInfo, SecurityAnalysisInfo
from gui.table_actions import install_table_actions


ANALYSIS_HEADERS: tuple[str, ...] = ("Check", "Result", "Assessment", "Why")

SEVERITY_COLORS = {
    "good": QColor("#6ee7a8"),
    "info": QColor("#8fc7ff"),
    "warning": QColor("#f6c177"),
    "danger": QColor("#ff7b8b"),
}


class AnalysisTableModel(QAbstractTableModel):
    """Read-only table that keeps every conclusion beside its explanation."""

    def __init__(self) -> None:
        super().__init__()
        self._findings: tuple[AnalysisFindingInfo, ...] = ()

    def set_findings(self, findings: Sequence[AnalysisFindingInfo]) -> None:
        self.beginResetModel()
        self._findings = tuple(findings)
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._findings)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(ANALYSIS_HEADERS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object | None:
        if (
            orientation == Qt.Orientation.Horizontal
            and role == Qt.ItemDataRole.DisplayRole
            and 0 <= section < len(ANALYSIS_HEADERS)
        ):
            return ANALYSIS_HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = 0) -> object | None:
        if not index.isValid() or not 0 <= index.row() < len(self._findings):
            return None

        finding = self._findings[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            values = (
                finding["label"],
                finding["value"],
                finding["severity"].title(),
                finding["explanation"],
            )
            return values[index.column()]
        if role == Qt.ItemDataRole.ForegroundRole and index.column() in {1, 2}:
            return SEVERITY_COLORS[finding["severity"]]
        if role == Qt.ItemDataRole.FontRole and index.column() == 0:
            font = QFont()
            font.setBold(True)
            return font
        if role == Qt.ItemDataRole.ToolTipRole:
            return finding["explanation"]
        return None


class AnalysisWidget(QWidget):
    """Risk banner plus detailed, evidence-backed analysis conclusions."""

    def __init__(self) -> None:
        super().__init__()
        self.risk_label = QLabel("Analysis unavailable")
        self.risk_label.setObjectName("riskBanner")
        self.risk_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.model = AnalysisTableModel()
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setWordWrap(True)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive
        )
        self.table.horizontalHeader().setSectionResizeMode(
            3,
            QHeaderView.ResizeMode.Stretch,
        )
        self.table.setColumnWidth(0, 190)
        self.table.setColumnWidth(1, 220)
        self.table.setColumnWidth(2, 100)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(self.risk_label)
        layout.addWidget(self.table)
        install_table_actions(self.table)

    def set_analysis(self, analysis: SecurityAnalysisInfo | None) -> None:
        if analysis is None:
            self.clear_analysis()
            return
        risk = analysis["overall_risk"]
        self.risk_label.setText(
            f"Overall Risk: {risk}  |  Score: {analysis['risk_score']}"
        )
        self.risk_label.setProperty("risk", risk.lower())
        self.risk_label.style().unpolish(self.risk_label)
        self.risk_label.style().polish(self.risk_label)
        self.model.set_findings(analysis["findings"])

    def clear_analysis(self) -> None:
        self.risk_label.setText("Analysis unavailable")
        self.risk_label.setProperty("risk", "none")
        self.risk_label.style().unpolish(self.risk_label)
        self.risk_label.style().polish(self.risk_label)
        self.model.set_findings(())
