"""Professional views for entropy, overlays, hashes, signatures, and version data."""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtCore import (
    QAbstractItemModel,
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
    QPushButton,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from gui.table_actions import install_table_actions
from pe.certificates import CertificateAnalysis
from pe.file_analysis import FileAnalysis, OverlayRegion, SectionEntropy
from pe.version_info import VersionInformation
from utils.file_utils import format_hex, format_size


ENTROPY_HEADERS = (
    "#",
    "Section",
    "File Offset",
    "Raw Size",
    "Entropy",
    "Indicator",
    "Packed Suspicion",
    "Why",
)

_COLOR_VALUES = {
    "gray": QColor("#8b95a7"),
    "green": QColor("#6ee7a8"),
    "amber": QColor("#f6c177"),
    "red": QColor("#ff7b8b"),
}


class EntropyTableModel(QAbstractTableModel):
    """Sortable section-entropy model with evidence beside every verdict."""

    def __init__(self) -> None:
        super().__init__()
        self._sections: tuple[SectionEntropy, ...] = ()

    def set_sections(self, sections: Sequence[SectionEntropy]) -> None:
        self.beginResetModel()
        self._sections = tuple(sections)
        self.endResetModel()

    def section(self, row: int) -> SectionEntropy | None:
        if 0 <= row < len(self._sections):
            return self._sections[row]
        return None

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._sections)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(ENTROPY_HEADERS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object | None:
        if (
            orientation == Qt.Orientation.Horizontal
            and role == Qt.ItemDataRole.DisplayRole
            and 0 <= section < len(ENTROPY_HEADERS)
        ):
            return ENTROPY_HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = 0) -> object | None:
        section = self.section(index.row())
        if section is None or not index.isValid():
            return None
        suspicion = (
            "High"
            if section.suspicious
            else "Review"
            if section.color == "amber"
            else "Unknown"
            if section.entropy is None
            else "Low"
        )
        display = (
            str(section.section_index),
            section.section_name,
            format_hex(section.file_offset),
            format_size(section.declared_size),
            "N/A" if section.entropy is None else f"{section.entropy:.3f}",
            f"● {section.color.title()}",
            suspicion,
            section.explanation,
        )
        raw: tuple[object, ...] = (
            section.section_index,
            section.section_name,
            section.file_offset,
            section.declared_size,
            -1.0 if section.entropy is None else section.entropy,
            section.color,
            suspicion,
            section.explanation,
        )
        if role == Qt.ItemDataRole.DisplayRole:
            return display[index.column()]
        if role == Qt.ItemDataRole.UserRole:
            return raw[index.column()]
        if role == Qt.ItemDataRole.ForegroundRole and index.column() in {5, 6}:
            return _COLOR_VALUES[section.color]
        if role == Qt.ItemDataRole.BackgroundRole and section.suspicious:
            return QColor("#3a2229")
        if role == Qt.ItemDataRole.ToolTipRole:
            return section.explanation
        return None


OVERLAY_HEADERS = ("File Offset", "Size", "End Offset")


class OverlayRegionModel(QAbstractTableModel):
    """Physical file ranges classified as overlay data."""

    def __init__(self) -> None:
        super().__init__()
        self._regions: tuple[OverlayRegion, ...] = ()

    def set_regions(self, regions: Sequence[OverlayRegion]) -> None:
        self.beginResetModel()
        self._regions = tuple(regions)
        self.endResetModel()

    def region(self, row: int) -> OverlayRegion | None:
        if 0 <= row < len(self._regions):
            return self._regions[row]
        return None

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._regions)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(OVERLAY_HEADERS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object | None:
        if (
            orientation == Qt.Orientation.Horizontal
            and role == Qt.ItemDataRole.DisplayRole
            and 0 <= section < len(OVERLAY_HEADERS)
        ):
            return OVERLAY_HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = 0) -> object | None:
        region = self.region(index.row())
        if region is None or not index.isValid():
            return None
        raw = (region.file_offset, region.size, region.end_offset)
        if role == Qt.ItemDataRole.DisplayRole:
            return (
                format_hex(region.file_offset),
                f"{format_size(region.size)} ({region.size} bytes)",
                format_hex(region.end_offset),
            )[index.column()]
        if role == Qt.ItemDataRole.UserRole:
            return raw[index.column()]
        return None


class KeyValueTableModel(QAbstractTableModel):
    """Small reusable two-column details model."""

    def __init__(self) -> None:
        super().__init__()
        self._rows: tuple[tuple[str, str], ...] = ()

    def set_rows(self, rows: Sequence[tuple[str, object]]) -> None:
        self.beginResetModel()
        self._rows = tuple(
            (label, "Unavailable" if value is None else str(value))
            for label, value in rows
        )
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else 2

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object | None:
        if (
            orientation == Qt.Orientation.Horizontal
            and role == Qt.ItemDataRole.DisplayRole
        ):
            return ("Field", "Value")[section] if 0 <= section < 2 else None
        return None

    def data(self, index: QModelIndex, role: int = 0) -> object | None:
        if not index.isValid() or not 0 <= index.row() < len(self._rows):
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            return self._rows[index.row()][index.column()]
        if role == Qt.ItemDataRole.ToolTipRole:
            return self._rows[index.row()][1]
        return None


class FileAnalysisWidget(QWidget):
    """Nested analysis views that remain compact at portfolio-tool scale."""

    fileOffsetNavigationRequested = Signal(int, int)

    def __init__(self) -> None:
        super().__init__()
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        self.entropy_model = EntropyTableModel()
        self.entropy_proxy = QSortFilterProxyModel(self)
        self.entropy_proxy.setSourceModel(self.entropy_model)
        self.entropy_proxy.setSortRole(Qt.ItemDataRole.UserRole)
        self.entropy_table = self._table(self.entropy_proxy)
        self.entropy_table.setSortingEnabled(True)
        self.entropy_table.horizontalHeader().setSectionResizeMode(
            7,
            QHeaderView.ResizeMode.Stretch,
        )
        self.entropy_table.setColumnWidth(0, 45)
        self.entropy_table.setColumnWidth(1, 110)
        self.entropy_table.setColumnWidth(2, 120)
        self.entropy_table.setColumnWidth(3, 110)
        self.entropy_table.setColumnWidth(4, 90)
        self.entropy_table.setColumnWidth(5, 100)
        self.entropy_table.setColumnWidth(6, 125)
        self.entropy_table.selectionModel().currentChanged.connect(
            self._navigate_entropy
        )
        install_table_actions(
            self.entropy_table,
            {"Copy file offset": 2},
        )
        self.tabs.addTab(self.entropy_table, "Entropy")

        self.overlay_label = QLabel("Overlay analysis unavailable")
        self.overlay_label.setObjectName("riskBanner")
        self.overlay_label.setWordWrap(True)
        self.overlay_model = OverlayRegionModel()
        self.overlay_table = self._table(self.overlay_model)
        self.overlay_table.selectionModel().currentChanged.connect(
            self._navigate_overlay
        )
        install_table_actions(
            self.overlay_table,
            {"Copy file offset": 0},
        )
        overlay_page = QWidget()
        overlay_layout = QVBoxLayout(overlay_page)
        overlay_layout.setContentsMargins(8, 8, 8, 8)
        overlay_layout.addWidget(self.overlay_label)
        overlay_layout.addWidget(self.overlay_table)
        self.tabs.addTab(overlay_page, "Overlay")

        self.hash_model, self.hash_table, hash_page = self._details_page()
        self.tabs.addTab(hash_page, "Hashes")
        self.certificate_model, self.certificate_table, certificate_page = (
            self._details_page()
        )
        self.tabs.addTab(certificate_page, "Digital Signature")
        self.version_model, self.version_table, version_page = self._details_page()
        self.tabs.addTab(version_page, "Version Information")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.tabs)

    def set_results(
        self,
        file_analysis: FileAnalysis,
        certificate: CertificateAnalysis,
        version: VersionInformation,
    ) -> None:
        self.entropy_model.set_sections(file_analysis.sections)
        self.entropy_table.sortByColumn(0, Qt.SortOrder.AscendingOrder)

        overlay = file_analysis.overlay
        level = getattr(
            overlay,
            "suspicion_level",
            "Review" if overlay.present else "None",
        )
        overlay_offset = (
            format_hex(overlay.start_offset)
            if overlay.start_offset is not None
            else "N/A"
        )
        self.overlay_label.setText(
            f"Overlay: {'Present' if overlay.present else 'Absent'}  |  "
            f"Offset: {overlay_offset}"
            f"  |  Size: {format_size(overlay.total_size)}  |  "
            f"Suspicion: {level}\n{overlay.explanation}"
        )
        risk = (
            "high"
            if level == "High"
            else "medium"
            if overlay.present
            else "low"
        )
        self.overlay_label.setProperty("risk", risk)
        self.overlay_label.style().unpolish(self.overlay_label)
        self.overlay_label.style().polish(self.overlay_label)
        self.overlay_model.set_regions(overlay.regions)

        hashes = file_analysis.hashes
        self.hash_model.set_rows(
            (
                ("MD5", hashes.md5),
                ("SHA-1", hashes.sha1),
                ("SHA-256", hashes.sha256),
                ("SHA-512", hashes.sha512),
            )
        )
        self.certificate_model.set_rows(
            (
                ("Present", "Yes" if certificate.present else "No"),
                ("Parsed", "Yes" if certificate.parsed else "No"),
                ("Subject", certificate.subject),
                ("Issuer", certificate.issuer),
                ("Timestamp", certificate.signing_timestamp),
                ("Thumbprint (SHA-1)", certificate.sha1_thumbprint),
                ("Signature Algorithm", certificate.signature_algorithm),
                ("Valid From", certificate.valid_from),
                ("Valid Until", certificate.valid_to),
                ("Availability", certificate.unavailable_reason or "Available"),
                ("Trust", certificate.trust_statement),
            )
        )
        self.version_model.set_rows(
            (
                ("Company Name", version.company_name),
                ("Product Name", version.product_name),
                ("File Description", version.file_description),
                ("Product Version", version.product_version),
                ("File Version", version.file_version),
                ("Original Filename", version.original_filename),
                ("Copyright", version.legal_copyright),
                ("Fixed Product Version", version.fixed_product_version),
                ("Fixed File Version", version.fixed_file_version),
                ("Availability", version.unavailable_reason or "Available"),
            )
        )

    def clear_results(self) -> None:
        self.entropy_model.set_sections(())
        self.overlay_model.set_regions(())
        self.overlay_label.setText("Overlay analysis unavailable")
        self.overlay_label.setProperty("risk", "none")
        self.overlay_label.style().unpolish(self.overlay_label)
        self.overlay_label.style().polish(self.overlay_label)
        self.hash_model.set_rows(())
        self.certificate_model.set_rows(())
        self.version_model.set_rows(())

    def _navigate_entropy(
        self,
        current: QModelIndex,
        previous: QModelIndex = QModelIndex(),
    ) -> None:
        del previous
        source = self.entropy_proxy.mapToSource(current)
        section = self.entropy_model.section(source.row())
        if section is not None and section.analyzed_size:
            self.fileOffsetNavigationRequested.emit(
                section.file_offset,
                section.analyzed_size,
            )

    def _navigate_overlay(
        self,
        current: QModelIndex,
        previous: QModelIndex = QModelIndex(),
    ) -> None:
        del previous
        region = self.overlay_model.region(current.row())
        if region is not None:
            self.fileOffsetNavigationRequested.emit(
                region.file_offset,
                region.size,
            )

    @staticmethod
    def _table(model: QAbstractItemModel) -> QTableView:
        table = QTableView()
        table.setModel(model)
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

    def _details_page(
        self,
    ) -> tuple[KeyValueTableModel, QTableView, QWidget]:
        model = KeyValueTableModel()
        table = self._table(model)
        table.horizontalHeader().setSectionResizeMode(
            1,
            QHeaderView.ResizeMode.Stretch,
        )
        table.setColumnWidth(0, 190)
        controller = install_table_actions(table)
        copy_button = QPushButton("Copy selected value")
        copy_button.clicked.connect(lambda: controller.copy_column_value(1))
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.addWidget(table)
        layout.addWidget(copy_button, 0, Qt.AlignmentFlag.AlignRight)
        return model, table, page


__all__ = [
    "EntropyTableModel",
    "FileAnalysisWidget",
    "KeyValueTableModel",
    "OverlayRegionModel",
]
