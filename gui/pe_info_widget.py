"""Widgets responsible for presenting parsed PE structures."""

from collections.abc import Mapping, Sequence
from typing import cast

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFontDatabase
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QStyle,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
)

from gui.analysis_widget import AnalysisWidget
from gui.data_directories_widget import DataDirectoriesWidget
from gui.exports_widget import ExportsWidget
from gui.file_analysis_widget import FileAnalysisWidget
from gui.formatters import (
    SECTION_FIELDS,
    STANDARD_OPTIONAL_FIELDS,
    WINDOWS_OPTIONAL_FIELDS,
    format_optional_value,
    format_section_value,
    format_summary,
    section_characteristics_tooltip,
)
from gui.imports_widget import ImportsWidget
from gui.hex_widget import HexWidget
from gui.resources_widget import ResourcesWidget
from gui.search_widget import SearchWidget
from gui.strings_widget import StringsWidget
from gui.table_actions import install_table_actions
from pe.addressing import AddressingService
from pe.document import PEInspectionDocument
from pe.errors import PEFormatError
from pe.file_analysis import SectionEntropy
from pe.models import (
    DataDirectoryInfo,
    ExportDirectoryInfo,
    ImportDescriptorInfo,
    PEInfo,
    ResourceNodeInfo,
    SecurityAnalysisInfo,
)
from utils.file_utils import format_hex


_NAVIGATION_OFFSET_ROLE = int(Qt.ItemDataRole.UserRole) + 10
_NAVIGATION_LENGTH_ROLE = _NAVIGATION_OFFSET_ROLE + 1

_PE32_OPTIONAL_LAYOUT: dict[str, tuple[int, int]] = {
    "magic": (0, 2),
    "major_linker_version": (2, 1),
    "minor_linker_version": (3, 1),
    "size_of_code": (4, 4),
    "size_of_initialized_data": (8, 4),
    "size_of_uninitialized_data": (12, 4),
    "address_of_entry_point": (16, 4),
    "base_of_code": (20, 4),
    "base_of_data": (24, 4),
    "image_base": (28, 4),
    "section_alignment": (32, 4),
    "file_alignment": (36, 4),
    "major_operating_system_version": (40, 2),
    "minor_operating_system_version": (42, 2),
    "major_image_version": (44, 2),
    "minor_image_version": (46, 2),
    "major_subsystem_version": (48, 2),
    "minor_subsystem_version": (50, 2),
    "win32_version_value": (52, 4),
    "size_of_image": (56, 4),
    "size_of_headers": (60, 4),
    "checksum": (64, 4),
    "subsystem": (68, 2),
    "dll_characteristics": (70, 2),
    "size_of_stack_reserve": (72, 4),
    "size_of_stack_commit": (76, 4),
    "size_of_heap_reserve": (80, 4),
    "size_of_heap_commit": (84, 4),
    "loader_flags": (88, 4),
    "number_of_rva_and_sizes": (92, 4),
}

_PE32_PLUS_OPTIONAL_LAYOUT = {
    **{
        key: value
        for key, value in _PE32_OPTIONAL_LAYOUT.items()
        if key != "base_of_data"
    },
    "image_base": (24, 8),
    "size_of_stack_reserve": (72, 8),
    "size_of_stack_commit": (80, 8),
    "size_of_heap_reserve": (88, 8),
    "size_of_heap_commit": (96, 8),
    "loader_flags": (104, 4),
    "number_of_rva_and_sizes": (108, 4),
}


class PEInfoWidget(QTabWidget):
    """Tabbed view for every parsed PE structure and analysis result."""

    fileOffsetNavigationRequested = Signal(int, int)

    def __init__(self) -> None:
        super().__init__()
        self._addressing: AddressingService | None = None
        self._current_info: PEInfo | None = None

        self.summary_output = QTextEdit()
        self.summary_output.setReadOnly(True)
        self.summary_output.setFont(
            QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        )

        self.optional_tree = self._create_optional_tree()
        self.sections_table = self._create_sections_table()
        self.imports_widget = ImportsWidget()
        self.exports_widget = ExportsWidget()
        self.resources_widget = ResourcesWidget()
        self.data_directories_widget = DataDirectoriesWidget()
        self.analysis_widget = AnalysisWidget()
        self.hex_widget = HexWidget()
        self.search_widget = SearchWidget()
        self.strings_widget = StringsWidget()
        self.file_analysis_widget = FileAnalysisWidget()

        self.setDocumentMode(True)
        self.setUsesScrollButtons(True)
        self.setElideMode(Qt.TextElideMode.ElideRight)
        self._add_tabs()
        self._connect_navigation()
        install_table_actions(self.optional_tree)
        install_table_actions(
            self.sections_table,
            {
                "Copy RVA": 4,
                "Copy file offset": 6,
            },
        )

    def set_document(self, document: PEInspectionDocument) -> None:
        """Display one precomputed inspection document without reparsing it."""

        self.set_information(document.structural_info, document.addressing)
        self.hex_widget.set_image(
            document.data,
            document.image.optional_header,
            document.image.sections,
        )
        self.search_widget.set_service(document.search)
        self.strings_widget.set_strings(
            document.strings,
            truncated=document.strings_truncated,
            limit=document.string_limit,
        )
        self.file_analysis_widget.set_results(
            document.file_analysis,
            document.certificate,
            document.version_information,
        )
        self._apply_entropy_highlights(document.file_analysis.sections)

    def set_information(
        self,
        info: PEInfo,
        addressing: AddressingService | None = None,
    ) -> None:
        """Replace every view with data from a newly parsed image."""

        self._clear_derived_views()
        self._current_info = info
        self._addressing = addressing
        self.summary_output.setPlainText(format_summary(info))
        self._populate_optional_header(info)
        self._populate_sections(info)
        imports = cast(Mapping[str, object], info).get("imports", [])
        import_directory_rva = next(
            (
                directory["virtual_address"]
                for directory in info["optional_header"]["data_directories"]
                if directory["index"] == 1
            ),
            0,
        )
        self.imports_widget.set_imports(
            cast(Sequence[ImportDescriptorInfo], imports),
            info["optional_header"]["format"],
            import_directory_rva or None,
        )
        values = cast(Mapping[str, object], info)
        self.exports_widget.set_exports(
            cast(ExportDirectoryInfo | None, values.get("exports"))
        )
        self.resources_widget.set_resource(
            cast(ResourceNodeInfo | None, values.get("resources"))
        )
        directories = values.get(
            "data_directories",
            info["optional_header"]["data_directories"],
        )
        self.data_directories_widget.set_directories(
            cast(Sequence[DataDirectoryInfo], directories)
        )
        self.analysis_widget.set_analysis(
            cast(SecurityAnalysisInfo | None, values.get("analysis"))
        )

    def clear_information(self) -> None:
        """Clear all views."""

        self.summary_output.clear()
        self._current_info = None
        self._addressing = None
        self.optional_tree.clear()
        self.sections_table.setRowCount(0)
        self.imports_widget.clear_imports()
        self.exports_widget.clear_exports()
        self.resources_widget.clear_resource()
        self.data_directories_widget.clear_directories()
        self.analysis_widget.clear_analysis()

        self._clear_derived_views()

    def _clear_derived_views(self) -> None:
        """Clear document-only views while preserving structural widgets."""

        self.hex_widget.clear()
        self.search_widget.clear()
        self.strings_widget.clear()
        self.file_analysis_widget.clear_results()

    def focus_search(self) -> None:
        """Activate and focus the global-search controls."""

        self.setCurrentWidget(self.search_widget)
        self.search_widget.focus_search()

    def focus_hex_jump(self) -> None:
        """Activate the Hex tab and focus its address field."""

        self.setCurrentWidget(self.hex_widget)
        self.hex_widget.address_input.setFocus(Qt.FocusReason.ShortcutFocusReason)
        self.hex_widget.address_input.selectAll()

    def _add_tabs(self) -> None:
        """Add stable tabs with platform-native icons."""

        tabs = (
            (
                self.summary_output,
                QStyle.StandardPixmap.SP_FileDialogInfoView,
                "Overview",
            ),
            (
                self.optional_tree,
                QStyle.StandardPixmap.SP_FileDialogDetailedView,
                "Optional Header",
            ),
            (
                self.sections_table,
                QStyle.StandardPixmap.SP_DirIcon,
                "Sections",
            ),
            (
                self.imports_widget,
                QStyle.StandardPixmap.SP_ArrowDown,
                "Imports",
            ),
            (
                self.exports_widget,
                QStyle.StandardPixmap.SP_ArrowUp,
                "Exports",
            ),
            (
                self.resources_widget,
                QStyle.StandardPixmap.SP_DirOpenIcon,
                "Resources",
            ),
            (
                self.data_directories_widget,
                QStyle.StandardPixmap.SP_DriveHDIcon,
                "Data Directories",
            ),
            (
                self.analysis_widget,
                QStyle.StandardPixmap.SP_MessageBoxWarning,
                "Analysis",
            ),
            (
                self.hex_widget,
                QStyle.StandardPixmap.SP_FileDialogDetailedView,
                "Hex",
            ),
            (
                self.search_widget,
                QStyle.StandardPixmap.SP_FileDialogContentsView,
                "Search",
            ),
            (
                self.strings_widget,
                QStyle.StandardPixmap.SP_FileDialogListView,
                "Strings",
            ),
            (
                self.file_analysis_widget,
                QStyle.StandardPixmap.SP_ComputerIcon,
                "File Analysis",
            ),
        )
        for widget, pixmap, label in tabs:
            self.addTab(widget, self.style().standardIcon(pixmap), label)

    def _connect_navigation(self) -> None:
        self.optional_tree.currentItemChanged.connect(
            self._navigate_optional_item
        )
        self.sections_table.currentCellChanged.connect(
            self._navigate_section_header
        )
        self.imports_widget.rvaNavigationRequested.connect(
            self._navigate_rva
        )
        self.exports_widget.rvaNavigationRequested.connect(
            self._navigate_rva
        )
        self.resources_widget.fileOffsetNavigationRequested.connect(
            self.fileOffsetNavigationRequested.emit
        )
        self.data_directories_widget.addressNavigationRequested.connect(
            self._navigate_directory_address
        )
        self.fileOffsetNavigationRequested.connect(self._navigate_hex_offset)
        self.search_widget.fileOffsetNavigationRequested.connect(
            self._activate_hex_offset
        )
        self.strings_widget.fileOffsetNavigationRequested.connect(
            self._navigate_hex_offset
        )
        self.strings_widget.table.doubleClicked.connect(
            lambda index: self.setCurrentWidget(self.hex_widget)
        )
        self.file_analysis_widget.fileOffsetNavigationRequested.connect(
            self._navigate_hex_offset
        )
        self.file_analysis_widget.entropy_table.doubleClicked.connect(
            lambda index: self.setCurrentWidget(self.hex_widget)
        )
        self.file_analysis_widget.overlay_table.doubleClicked.connect(
            lambda index: self.setCurrentWidget(self.hex_widget)
        )

    def _navigate_optional_item(
        self,
        current: QTreeWidgetItem | None,
        previous: QTreeWidgetItem | None,
    ) -> None:
        del previous
        if current is None:
            return
        offset = current.data(0, _NAVIGATION_OFFSET_ROLE)
        length = current.data(0, _NAVIGATION_LENGTH_ROLE)
        if isinstance(offset, int) and isinstance(length, int):
            self.fileOffsetNavigationRequested.emit(offset, max(1, length))

    def _navigate_section_header(
        self,
        current_row: int,
        current_column: int,
        previous_row: int,
        previous_column: int,
    ) -> None:
        del current_column, previous_row, previous_column
        info = self._current_info
        if info is None or not 0 <= current_row < len(info["sections"]):
            return
        section_table_offset = (
            info["pe_offset"]
            + 4
            + 20
            + info["coff_header"]["optional_header_size"]
        )
        self.fileOffsetNavigationRequested.emit(
            section_table_offset + current_row * 40,
            40,
        )

    def _navigate_rva(self, rva: int, length: int) -> None:
        if self._addressing is None:
            return
        try:
            offset = self._addressing.rva_to_file_offset(rva, max(1, length))
        except (PEFormatError, ValueError):
            try:
                offset = self._addressing.rva_to_file_offset(rva, 1)
            except (PEFormatError, ValueError):
                return
            length = 1
        self.fileOffsetNavigationRequested.emit(offset, max(1, length))

    def _navigate_directory_address(
        self,
        kind: str,
        address: int,
        length: int,
    ) -> None:
        if kind == "file_offset":
            self.fileOffsetNavigationRequested.emit(address, max(1, length))
        elif kind == "rva":
            self._navigate_rva(address, length)

    def _navigate_hex_offset(self, offset: int, length: int) -> None:
        """Synchronize a parser selection with the virtualized Hex model."""

        self.hex_widget.navigate_to_offset(offset, max(1, length))

    def _activate_hex_offset(self, offset: int, length: int) -> None:
        """Navigate to a result and make the Hex view visible."""

        if self.hex_widget.navigate_to_offset(offset, max(1, length)):
            self.setCurrentWidget(self.hex_widget)

    @staticmethod
    def _create_optional_tree() -> QTreeWidget:
        tree = QTreeWidget()
        tree.setHeaderLabels(["Field", "Value"])
        tree.setAlternatingRowColors(True)
        tree.setUniformRowHeights(True)
        tree.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        return tree

    @staticmethod
    def _create_sections_table() -> QTableWidget:
        table = QTableWidget(0, len(SECTION_FIELDS))
        table.setHorizontalHeaderLabels([label for label, _ in SECTION_FIELDS])
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setSortingEnabled(False)
        table.setWordWrap(False)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive
        )

        widths = (45, 100, 175, 105, 115, 120, 130, 145, 150, 145, 145, 120)
        for column, width in enumerate(widths):
            table.setColumnWidth(column, width)
        return table

    def _populate_optional_header(self, info: PEInfo) -> None:
        header = info["optional_header"]
        header_values = cast(Mapping[str, object], header)
        self.optional_tree.clear()
        optional_offset = info["pe_offset"] + 4 + 20
        optional_size = info["coff_header"]["optional_header_size"]
        layout = (
            _PE32_PLUS_OPTIONAL_LAYOUT
            if header["format"] == "PE32+"
            else _PE32_OPTIONAL_LAYOUT
        )
        fixed_size = 112 if header["format"] == "PE32+" else 96

        standard_group = QTreeWidgetItem(
            self.optional_tree,
            ["Standard fields", header["format"]],
        )
        self._set_navigation_data(
            standard_group,
            optional_offset,
            min(fixed_size, optional_size),
        )
        for label, field, style in STANDARD_OPTIONAL_FIELDS:
            value = header_values[field]
            if value is None:
                continue
            item = QTreeWidgetItem(
                standard_group,
                [
                    label,
                    format_optional_value(field, int(value), style, header),
                ],
            )
            relative_offset, field_size = layout[field]
            self._set_navigation_data(
                item,
                optional_offset + relative_offset,
                field_size,
            )

        windows_group = QTreeWidgetItem(
            self.optional_tree,
            ["Windows-specific fields", ""],
        )
        self._set_navigation_data(
            windows_group,
            optional_offset,
            min(fixed_size, optional_size),
        )
        for label, field, style in WINDOWS_OPTIONAL_FIELDS:
            value = header_values[field]
            item = QTreeWidgetItem(
                windows_group,
                [
                    label,
                    format_optional_value(field, int(value), style, header),
                ],
            )
            relative_offset, field_size = layout[field]
            self._set_navigation_data(
                item,
                optional_offset + relative_offset,
                field_size,
            )

        directories = header["data_directories"]
        directories_group = QTreeWidgetItem(
            self.optional_tree,
            ["Data directories", f"{len(directories)} entries"],
        )
        directory_bytes = max(0, optional_size - fixed_size)
        self._set_navigation_data(
            directories_group,
            optional_offset + fixed_size,
            directory_bytes,
        )
        if not directories:
            QTreeWidgetItem(directories_group, ["(none)", ""])

        for directory in directories:
            directory_item = QTreeWidgetItem(
                directories_group,
                [f"[{directory['index']:02d}] {directory['name']}", ""],
            )
            entry_offset = (
                optional_offset + fixed_size + directory["index"] * 8
            )
            self._set_navigation_data(directory_item, entry_offset, 8)
            address_item = QTreeWidgetItem(
                directory_item,
                ["VirtualAddress", format_hex(directory["virtual_address"])],
            )
            self._set_navigation_data(address_item, entry_offset, 4)
            size_item = QTreeWidgetItem(
                directory_item,
                ["Size", format_hex(directory["size"])],
            )
            self._set_navigation_data(size_item, entry_offset + 4, 4)
            status_item = QTreeWidgetItem(
                directory_item,
                ["Status", directory["status"]],
            )
            self._set_navigation_data(status_item, entry_offset, 8)

        self.optional_tree.expandAll()

    @staticmethod
    def _set_navigation_data(
        item: QTreeWidgetItem,
        offset: int,
        length: int,
    ) -> None:
        item.setData(0, _NAVIGATION_OFFSET_ROLE, offset)
        item.setData(0, _NAVIGATION_LENGTH_ROLE, length)

    def _populate_sections(self, info: PEInfo) -> None:
        sections = info["sections"]
        self.sections_table.setRowCount(len(sections))

        for row, section in enumerate(sections):
            for column, (_, field) in enumerate(SECTION_FIELDS):
                item = QTableWidgetItem(format_section_value(field, section))
                item.setTextAlignment(
                    Qt.AlignmentFlag.AlignVCenter
                    | (
                        Qt.AlignmentFlag.AlignLeft
                        if field in {"name", "raw_name"}
                        else Qt.AlignmentFlag.AlignRight
                    )
                )
                if field == "characteristics":
                    item.setToolTip(
                        section_characteristics_tooltip(
                            section["characteristics"]
                        )
                    )
                self.sections_table.setItem(row, column, item)

    def _apply_entropy_highlights(
        self,
        sections: Sequence[SectionEntropy],
    ) -> None:
        """Annotate structural section rows with entropy evidence."""

        for row, section in enumerate(sections):
            if row >= self.sections_table.rowCount():
                break
            suspicious = section.suspicious
            color_name = section.color
            explanation = section.explanation
            background = (
                QColor("#3a2229")
                if suspicious
                else QColor("#3a3120")
                if color_name == "amber"
                else QColor()
            )
            for column in range(self.sections_table.columnCount()):
                item = self.sections_table.item(row, column)
                if item is None:
                    continue
                if background.isValid():
                    item.setBackground(background)
                if explanation:
                    existing = item.toolTip()
                    item.setToolTip(
                        f"{existing}\n\n{explanation}" if existing else explanation
                    )
