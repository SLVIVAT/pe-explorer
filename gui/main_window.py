"""Main application window, asynchronous loading, and usability workflows."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from PySide6.QtCore import QSettings, QSize, QThreadPool, Qt
from PySide6.QtGui import (
    QDragEnterEvent,
    QDropEvent,
    QKeySequence,
    QShortcut,
)
from PySide6.QtWidgets import (
    QFileDialog,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QStatusBar,
    QStyle,
    QToolBar,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from gui.pe_info_widget import PEInfoWidget
from gui.workers import BackgroundTask
from pe.document import PEInspectionDocument
from pe.models import PEInfo


class MainWindow(QMainWindow):
    """Responsive top-level shell for professional PE inspection."""

    _RECENT_FILES_KEY = "recent_files"
    _MAX_RECENT_FILES = 10

    def __init__(self) -> None:
        super().__init__()
        self.current_document: PEInspectionDocument | None = None
        self._thread_pool = QThreadPool.globalInstance()
        self._load_generation = 0
        self._load_tasks: dict[int, BackgroundTask] = {}
        self._settings = QSettings("PE Explorer", "PE Explorer")
        self._shortcuts: list[QShortcut] = []

        self.setWindowTitle("PE Explorer")
        self.resize(1440, 900)
        self.setMinimumSize(960, 640)
        self.setAcceptDrops(True)

        self._create_toolbar()
        self._create_central_widget()
        self._create_statusbar()
        self._create_shortcuts()
        self._rebuild_recent_menu()

    def _create_toolbar(self) -> None:
        toolbar = QToolBar("Main Toolbar")
        toolbar.setObjectName("mainToolbar")
        toolbar.setMovable(False)
        toolbar.setFloatable(False)
        toolbar.setIconSize(QSize(18, 18))
        self.addToolBar(toolbar)

        self.open_button = QPushButton("Open PE File")
        self.open_button.setIcon(
            self.style().standardIcon(
                QStyle.StandardPixmap.SP_DialogOpenButton
            )
        )
        self.open_button.setToolTip("Open a PE file (Ctrl+O)")
        self.open_button.clicked.connect(self.open_file)
        toolbar.addWidget(self.open_button)

        self.recent_button = QToolButton()
        self.recent_button.setText("Recent")
        self.recent_button.setPopupMode(
            QToolButton.ToolButtonPopupMode.InstantPopup
        )
        self.recent_menu = QMenu(self.recent_button)
        self.recent_button.setMenu(self.recent_menu)
        toolbar.addWidget(self.recent_button)

        self.search_button = QPushButton("Search")
        self.search_button.setIcon(
            self.style().standardIcon(
                QStyle.StandardPixmap.SP_FileDialogContentsView
            )
        )
        self.search_button.setToolTip("Open global search (Ctrl+F)")
        self.search_button.setEnabled(False)
        self.search_button.clicked.connect(self._focus_search)
        toolbar.addWidget(self.search_button)

        self.report_button = QPushButton("Generate Report")
        self.report_button.setIcon(
            self.style().standardIcon(
                QStyle.StandardPixmap.SP_DialogSaveButton
            )
        )
        self.report_button.setToolTip(
            "Generate HTML, JSON, or Markdown report (Ctrl+Shift+S)"
        )
        self.report_button.setEnabled(False)
        self.report_button.clicked.connect(self.generate_report)
        toolbar.addWidget(self.report_button)

        toolbar.addSeparator()
        title = QLabel("Portable Executable Inspector")
        title.setObjectName("toolbarTitle")
        toolbar.addWidget(title)

        spacer = QWidget()
        spacer.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Preferred,
        )
        toolbar.addWidget(spacer)

    def _create_central_widget(self) -> None:
        self.info_label = QLabel(
            "Drop an executable here or open a file to begin."
        )
        self.info_label.setObjectName("filePathLabel")
        self.info_label.setAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        self.info_label.setWordWrap(True)

        self.pe_info = PEInfoWidget()
        # Preserve the original public summary-widget attribute.
        self.output = self.pe_info.summary_output

        layout = QVBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(9)
        layout.addWidget(self.info_label)
        layout.addWidget(self.pe_info, 1)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def _create_statusbar(self) -> None:
        status = QStatusBar()
        status.setSizeGripEnabled(False)
        status.showMessage("Ready")

        self.loading_progress = QProgressBar()
        self.loading_progress.setRange(0, 0)
        self.loading_progress.setFixedWidth(110)
        self.loading_progress.setTextVisible(False)
        self.loading_progress.hide()
        status.addPermanentWidget(self.loading_progress)

        self.status_details = QLabel("No image loaded")
        status.addPermanentWidget(self.status_details)
        self.setStatusBar(status)

    def _create_shortcuts(self) -> None:
        bindings = (
            (QKeySequence.StandardKey.Open, self.open_file),
            (QKeySequence.StandardKey.Find, self._focus_search),
            (QKeySequence("Ctrl+G"), self._focus_hex_jump),
            (QKeySequence("Ctrl+Shift+S"), self.generate_report),
        )
        for sequence, callback in bindings:
            shortcut = QShortcut(sequence, self)
            shortcut.activated.connect(callback)
            self._shortcuts.append(shortcut)

    def open_file(self) -> None:
        if self._load_tasks:
            self.statusBar().showMessage(
                "A PE file is already loading; please wait for it to finish."
            )
            return
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Open PE File",
            "",
            (
                "PE Files (*.exe *.dll *.sys *.ocx *.cpl *.pyd *.mui);;"
                "All Files (*)"
            ),
        )
        if filename:
            self.load_file(filename)

    def load_file(self, file_path: str | Path) -> None:
        """Begin non-blocking parsing and analysis of one path."""

        if self._load_tasks:
            self.statusBar().showMessage(
                "A PE file is already loading; additional load ignored."
            )
            return
        path = Path(file_path)
        if not path.is_file():
            self._show_error(
                "File Not Found",
                f"The selected path is not a readable file:\n{path}",
            )
            return

        self._load_generation += 1
        generation = self._load_generation
        task = BackgroundTask(
            generation,
            lambda progress: PEInspectionDocument.load(
                path,
                progress=progress,
            ),
        )
        task.signals.progress.connect(self._on_load_progress)
        task.signals.succeeded.connect(self._on_load_succeeded)
        task.signals.failed.connect(self._on_load_failed)
        task.signals.finished.connect(self._on_load_finished)
        self._load_tasks[generation] = task

        self.open_button.setEnabled(False)
        self.loading_progress.show()
        self.statusBar().showMessage(f"Loading {path.name}…")
        self.info_label.setText(f"Loading: {path}")
        self.info_label.setToolTip(str(path))
        self._thread_pool.start(task)

    def _on_load_progress(self, generation: int, message: str) -> None:
        if generation == self._load_generation:
            self.statusBar().showMessage(message)

    def _on_load_succeeded(self, generation: int, result: object) -> None:
        if generation != self._load_generation:
            return
        document = cast(PEInspectionDocument, result)
        self.show_document(document)
        self._add_recent_file(document.path)
        self.statusBar().showMessage("PE inspection completed", 5000)

    def _on_load_failed(
        self,
        generation: int,
        message: str,
        details: str,
    ) -> None:
        if generation != self._load_generation:
            return
        self.info_label.setText(
            str(self.current_document.path)
            if self.current_document is not None
            else "No file selected"
        )
        self.statusBar().showMessage("Unable to inspect selected file")
        self._show_error(
            "Unable to Open PE File",
            message or "The selected file could not be inspected.",
            details,
        )

    def _on_load_finished(self, generation: int) -> None:
        self._load_tasks.pop(generation, None)
        if generation == self._load_generation:
            self.open_button.setEnabled(True)
            self.loading_progress.hide()

    def show_document(self, document: PEInspectionDocument) -> None:
        """Display a completed immutable inspection document."""

        self.current_document = document
        self.pe_info.set_document(document)
        self.info_label.setText(str(document.path))
        self.info_label.setToolTip(str(document.path))
        self.report_button.setEnabled(True)
        self.search_button.setEnabled(True)
        self._update_status(document.structural_info)

    def show_pe_information(self, info: PEInfo) -> None:
        """Preserve the legacy dictionary display API."""

        self.current_document = None
        self.pe_info.set_information(info)
        self.report_button.setEnabled(False)
        self.search_button.setEnabled(False)
        self._update_status(info)

    def _update_status(self, info: PEInfo) -> None:
        imports = info.get("imports", [])
        imported_functions = sum(
            len(descriptor["functions"]) for descriptor in imports
        )
        exports = info.get("exports")
        exported_functions = (
            sum(function["rva"] != 0 for function in exports["functions"])
            if exports is not None
            else 0
        )
        analysis = info.get("analysis")
        risk = analysis["overall_risk"] if analysis is not None else "N/A"
        file_size = int(info.get("file_size", 0))
        self.status_details.setText(
            "  •  ".join(
                (
                    info["optional_header"]["format"],
                    f"{file_size:,} bytes",
                    f"{len(info['sections'])} sections",
                    f"{imported_functions} imports",
                    f"{exported_functions} exports",
                    f"Risk {risk}",
                )
            )
        )

    def generate_report(self) -> None:
        document = self.current_document
        if document is None:
            self.statusBar().showMessage("Load a PE file before generating a report")
            return

        default_path = document.path.with_name(
            f"{document.path.stem}-report.html"
        )
        filename, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Generate PE Report",
            str(default_path),
            (
                "HTML Report (*.html);;JSON Report (*.json);;"
                "Markdown Report (*.md)"
            ),
        )
        if not filename:
            return

        output = Path(filename)
        report_format = (
            "json"
            if selected_filter.startswith("JSON")
            else "markdown"
            if selected_filter.startswith("Markdown")
            else "html"
        )
        if not output.suffix:
            suffix = (
                ".json"
                if report_format == "json"
                else ".md"
                if report_format == "markdown"
                else ".html"
            )
            output = output.with_suffix(suffix)
        try:
            document.report_generator().write(output, report_format)
        except Exception as error:
            self._show_error(
                "Report Generation Failed",
                str(error),
            )
            return
        self.statusBar().showMessage(f"Report saved to {output}", 7000)

    def _focus_search(self) -> None:
        focus = getattr(self.pe_info, "focus_search", None)
        if callable(focus):
            focus()

    def _focus_hex_jump(self) -> None:
        focus = getattr(self.pe_info, "focus_hex_jump", None)
        if callable(focus):
            focus()

    def _recent_files(self) -> list[str]:
        value = self._settings.value(self._RECENT_FILES_KEY, [])
        if isinstance(value, str):
            return [value]
        if isinstance(value, (list, tuple)):
            return [str(item) for item in value if str(item)]
        return []

    def _add_recent_file(self, path: Path) -> None:
        normalized = str(path.resolve())
        recent = [
            item for item in self._recent_files() if item != normalized
        ]
        recent.insert(0, normalized)
        self._settings.setValue(
            self._RECENT_FILES_KEY,
            recent[: self._MAX_RECENT_FILES],
        )
        self._rebuild_recent_menu()

    def _rebuild_recent_menu(self) -> None:
        self.recent_menu.clear()
        existing = [
            path for path in self._recent_files() if Path(path).is_file()
        ]
        if not existing:
            empty = self.recent_menu.addAction("No recent files")
            empty.setEnabled(False)
        else:
            for path in existing:
                action = self.recent_menu.addAction(Path(path).name)
                action.setToolTip(path)
                action.triggered.connect(
                    lambda checked=False, value=path: self.load_file(value)
                )
            self.recent_menu.addSeparator()
            clear_action = self.recent_menu.addAction("Clear recent files")
            clear_action.triggered.connect(self._clear_recent_files)
        self.recent_button.setEnabled(bool(existing))

    def _clear_recent_files(self) -> None:
        self._settings.remove(self._RECENT_FILES_KEY)
        self._rebuild_recent_menu()

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if any(
            url.isLocalFile() and Path(url.toLocalFile()).is_file()
            for url in event.mimeData().urls()
        ):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent) -> None:
        for url in event.mimeData().urls():
            if url.isLocalFile():
                path = Path(url.toLocalFile())
                if path.is_file():
                    event.acceptProposedAction()
                    self.load_file(path)
                    return
        event.ignore()

    def _show_error(
        self,
        title: str,
        message: str,
        details: str | None = None,
    ) -> None:
        dialog = QMessageBox(self)
        dialog.setIcon(QMessageBox.Icon.Critical)
        dialog.setWindowTitle(title)
        dialog.setText(message)
        dialog.setInformativeText(
            "Verify that the file is a complete Windows Portable Executable."
        )
        if details:
            dialog.setDetailedText(details)
        dialog.exec()
