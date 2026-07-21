"""Application-wide visual styling for PE Explorer."""

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication


DARK_STYLESHEET = """
QWidget {
    background-color: #151922;
    color: #e6e9ef;
    font-size: 10pt;
}

QMainWindow, QTabWidget::pane {
    background-color: #151922;
}

QToolBar {
    background-color: #1c2230;
    border: 0;
    border-bottom: 1px solid #30394a;
    spacing: 8px;
    padding: 8px 10px;
}

QPushButton {
    background-color: #4f8cff;
    border: 1px solid #6399ff;
    border-radius: 5px;
    color: #ffffff;
    font-weight: 600;
    min-height: 28px;
    padding: 3px 14px;
}

QPushButton:hover { background-color: #6399ff; }
QPushButton:pressed { background-color: #3977e8; }
QPushButton:disabled { background-color: #343c4c; color: #7d8798; }

QToolButton {
    background-color: #242c3a;
    border: 1px solid #3a4559;
    border-radius: 5px;
    color: #e6e9ef;
    min-height: 28px;
    padding: 3px 10px;
}
QToolButton:hover { background-color: #303a4c; }
QToolButton:pressed { background-color: #202735; }

QLineEdit, QComboBox, QSpinBox {
    background-color: #10141c;
    border: 1px solid #3a4559;
    border-radius: 5px;
    color: #e6e9ef;
    min-height: 28px;
    padding: 2px 8px;
    selection-background-color: #315d9f;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border-color: #4f8cff;
}
QComboBox::drop-down { border: 0; width: 24px; }

QMenu {
    background-color: #1c2230;
    border: 1px solid #3a4559;
    padding: 5px;
}
QMenu::item { border-radius: 3px; padding: 6px 28px 6px 10px; }
QMenu::item:selected { background-color: #315d9f; }
QMenu::separator { background-color: #3a4559; height: 1px; margin: 4px; }

QLabel#filePathLabel {
    background-color: #1c2230;
    border: 1px solid #30394a;
    border-radius: 5px;
    color: #b8c0cf;
    padding: 8px 10px;
}

QLabel#summaryBanner, QLabel#riskBanner {
    background-color: #1c2230;
    border: 1px solid #30394a;
    border-radius: 5px;
    padding: 9px 12px;
}

QLabel#riskBanner[risk="low"] {
    background-color: #17352c;
    border-color: #2e745d;
    color: #8df0c1;
}

QLabel#riskBanner[risk="medium"] {
    background-color: #3a3020;
    border-color: #80662f;
    color: #f6cf78;
}

QLabel#riskBanner[risk="high"] {
    background-color: #3a2229;
    border-color: #864151;
    color: #ff9baa;
}

QTabWidget::pane {
    border: 1px solid #30394a;
    border-radius: 5px;
    top: -1px;
}

QTabBar::tab {
    background-color: #1c2230;
    border: 1px solid #30394a;
    border-bottom: 0;
    color: #9da7b8;
    margin-right: 2px;
    min-width: 88px;
    padding: 9px 12px;
}

QTabBar::tab:selected {
    background-color: #242c3a;
    color: #ffffff;
    border-top: 2px solid #4f8cff;
}

QTabBar::tab:hover:!selected {
    background-color: #202735;
    color: #d8dce5;
}

QTableView, QTableWidget, QTreeView, QTreeWidget,
QTextEdit, QPlainTextEdit {
    alternate-background-color: #1a202b;
    background-color: #151922;
    border: 0;
    gridline-color: #293142;
    selection-background-color: #315d9f;
    selection-color: #ffffff;
}

QTableView::item, QTableWidget::item,
QTreeView::item, QTreeWidget::item {
    min-height: 24px;
    padding: 3px 6px;
}

QHeaderView::section {
    background-color: #242c3a;
    border: 0;
    border-bottom: 1px solid #3a4559;
    border-right: 1px solid #30394a;
    color: #cbd1dc;
    font-weight: 600;
    min-height: 27px;
    padding: 4px 7px;
}

QGroupBox {
    border: 1px solid #30394a;
    border-radius: 5px;
    font-weight: 600;
    margin-top: 12px;
    padding-top: 9px;
}

QGroupBox::title {
    color: #cbd1dc;
    left: 9px;
    padding: 0 4px;
    subcontrol-origin: margin;
}

QSplitter::handle { background-color: #30394a; }
QSplitter::handle:vertical { height: 1px; }
QSplitter::handle:horizontal { width: 1px; }

QStatusBar {
    background-color: #1c2230;
    border-top: 1px solid #30394a;
    color: #9da7b8;
}

QStatusBar QLabel { color: #b8c0cf; padding: 2px 8px; }

QProgressBar {
    background-color: #10141c;
    border: 1px solid #3a4559;
    border-radius: 4px;
    color: #e6e9ef;
    max-height: 10px;
    text-align: center;
}
QProgressBar::chunk { background-color: #4f8cff; border-radius: 3px; }

QScrollBar:vertical {
    background: #151922;
    border: 0;
    width: 12px;
}
QScrollBar::handle:vertical {
    background: #3a4559;
    border-radius: 5px;
    min-height: 24px;
    margin: 2px;
}
QScrollBar::handle:vertical:hover { background: #526079; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

QScrollBar:horizontal {
    background: #151922;
    border: 0;
    height: 12px;
}
QScrollBar::handle:horizontal {
    background: #3a4559;
    border-radius: 5px;
    min-width: 24px;
    margin: 2px;
}
QScrollBar::handle:horizontal:hover { background: #526079; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
"""


def apply_dark_theme(application: QApplication) -> None:
    """Apply the supported platform-neutral dark presentation."""

    application.setStyle("Fusion")
    application.setFont(QFont("Segoe UI", 10))
    application.setStyleSheet(DARK_STYLESHEET)


__all__ = ["DARK_STYLESHEET", "apply_dark_theme"]
