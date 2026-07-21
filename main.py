import sys

from PySide6.QtWidgets import QApplication

from gui.main_window import MainWindow
from gui.theme import apply_dark_theme


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("PE Explorer")
    app.setOrganizationName("PE Explorer")
    apply_dark_theme(app)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
