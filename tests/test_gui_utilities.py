from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import QApplication, QTableView, QTreeView

from gui.table_actions import install_table_actions
from gui.workers import BackgroundTask


class GUIUtilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def test_table_actions_copy_value_row_table_and_address(self) -> None:
        model = QStandardItemModel(2, 3)
        model.setHorizontalHeaderLabels(["Offset", "RVA", "Value"])
        values = (
            ("0x10", "0x1010", "Alpha"),
            ("0x20", "0x1020", "Beta"),
        )
        for row, row_values in enumerate(values):
            for column, value in enumerate(row_values):
                model.setItem(row, column, QStandardItem(value))

        table = QTableView()
        table.setModel(model)
        controller = install_table_actions(
            table,
            {"Copy file offset": 0, "Copy RVA": 1},
        )
        table.setCurrentIndex(model.index(1, 2))

        controller.copy_value()
        self.assertEqual(QApplication.clipboard().text(), "Beta")
        controller.copy_row()
        self.assertEqual(
            QApplication.clipboard().text(),
            "0x20\t0x1020\tBeta",
        )
        controller.copy_column_value(1)
        self.assertEqual(QApplication.clipboard().text(), "0x1020")
        controller.copy_table()
        self.assertEqual(
            QApplication.clipboard().text(),
            "Offset\tRVA\tValue\n"
            "0x10\t0x1010\tAlpha\n"
            "0x20\t0x1020\tBeta",
        )

    def test_background_task_reports_success_progress_and_failure(self) -> None:
        progress_messages: list[tuple[int, str]] = []
        successes: list[tuple[int, object]] = []
        failures: list[tuple[int, str, str]] = []
        finished: list[int] = []

        task = BackgroundTask(
            7,
            lambda progress: (
                progress("Parsing headers"),
                "complete",
            )[1],
        )
        task.signals.progress.connect(
            lambda generation, message: progress_messages.append(
                (generation, message)
            )
        )
        task.signals.succeeded.connect(
            lambda generation, result: successes.append((generation, result))
        )
        task.signals.finished.connect(finished.append)
        task.run()

        self.assertEqual(progress_messages, [(7, "Parsing headers")])
        self.assertEqual(successes, [(7, "complete")])
        self.assertEqual(finished, [7])

        def fail(progress: object) -> object:
            raise ValueError("deliberate failure")

        failed_task = BackgroundTask(8, fail)
        failed_task.signals.failed.connect(
            lambda generation, message, details: failures.append(
                (generation, message, details)
            )
        )
        failed_task.run()
        self.assertEqual(failures[0][0:2], (8, "deliberate failure"))
        self.assertIn("ValueError", failures[0][2])

    def test_table_actions_preserve_hierarchy_for_tree_rows(self) -> None:
        model = QStandardItemModel()
        model.setHorizontalHeaderLabels(["Field", "Value"])
        root_name = QStandardItem("Header")
        root_value = QStandardItem("PE32+")
        child_name = QStandardItem("ImageBase")
        child_value = QStandardItem("0x140000000")
        root_name.appendRow((child_name, child_value))
        model.appendRow((root_name, root_value))

        tree = QTreeView()
        tree.setModel(model)
        controller = install_table_actions(tree)
        tree.setCurrentIndex(child_value.index())

        controller.copy_row()
        self.assertEqual(
            QApplication.clipboard().text(),
            "ImageBase\t0x140000000",
        )
        controller.copy_table()
        self.assertEqual(
            QApplication.clipboard().text(),
            "Field\tValue\n"
            "Header\tPE32+\n"
            "  ImageBase\t0x140000000",
        )


if __name__ == "__main__":
    unittest.main()
