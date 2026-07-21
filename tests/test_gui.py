from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QAbstractItemModel, Qt
from PySide6.QtWidgets import QApplication, QTableView, QTreeView

from gui.formatters import (
    SECTION_FIELDS,
    STANDARD_OPTIONAL_FIELDS,
    WINDOWS_OPTIONAL_FIELDS,
)
from gui.pe_info_widget import PEInfoWidget
from pe.models import PEInfo, ResourceNodeInfo
from pe.parser import PEParser
from tests.test_imports import (
    BOUND_DESCRIPTOR_TIMESTAMP,
    FIRST_DESCRIPTOR_FORWARDER_CHAIN,
    FIRST_DESCRIPTOR_TIMESTAMP,
    build_bound_import_fixture,
    build_import_fixture,
)
from tests.test_exports import build_export_fixture
from tests.test_parser import (
    DATA_DIRECTORY_COUNT,
    SECTION_VALUES,
    build_pe_fixture,
)


class PEInfoWidgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)

    def _parse_data(self, data: bytes, file_name: str = "fixture.exe") -> PEInfo:
        path = Path(self._temporary_directory.name) / file_name
        path.write_bytes(data)
        return PEParser(path).parse()

    def _parse_fixture(self, pe32_plus: bool) -> PEInfo:
        return self._parse_data(build_pe_fixture(pe32_plus=pe32_plus))

    @staticmethod
    def _model_headers(model: QAbstractItemModel) -> list[str]:
        return [
            str(
                model.headerData(
                    column,
                    Qt.Orientation.Horizontal,
                    Qt.ItemDataRole.DisplayRole,
                )
            )
            for column in range(model.columnCount())
        ]

    @staticmethod
    def _model_row(model: QAbstractItemModel, row: int) -> list[str]:
        return [
            str(
                model.data(
                    model.index(row, column),
                    Qt.ItemDataRole.DisplayRole,
                )
            )
            for column in range(model.columnCount())
        ]

    def _parse_import_fixture(self, pe32_plus: bool) -> PEInfo:
        path = Path(self._temporary_directory.name) / "fixture.exe"
        path.write_bytes(build_import_fixture(pe32_plus=pe32_plus))
        return PEParser(path).parse()

    def test_displays_all_optional_header_fields_for_both_formats(self) -> None:
        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus):
                info = self._parse_fixture(pe32_plus)
                view = PEInfoWidget()
                view.set_information(info)

                self.assertEqual(view.optional_tree.topLevelItemCount(), 3)
                standard = view.optional_tree.topLevelItem(0)
                windows = view.optional_tree.topLevelItem(1)
                directories = view.optional_tree.topLevelItem(2)

                expected_standard = {
                    label
                    for label, field, _ in STANDARD_OPTIONAL_FIELDS
                    if field != "base_of_data" or not pe32_plus
                }
                actual_standard = {
                    standard.child(index).text(0)
                    for index in range(standard.childCount())
                }
                self.assertEqual(actual_standard, expected_standard)

                expected_windows = {
                    label for label, _, _ in WINDOWS_OPTIONAL_FIELDS
                }
                actual_windows = {
                    windows.child(index).text(0)
                    for index in range(windows.childCount())
                }
                self.assertEqual(actual_windows, expected_windows)

                self.assertEqual(
                    directories.childCount(),
                    DATA_DIRECTORY_COUNT,
                )
                for index in range(DATA_DIRECTORY_COUNT):
                    directory = directories.child(index)
                    self.assertTrue(directory.text(0).startswith(f"[{index:02d}]"))
                    self.assertEqual(directory.childCount(), 3)
                    self.assertEqual(directory.child(0).text(0), "VirtualAddress")
                    self.assertEqual(directory.child(1).text(0), "Size")
                    self.assertEqual(directory.child(2).text(0), "Status")

                overview = view.summary_output.toPlainText()
                self.assertIn(info["optional_header"]["format"], overview)
                self.assertIn(f"{info['file_size']} bytes", overview)

    def test_displays_the_complete_section_table_and_can_clear(self) -> None:
        info = self._parse_fixture(pe32_plus=True)
        view = PEInfoWidget()
        view.set_information(info)

        self.assertEqual(view.sections_table.columnCount(), len(SECTION_FIELDS))
        self.assertEqual(view.sections_table.rowCount(), len(SECTION_VALUES))
        self.assertEqual(view.sections_table.item(0, 0).text(), "1")
        self.assertEqual(view.sections_table.item(0, 1).text(), ".text")
        self.assertEqual(
            view.sections_table.item(0, 2).text(),
            "2E 74 65 78 74 00 00 00",
        )
        self.assertEqual(
            view.sections_table.item(0, 11).text(),
            "0x60000020",
        )
        self.assertIn("Executable", view.sections_table.item(0, 11).toolTip())

        view.clear_information()
        self.assertEqual(view.summary_output.toPlainText(), "")
        self.assertEqual(view.optional_tree.topLevelItemCount(), 0)
        self.assertEqual(view.sections_table.rowCount(), 0)

    def test_displays_import_master_detail_for_pe32_and_pe32_plus(self) -> None:
        descriptor_headers = [
            "#",
            "DLL",
            "OriginalFirstThunk",
            "TimeDateStamp",
            "ForwarderChain",
            "Name RVA",
            "FirstThunk",
            "Symbols",
        ]
        symbol_headers = [
            "#",
            "Kind",
            "Name",
            "Ordinal",
            "Hint",
            "Lookup Entry RVA",
            "IAT Entry RVA",
            "Name RVA",
            "Raw Value",
        ]

        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus):
                info = self._parse_import_fixture(pe32_plus)
                view = PEInfoWidget()
                view.set_information(info)

                self.assertEqual(view.count(), 12)
                self.assertEqual(
                    [view.tabText(index) for index in range(view.count())],
                    [
                        "Overview",
                        "Optional Header",
                        "Sections",
                        "Imports",
                        "Exports",
                        "Resources",
                        "Data Directories",
                        "Analysis",
                        "Hex",
                        "Search",
                        "Strings",
                        "File Analysis",
                    ],
                )
                self.assertIs(view.widget(0), view.summary_output)
                self.assertIs(view.widget(1), view.optional_tree)
                self.assertIs(view.widget(2), view.sections_table)
                self.assertIs(view.widget(3), view.imports_widget)
                self.assertIs(view.widget(4), view.exports_widget)
                self.assertIs(view.widget(5), view.resources_widget)
                self.assertIs(view.widget(6), view.data_directories_widget)
                self.assertIs(view.widget(7), view.analysis_widget)
                self.assertIs(view.widget(8), view.hex_widget)
                self.assertIs(view.widget(9), view.search_widget)
                self.assertIs(view.widget(10), view.strings_widget)
                self.assertIs(view.widget(11), view.file_analysis_widget)
                self.assertTrue(
                    all(
                        not view.tabIcon(index).isNull()
                        for index in range(view.count())
                    )
                )

                descriptor_model = view.imports_widget.descriptor_model
                symbol_model = view.imports_widget.symbol_model
                self.assertEqual(
                    view.data_directories_widget.model.rowCount(),
                    DATA_DIRECTORY_COUNT,
                )
                self.assertEqual(view.analysis_widget.model.rowCount(), 15)
                self.assertEqual(
                    self._model_headers(descriptor_model),
                    descriptor_headers,
                )
                self.assertEqual(self._model_headers(symbol_model), symbol_headers)
                self.assertEqual(descriptor_model.rowCount(), 2)
                self.assertEqual(
                    self._model_row(descriptor_model, 0),
                    [
                        "1",
                        "KERNEL32.dll",
                        "0x00002080",
                        f"0x{FIRST_DESCRIPTOR_TIMESTAMP:08X}",
                        f"0x{FIRST_DESCRIPTOR_FORWARDER_CHAIN:08X}",
                        "0x00002040",
                        "0x000020A0",
                        "2",
                    ],
                )
                self.assertEqual(
                    self._model_row(descriptor_model, 1),
                    [
                        "2",
                        "USER32.dll",
                        "0x00000000",
                        "0x00000000",
                        "0x00000000",
                        "0x00002050",
                        "0x000020C0",
                        "1",
                    ],
                )

                entry_size = 8 if pe32_plus else 4
                named_raw = (
                    "0x0000000000002060" if pe32_plus else "0x00002060"
                )
                ordinal_raw = (
                    "0x8000000000000042" if pe32_plus else "0x80000042"
                )
                self.assertEqual(symbol_model.rowCount(), 2)
                self.assertEqual(
                    self._model_row(symbol_model, 0),
                    [
                        "1",
                        "Name",
                        "CreateFileW",
                        "",
                        "4660",
                        "0x00002080",
                        "0x000020A0",
                        "0x00002060",
                        named_raw,
                    ],
                )
                self.assertEqual(
                    self._model_row(symbol_model, 1),
                    [
                        "2",
                        "Ordinal",
                        "",
                        "66",
                        "",
                        f"0x{0x2080 + entry_size:08X}",
                        f"0x{0x20A0 + entry_size:08X}",
                        "",
                        ordinal_raw,
                    ],
                )

                view.imports_widget.descriptor_table.selectRow(1)
                self.application.processEvents()
                fallback_raw = (
                    "0x0000000000002070" if pe32_plus else "0x00002070"
                )
                self.assertEqual(symbol_model.rowCount(), 1)
                self.assertEqual(
                    self._model_row(symbol_model, 0),
                    [
                        "1",
                        "Name",
                        "MessageBoxA",
                        "",
                        "7",
                        "0x000020C0",
                        "0x000020C0",
                        "0x00002070",
                        fallback_raw,
                    ],
                )
                self.assertIn("USER32.dll", view.imports_widget.symbol_group.title())

                overview = view.summary_output.toPlainText()
                self.assertIn("Imported DLLs         : 2", overview)
                self.assertIn("Imported Functions    : 3", overview)

                no_imports = self._parse_fixture(pe32_plus)
                view.set_information(no_imports)
                self.assertEqual(descriptor_model.rowCount(), 0)
                self.assertEqual(symbol_model.rowCount(), 0)

                view.set_information(info)
                self.assertEqual(descriptor_model.rowCount(), 2)
                self.assertEqual(symbol_model.rowCount(), 2)
                view.clear_information()
                self.assertEqual(descriptor_model.rowCount(), 0)
                self.assertEqual(symbol_model.rowCount(), 0)

    def test_displays_bound_addresses_from_oft_fallback(self) -> None:
        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus):
                info = self._parse_data(
                    build_bound_import_fixture(pe32_plus=pe32_plus),
                    "bound-imports.exe",
                )
                view = PEInfoWidget()
                view.set_information(info)
                view.imports_widget.descriptor_table.selectRow(1)
                self.application.processEvents()

                descriptor_model = view.imports_widget.descriptor_model
                symbol_model = view.imports_widget.symbol_model
                descriptor_row = self._model_row(descriptor_model, 1)
                self.assertEqual(
                    descriptor_row,
                    [
                        "2",
                        "USER32.dll",
                        "0x00000000",
                        f"0x{BOUND_DESCRIPTOR_TIMESTAMP:08X}",
                        "0x00000000",
                        "0x00002050",
                        "0x000020C0",
                        "2",
                    ],
                )

                expected_raw_values = (
                    ["0x00007FFB12345678", "0x00007FFB23456789"]
                    if pe32_plus
                    else ["0x76543210", "0x76544321"]
                )
                entry_size = 8 if pe32_plus else 4
                self.assertEqual(symbol_model.rowCount(), 2)
                for index, raw_value in enumerate(expected_raw_values):
                    with self.subTest(symbol=index + 1):
                        entry_rva = 0x20C0 + index * entry_size
                        self.assertEqual(
                            self._model_row(symbol_model, index),
                            [
                                str(index + 1),
                                "Bound address",
                                "",
                                "",
                                "",
                                f"0x{entry_rva:08X}",
                                f"0x{entry_rva:08X}",
                                "",
                                raw_value,
                            ],
                        )

    def test_displays_exports_resources_directories_and_analysis(self) -> None:
        info = self._parse_data(
            build_export_fixture(pe32_plus=True),
            "exports.dll",
        )
        view = PEInfoWidget()
        view.set_information(info)

        self.assertIsInstance(view.exports_widget.table, QTableView)
        self.assertTrue(view.exports_widget.table.isSortingEnabled())
        self.assertEqual(view.exports_widget.model.rowCount(), 5)
        self.assertEqual(
            self._model_headers(view.exports_widget.model),
            ["#", "Ordinal", "Name / Aliases", "RVA", "Type", "Forwarder"],
        )
        self.assertEqual(
            self._model_row(view.exports_widget.model, 3),
            [
                "4",
                "13",
                "Forwarded",
                "0x000020A0",
                "Forwarder",
                "KERNEL32.Sleep",
            ],
        )
        self.assertEqual(
            self._model_row(view.exports_widget.model, 1)[4],
            "Unused",
        )
        self.assertIn("4 exports", view.exports_widget.summary_label.text())
        self.assertIn("5 EAT entries", view.exports_widget.summary_label.text())

        self.assertIsInstance(view.data_directories_widget.table, QTableView)
        self.assertTrue(view.data_directories_widget.table.isSortingEnabled())
        self.assertEqual(
            view.data_directories_widget.model.rowCount(),
            DATA_DIRECTORY_COUNT,
        )
        self.assertEqual(
            self._model_row(view.data_directories_widget.model, 0)[4],
            "Present - RVA range is file-backed",
        )

        self.assertIsInstance(view.analysis_widget.table, QTableView)
        self.assertEqual(view.analysis_widget.model.rowCount(), 15)
        explanations = [
            str(
                view.analysis_widget.model.data(
                    view.analysis_widget.model.index(row, 3),
                    Qt.ItemDataRole.DisplayRole,
                )
            )
            for row in range(view.analysis_widget.model.rowCount())
        ]
        self.assertTrue(all(explanations))

        resource: ResourceNodeInfo = {
            "name": "Resources",
            "identifier": None,
            "level": 0,
            "is_directory": True,
            "characteristics": 0,
            "timestamp": 0,
            "major_version": 0,
            "minor_version": 0,
            "number_of_named_entries": 0,
            "number_of_id_entries": 1,
            "data": None,
            "children": [
                {
                    "name": "RT_MANIFEST",
                    "identifier": 24,
                    "level": 1,
                    "is_directory": True,
                    "characteristics": 0,
                    "timestamp": 0,
                    "major_version": 0,
                    "minor_version": 0,
                    "number_of_named_entries": 0,
                    "number_of_id_entries": 1,
                    "data": None,
                    "children": [
                        {
                            "name": "English (United States)",
                            "identifier": 1033,
                            "level": 2,
                            "is_directory": False,
                            "characteristics": None,
                            "timestamp": None,
                            "major_version": None,
                            "minor_version": None,
                            "number_of_named_entries": 0,
                            "number_of_id_entries": 0,
                            "data": {
                                "rva": 0x2080,
                                "size": 23,
                                "code_page": 65001,
                                "reserved": 0,
                                "file_offset": 0xA80,
                                "resource_type": "RT_MANIFEST",
                                "summary": "XML application manifest",
                                "content": "<assembly></assembly>",
                            },
                            "children": [],
                        }
                    ],
                }
            ],
        }
        view.resources_widget.set_resource(resource)
        self.assertIsInstance(view.resources_widget.tree, QTreeView)
        root = view.resources_widget.model.index(0, 0)
        resource_type = view.resources_widget.model.index(0, 0, root)
        leaf = view.resources_widget.model.index(0, 0, resource_type)
        view.resources_widget.tree.setCurrentIndex(leaf)
        self.application.processEvents()
        self.assertIn("RT_MANIFEST", view.resources_widget.details.toPlainText())
        self.assertIn("<assembly>", view.resources_widget.details.toPlainText())

        view.clear_information()
        self.assertEqual(view.exports_widget.model.rowCount(), 0)
        self.assertEqual(view.resources_widget.model.rowCount(), 0)
        self.assertEqual(view.data_directories_widget.model.rowCount(), 0)
        self.assertEqual(view.analysis_widget.model.rowCount(), 0)


if __name__ == "__main__":
    unittest.main()
