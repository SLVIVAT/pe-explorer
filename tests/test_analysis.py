from __future__ import annotations

import unittest

from pe.analysis import PEAnalyzer
from pe.models import (
    AnalysisFinding,
    COFFHeader,
    DataDirectory,
    ExportDirectory,
    ExportedFunction,
    ImportDescriptor,
    ImportedFunction,
    OptionalHeader,
    ResourceNode,
    SectionHeader,
    SecurityAnalysis,
)


_ALL_MITIGATIONS = 0x0040 | 0x0100 | 0x4000
_EXPECTED_FINDING_KEYS = {
    "architecture",
    "pe_format",
    "image_type",
    "aslr",
    "dep",
    "cfg",
    "digital_signature",
    "section_count",
    "import_count",
    "export_count",
    "resources",
    "suspicious_section_names",
    "writable_executable_sections",
    "packed_heuristics",
    "overall_risk",
}


def _data_directories(
    *,
    certificate_offset: int = 0,
    certificate_size: int = 0,
) -> tuple[DataDirectory, ...]:
    directories = []
    for index in range(16):
        virtual_address = certificate_offset if index == 4 else 0
        size = certificate_size if index == 4 else 0
        directories.append(
            DataDirectory(
                index=index,
                name=f"Directory {index}",
                virtual_address=virtual_address,
                size=size,
            )
        )
    return tuple(directories)


def _optional_header(
    *,
    pe32_plus: bool = True,
    dll_characteristics: int = _ALL_MITIGATIONS,
    certificate_offset: int = 0xE00,
    certificate_size: int = 0x20,
) -> OptionalHeader:
    return OptionalHeader(
        magic=0x20B if pe32_plus else 0x10B,
        format="PE32+" if pe32_plus else "PE32",
        major_linker_version=14,
        minor_linker_version=0,
        size_of_code=0x200,
        size_of_initialized_data=0,
        size_of_uninitialized_data=0,
        address_of_entry_point=0x1000,
        base_of_code=0x1000,
        base_of_data=None if pe32_plus else 0x2000,
        image_base=0x140000000 if pe32_plus else 0x400000,
        section_alignment=0x1000,
        file_alignment=0x200,
        major_operating_system_version=6,
        minor_operating_system_version=0,
        major_image_version=0,
        minor_image_version=0,
        major_subsystem_version=6,
        minor_subsystem_version=0,
        win32_version_value=0,
        size_of_image=0x2000,
        size_of_headers=0x200,
        checksum=0,
        subsystem=3,
        dll_characteristics=dll_characteristics,
        size_of_stack_reserve=0x100000,
        size_of_stack_commit=0x1000,
        size_of_heap_reserve=0x100000,
        size_of_heap_commit=0x1000,
        loader_flags=0,
        number_of_rva_and_sizes=16,
        data_directories=_data_directories(
            certificate_offset=certificate_offset,
            certificate_size=certificate_size,
        ),
    )


def _coff_header(*, pe32_plus: bool = True, dll: bool = False) -> COFFHeader:
    return COFFHeader(
        machine=0x8664 if pe32_plus else 0x014C,
        number_of_sections=1,
        timestamp=0,
        pointer_to_symbol_table=0,
        number_of_symbols=0,
        optional_header_size=0xF0 if pe32_plus else 0xE0,
        characteristics=0x0002 | (0x2000 if dll else 0),
    )


def _section(
    *,
    name: str = ".text",
    pointer: int = 0x200,
    raw_size: int = 0x400,
    virtual_size: int = 0x400,
    characteristics: int = 0x60000020,
) -> SectionHeader:
    encoded_name = name.encode("ascii", errors="replace")[:8]
    return SectionHeader(
        index=1,
        name=name,
        raw_name=encoded_name.ljust(8, b"\x00"),
        virtual_size=virtual_size,
        virtual_address=0x1000,
        size_of_raw_data=raw_size,
        pointer_to_raw_data=pointer,
        pointer_to_relocations=0,
        pointer_to_linenumbers=0,
        number_of_relocations=0,
        number_of_linenumbers=0,
        characteristics=characteristics,
    )


def _resource_root() -> ResourceNode:
    return ResourceNode(
        name="Resources",
        identifier=None,
        level=0,
        is_directory=True,
        characteristics=0,
        timestamp=0,
        major_version=0,
        minor_version=0,
        number_of_named_entries=0,
        number_of_id_entries=0,
        data=None,
        children=(),
    )


def _imports() -> tuple[ImportDescriptor, ...]:
    functions = tuple(
        ImportedFunction(
            index=index,
            kind="ordinal" if index == 2 else "name",
            name=None if index == 2 else "CreateFileW",
            ordinal=42 if index == 2 else None,
            hint=None if index == 2 else 0,
            is_ordinal=index == 2,
            lookup_table_rva=0x2000 + index * 8,
            import_address_table_rva=0x2100 + index * 8,
            name_rva=None if index == 2 else 0x2200,
            raw_value=42 if index == 2 else 0x2200,
        )
        for index in (1, 2)
    )
    return (
        ImportDescriptor(
            index=1,
            dll_name="KERNEL32.dll",
            original_first_thunk=0x2000,
            timestamp=0,
            forwarder_chain=0,
            name_rva=0x2300,
            first_thunk=0x2100,
            functions=functions,
        ),
    )


def _exports() -> ExportDirectory:
    functions = (
        ExportedFunction(
            index=1,
            ordinal=1,
            ordinal_index=0,
            name="ExportedOne",
            names=("ExportedOne",),
            rva=0x1100,
            is_forwarder=False,
            forwarder=None,
        ),
        # A zero-RVA EAT gap is not an active exported function.
        ExportedFunction(
            index=2,
            ordinal=2,
            ordinal_index=1,
            name=None,
            names=(),
            rva=0,
            is_forwarder=False,
            forwarder=None,
        ),
    )
    return ExportDirectory(
        characteristics=0,
        timestamp=0,
        major_version=0,
        minor_version=0,
        name_rva=0x3000,
        dll_name="fixture.dll",
        ordinal_base=1,
        address_table_entries=2,
        number_of_name_pointers=1,
        export_address_table_rva=0x3100,
        name_pointer_rva=0x3200,
        ordinal_table_rva=0x3300,
        functions=functions,
    )


def _analyze(
    *,
    data: bytes | None = None,
    pe32_plus: bool = True,
    dll: bool = False,
    dll_characteristics: int = _ALL_MITIGATIONS,
    certificate_offset: int = 0xE00,
    certificate_size: int = 0x20,
    sections: tuple[SectionHeader, ...] | None = None,
    imports: tuple[ImportDescriptor, ...] = (),
    exports: ExportDirectory | None = None,
    resources: ResourceNode | None = None,
) -> SecurityAnalysis:
    image_data = data if data is not None else bytes(0x1000)
    parsed_sections = sections if sections is not None else (_section(),)
    return PEAnalyzer(
        image_data,
        _coff_header(pe32_plus=pe32_plus, dll=dll),
        _optional_header(
            pe32_plus=pe32_plus,
            dll_characteristics=dll_characteristics,
            certificate_offset=certificate_offset,
            certificate_size=certificate_size,
        ),
        parsed_sections,
        imports,
        exports,
        resources,
    ).analyze()


def _finding_map(analysis: SecurityAnalysis) -> dict[str, AnalysisFinding]:
    return {finding.key: finding for finding in analysis.findings}


class PEAnalyzerTests(unittest.TestCase):
    def test_clean_pe32_and_pe32_plus_have_all_explained_findings(self) -> None:
        for pe32_plus, expected_architecture, expected_format in (
            (False, "Intel 386", "PE32"),
            (True, "x64", "PE32+"),
        ):
            with self.subTest(pe32_plus=pe32_plus):
                analysis = _analyze(pe32_plus=pe32_plus)
                findings = _finding_map(analysis)

                self.assertEqual(analysis.overall_risk, "Low")
                self.assertEqual(analysis.risk_score, 0)
                self.assertEqual(set(findings), _EXPECTED_FINDING_KEYS)
                self.assertEqual(
                    len(findings),
                    len(analysis.findings),
                    "finding keys must remain unique",
                )
                self.assertEqual(
                    findings["architecture"].value,
                    expected_architecture,
                )
                self.assertEqual(findings["pe_format"].value, expected_format)
                self.assertTrue(
                    all(finding.explanation.strip() for finding in findings.values())
                )

    def test_image_type_counts_and_resource_presence_are_explained(self) -> None:
        analysis = _analyze(
            dll=True,
            imports=_imports(),
            exports=_exports(),
            resources=_resource_root(),
        )
        findings = _finding_map(analysis)

        self.assertEqual(findings["image_type"].value, "DLL")
        self.assertIn("0x2000", findings["image_type"].explanation)
        self.assertEqual(findings["section_count"].value, "1")
        self.assertEqual(findings["import_count"].value, "2")
        self.assertEqual(findings["export_count"].value, "1")
        self.assertEqual(findings["resources"].value, "Present")

    def test_signature_requires_a_complete_certificate_file_range(self) -> None:
        present = _finding_map(_analyze())["digital_signature"]
        missing = _finding_map(
            _analyze(certificate_offset=0, certificate_size=0)
        )["digital_signature"]
        invalid = _finding_map(
            _analyze(certificate_offset=0xFF0, certificate_size=0x40)
        )["digital_signature"]

        self.assertEqual(present.value, "Present")
        self.assertEqual(present.severity, "good")
        self.assertIn("presence only", present.explanation)
        self.assertEqual(missing.value, "Missing")
        self.assertIn("zero file offset", missing.explanation)
        self.assertEqual(invalid.value, "Missing")
        self.assertIn("outside the file", invalid.explanation)

    def test_disabled_mitigations_produce_medium_risk(self) -> None:
        analysis = _analyze(
            dll_characteristics=0,
            certificate_offset=0,
            certificate_size=0,
        )
        findings = _finding_map(analysis)

        self.assertEqual(analysis.overall_risk, "Medium")
        self.assertEqual(analysis.risk_score, 25)
        self.assertEqual(findings["aslr"].value, "Not enabled")
        self.assertEqual(findings["dep"].value, "Not enabled")
        self.assertEqual(findings["cfg"].value, "Not enabled")
        self.assertIn("+8 ASLR", findings["overall_risk"].explanation)
        self.assertIn("20-49", findings["overall_risk"].explanation)

    def test_suspicious_writable_executable_high_entropy_section_is_high(self) -> None:
        data = bytearray(0x1000)
        data[0x200:0x600] = bytes(range(256)) * 4
        section = _section(
            name=".UPX1",
            characteristics=0xE0000020,
        )
        analysis = _analyze(
            data=bytes(data),
            dll_characteristics=0,
            certificate_offset=0,
            certificate_size=0,
            sections=(section,),
        )
        findings = _finding_map(analysis)

        self.assertEqual(analysis.overall_risk, "High")
        self.assertEqual(analysis.risk_score, 95)
        self.assertEqual(findings["suspicious_section_names"].value, ".UPX1")
        self.assertEqual(
            findings["writable_executable_sections"].value,
            ".UPX1",
        )
        self.assertEqual(
            findings["packed_heuristics"].value,
            "Indicators detected",
        )
        self.assertIn("8.00 bits/byte", findings["packed_heuristics"].explanation)
        self.assertIn("heuristics", findings["packed_heuristics"].explanation)

    def test_executable_zero_raw_data_is_a_packing_indicator(self) -> None:
        section = _section(
            name=".stub",
            raw_size=0,
            virtual_size=0x1000,
            characteristics=0x60000020,
        )
        analysis = _analyze(sections=(section,))
        finding = _finding_map(analysis)["packed_heuristics"]

        self.assertEqual(finding.value, "Indicators detected")
        self.assertIn("no raw file data", finding.explanation)
        self.assertEqual(analysis.overall_risk, "Medium")


if __name__ == "__main__":
    unittest.main()
