from __future__ import annotations

from dataclasses import FrozenInstanceError
import struct
import unittest
from unittest.mock import patch

from pe.models import ResourceData, ResourceNode
from pe.version_info import VersionInfoParser, parse_version_info


def _utf16_z(value: str) -> bytes:
    return (value + "\x00").encode("utf-16-le")


def _block(
    key: str,
    value: bytes = b"",
    *,
    value_type: int,
    children: tuple[bytes, ...] = (),
    value_length: int | None = None,
) -> bytes:
    result = bytearray(6)
    result.extend(_utf16_z(key))
    while len(result) % 4:
        result.append(0)
    result.extend(value)
    if children:
        while len(result) % 4:
            result.append(0)
        for child in children:
            result.extend(child)
            while len(result) % 4:
                result.append(0)
    if value_length is None:
        value_length = len(value) // 2 if value_type == 1 else len(value)
    struct.pack_into(
        "<HHH", result, 0, len(result), value_length, value_type
    )
    return bytes(result)


def _version_payload(
    *,
    table_key: str = "040904B0",
    company: str = "Acme Corporation",
) -> bytes:
    values = {
        "CompanyName": company,
        "ProductName": "PE Explorer",
        "FileDescription": "Portable Executable inspector",
        "ProductVersion": "5.6.7.8 release",
        "FileVersion": "1.2.3.4 release",
        "OriginalFilename": "pe-explorer.exe",
        "LegalCopyright": "Copyright Acme",
    }
    strings = tuple(
        _block(key, _utf16_z(value), value_type=1)
        for key, value in values.items()
    )
    table = _block(table_key, value_type=1, children=strings)
    string_file_info = _block(
        "StringFileInfo", value_type=1, children=(table,)
    )
    fixed = struct.pack(
        "<13I",
        0xFEEF04BD,
        0x00010000,
        0x00010002,
        0x00030004,
        0x00050006,
        0x00070008,
        0x3F,
        0,
        0x00040004,
        1,
        0,
        0,
        0,
    )
    return _block(
        "VS_VERSION_INFO",
        fixed,
        value_type=0,
        value_length=52,
        children=(string_file_info,),
    )


def _resource_leaf(
    *,
    offset: int,
    size: int,
    resource_type: str = "RT_VERSION",
) -> ResourceNode:
    return ResourceNode(
        name="Language 0x0409",
        identifier=0x0409,
        level=3,
        is_directory=False,
        characteristics=None,
        timestamp=None,
        major_version=None,
        minor_version=None,
        number_of_named_entries=0,
        number_of_id_entries=0,
        data=ResourceData(
            rva=0x2000,
            size=size,
            code_page=1200,
            reserved=0,
            file_offset=offset,
            resource_type=resource_type,
            summary="Version information",
            content=None,
        ),
        children=(),
    )


def _root(*children: ResourceNode) -> ResourceNode:
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
        number_of_id_entries=len(children),
        data=None,
        children=children,
    )


class VersionInfoParserTests(unittest.TestCase):
    def test_extracts_all_requested_string_and_fixed_fields(self) -> None:
        payload = _version_payload()
        for pe32_plus, offset in ((False, 0x200), (True, 0x400)):
            with self.subTest(pe32_plus=pe32_plus):
                data = b"\x00" * offset + payload + b"trailing"
                result = VersionInfoParser(
                    data,
                    _root(_resource_leaf(offset=offset, size=len(payload))),
                ).parse()

                self.assertTrue(result.available)
                self.assertEqual(result.company_name, "Acme Corporation")
                self.assertEqual(result.product_name, "PE Explorer")
                self.assertEqual(
                    result.file_description,
                    "Portable Executable inspector",
                )
                self.assertEqual(result.product_version, "5.6.7.8 release")
                self.assertEqual(result.file_version, "1.2.3.4 release")
                self.assertEqual(result.original_filename, "pe-explorer.exe")
                self.assertEqual(result.legal_copyright, "Copyright Acme")
                self.assertEqual(result.fixed_file_version, "1.2.3.4")
                self.assertEqual(result.fixed_product_version, "5.6.7.8")
                self.assertEqual(result.resource_count, 1)
                self.assertIsNone(result.unavailable_reason)
                self.assertEqual(len(result.string_tables), 1)
                table = result.string_tables[0]
                self.assertEqual(table.translation, "040904B0")
                self.assertEqual(table.language_id, 0x0409)
                self.assertEqual(table.code_page, 0x04B0)
                self.assertEqual(len(table.strings), 7)

    def test_combines_multiple_version_leaves_deterministically(self) -> None:
        first = _version_payload(company="First Company")
        second = _version_payload(
            table_key="040C04E4",
            company="Deuxieme Societe",
        )
        second_offset = len(first) + 16
        data = first + b"\x00" * 16 + second
        result = parse_version_info(
            data,
            _root(
                _resource_leaf(offset=0, size=len(first)),
                _resource_leaf(offset=second_offset, size=len(second)),
            ),
        )

        self.assertTrue(result.available)
        self.assertEqual(result.resource_count, 2)
        self.assertEqual(result.company_name, "First Company")
        self.assertEqual(len(result.string_tables), 2)
        self.assertEqual(result.string_tables[1].language_id, 0x040C)
        self.assertEqual(result.string_tables[1].code_page, 0x04E4)

    def test_uses_fixed_versions_when_string_values_are_absent(self) -> None:
        payload = _version_payload()
        # Rename the two display-version keys without changing block lengths.
        payload = payload.replace(
            "FileVersion".encode("utf-16-le"),
            "FakeVersion".encode("utf-16-le"),
        ).replace(
            "ProductVersion".encode("utf-16-le"),
            "AlternateValue".encode("utf-16-le"),
        )
        result = parse_version_info(
            payload,
            _root(_resource_leaf(offset=0, size=len(payload))),
        )

        self.assertEqual(result.file_version, "1.2.3.4")
        self.assertEqual(result.product_version, "5.6.7.8")

    def test_reports_absent_malformed_and_invalid_ranges_gracefully(self) -> None:
        self.assertFalse(parse_version_info(b"", None).available)
        self.assertIn(
            "No RT_VERSION",
            parse_version_info(b"", _root()).unavailable_reason or "",
        )

        malformed = b"\x06\x00\x00\x00\x00\x00"
        malformed_result = parse_version_info(
            malformed,
            _root(_resource_leaf(offset=0, size=len(malformed))),
        )
        self.assertFalse(malformed_result.available)
        self.assertIn("malformed", malformed_result.unavailable_reason or "")

        range_result = parse_version_info(
            b"short",
            _root(_resource_leaf(offset=100, size=20)),
        )
        self.assertFalse(range_result.available)
        self.assertIn("invalid file range", range_result.unavailable_reason or "")

        unrelated_result = parse_version_info(
            b"data",
            _root(
                _resource_leaf(
                    offset=0,
                    size=4,
                    resource_type="RT_MANIFEST",
                )
            ),
        )
        self.assertFalse(unrelated_result.available)

    def test_models_are_immutable_and_to_dict_is_plain_data(self) -> None:
        payload = _version_payload()
        result = parse_version_info(
            payload,
            _root(_resource_leaf(offset=0, size=len(payload))),
        )
        with self.assertRaises(FrozenInstanceError):
            result.company_name = "Changed"  # type: ignore[misc]

        value = result.to_dict()
        self.assertEqual(value["company_name"], "Acme Corporation")
        self.assertIsInstance(value["string_tables"], list)
        self.assertIsInstance(value["string_tables"][0]["strings"], list)
        self.assertEqual(
            value["string_tables"][0]["strings"][0],
            {"key": "CompanyName", "value": "Acme Corporation"},
        )

    def test_resource_count_budget_keeps_the_parsed_prefix(self) -> None:
        payload = _version_payload()
        resources = _root(
            _resource_leaf(offset=0, size=len(payload)),
            _resource_leaf(offset=0, size=len(payload)),
        )

        with patch("pe.version_info._MAX_VERSION_RESOURCES", 1):
            result = parse_version_info(payload, resources)

        self.assertTrue(result.available)
        self.assertEqual(result.resource_count, 2)
        self.assertEqual(result.company_name, "Acme Corporation")
        self.assertEqual(len(result.string_tables), 1)
        self.assertIn("first 1 of 2", result.unavailable_reason or "")
        self.assertIn("resource-count safety limit", result.unavailable_reason or "")

    def test_payload_budget_keeps_prior_successful_resources(self) -> None:
        first = _version_payload(company="First Company")
        second = _version_payload(company="Second Company")
        second_offset = len(first)
        resources = _root(
            _resource_leaf(offset=0, size=len(first)),
            _resource_leaf(offset=second_offset, size=len(second)),
        )

        with patch("pe.version_info._MAX_VERSION_PAYLOAD_BYTES", len(first)):
            result = parse_version_info(first + second, resources)

        self.assertTrue(result.available)
        self.assertEqual(result.resource_count, 2)
        self.assertEqual(result.company_name, "First Company")
        self.assertEqual(len(result.string_tables), 1)
        self.assertIn("cumulative", result.unavailable_reason or "")
        self.assertIn("payload safety limit", result.unavailable_reason or "")

    def test_payload_over_budget_has_an_actionable_unavailable_reason(self) -> None:
        payload = _version_payload()
        resources = _root(_resource_leaf(offset=0, size=len(payload)))

        with patch(
            "pe.version_info._MAX_VERSION_PAYLOAD_BYTES",
            len(payload) - 1,
        ):
            result = parse_version_info(payload, resources)

        self.assertFalse(result.available)
        self.assertEqual(result.resource_count, 1)
        self.assertIn(f"{len(payload):,}-byte payload", result.unavailable_reason or "")
        self.assertIn("payload safety limit", result.unavailable_reason or "")

    def test_payload_is_not_copied_from_the_source_image(self) -> None:
        class TrackingBytes(bytes):
            def __new__(cls, value: bytes) -> TrackingBytes:
                instance = super().__new__(cls, value)
                instance.slice_lengths = []
                return instance

            def __getitem__(self, key: object) -> object:
                value = super().__getitem__(key)
                if isinstance(key, slice):
                    self.slice_lengths.append(len(value))
                return value

        payload = _version_payload()
        data = TrackingBytes(payload)
        result = parse_version_info(
            data,
            _root(_resource_leaf(offset=0, size=len(payload))),
        )

        self.assertTrue(result.available)
        self.assertEqual(data.slice_lengths, [])


if __name__ == "__main__":
    unittest.main()
