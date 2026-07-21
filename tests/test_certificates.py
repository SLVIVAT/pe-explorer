from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import struct
import unittest
from unittest.mock import patch

from pe.certificates import (
    CertificateParser,
    WIN_CERT_REVISION_2_0,
    WIN_CERT_TYPE_PKCS_SIGNED_DATA,
    parse_certificates,
)
from pe.models import DataDirectory, OptionalHeader


CERTIFICATE_OFFSET = 0x500


def _length(value: int) -> bytes:
    if value < 0x80:
        return bytes((value,))
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(encoded),)) + encoded


def _der(tag: int, value: bytes) -> bytes:
    return bytes((tag,)) + _length(len(value)) + value


def _base128(value: int) -> bytes:
    groups = [value & 0x7F]
    value >>= 7
    while value:
        groups.append(0x80 | (value & 0x7F))
        value >>= 7
    return bytes(reversed(groups))


def _oid(value: str) -> bytes:
    arcs = [int(part) for part in value.split(".")]
    encoded = bytearray(_base128(arcs[0] * 40 + arcs[1]))
    for arc in arcs[2:]:
        encoded.extend(_base128(arc))
    return _der(0x06, bytes(encoded))


def _integer(value: int) -> bytes:
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return _der(0x02, encoded)


def _sequence(*values: bytes) -> bytes:
    return _der(0x30, b"".join(values))


def _set(*values: bytes) -> bytes:
    return _der(0x31, b"".join(values))


def _algorithm(oid: str) -> bytes:
    return _sequence(_oid(oid), _der(0x05, b""))


def _name(
    common_name: str,
    organization: str,
    country: str = "US",
) -> bytes:
    def attribute(oid: str, value: str, tag: int = 0x0C) -> bytes:
        return _set(_sequence(_oid(oid), _der(tag, value.encode("utf-8"))))

    return _sequence(
        attribute("2.5.4.3", common_name),
        attribute("2.5.4.10", organization),
        attribute("2.5.4.6", country, tag=0x13),
    )


def _certificate(
    *,
    serial: int,
    subject: bytes,
    issuer: bytes,
) -> bytes:
    signature_algorithm = _algorithm("1.2.840.113549.1.1.11")
    validity = _sequence(
        _der(0x17, b"250101000000Z"),
        _der(0x17, b"300101000000Z"),
    )
    subject_public_key = _sequence(
        _algorithm("1.2.840.113549.1.1.1"),
        _der(0x03, b"\x00\x01\x02\x03"),
    )
    tbs = _sequence(
        _der(0xA0, _integer(2)),
        _integer(serial),
        signature_algorithm,
        issuer,
        validity,
        subject,
        subject_public_key,
    )
    return _sequence(
        tbs,
        signature_algorithm,
        _der(0x03, b"\x00synthetic-signature"),
    )


def _pkcs7(
    certificate: bytes,
    *,
    issuer: bytes,
    serial: int,
    signing_time: bytes | None = b"260713143045Z",
    content_type: str = "1.2.840.113549.1.7.2",
) -> bytes:
    signed_attributes = b""
    if signing_time is not None:
        signing_time_attribute = _sequence(
            _oid("1.2.840.113549.1.9.5"),
            _set(_der(0x17, signing_time)),
        )
        signed_attributes = _der(0xA0, signing_time_attribute)
    signer_info = _sequence(
        _integer(1),
        _sequence(issuer, _integer(serial)),
        _algorithm("2.16.840.1.101.3.4.2.1"),
        signed_attributes,
        _algorithm("1.2.840.113549.1.1.1"),
        _der(0x04, b"synthetic-signature"),
    )
    signed_data = _sequence(
        _integer(1),
        _set(_algorithm("2.16.840.1.101.3.4.2.1")),
        _sequence(_oid("1.2.840.113549.1.7.1")),
        _der(0xA0, certificate),
        _set(signer_info),
    )
    return _sequence(_oid(content_type), _der(0xA0, signed_data))


def _win_certificate(
    blob: bytes,
    *,
    revision: int = WIN_CERT_REVISION_2_0,
    certificate_type: int = WIN_CERT_TYPE_PKCS_SIGNED_DATA,
) -> bytes:
    length = 8 + len(blob)
    result = struct.pack("<IHH", length, revision, certificate_type) + blob
    return result + b"\x00" * ((-length) % 8)


def _optional_header(
    *,
    pe32_plus: bool,
    certificate_offset: int,
    certificate_size: int,
) -> OptionalHeader:
    directories = tuple(
        DataDirectory(
            index,
            f"Directory {index}",
            certificate_offset if index == 4 else 0,
            certificate_size if index == 4 else 0,
        )
        for index in range(5)
    )
    return OptionalHeader(
        magic=0x20B if pe32_plus else 0x10B,
        format="PE32+" if pe32_plus else "PE32",
        major_linker_version=14,
        minor_linker_version=0,
        size_of_code=0,
        size_of_initialized_data=0,
        size_of_uninitialized_data=0,
        address_of_entry_point=0,
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
        size_of_image=0x4000,
        size_of_headers=0x400,
        checksum=0,
        subsystem=3,
        dll_characteristics=0,
        size_of_stack_reserve=0x100000,
        size_of_stack_commit=0x1000,
        size_of_heap_reserve=0x100000,
        size_of_heap_commit=0x1000,
        loader_flags=0,
        number_of_rva_and_sizes=5,
        data_directories=directories,
    )


def _signed_fixture(
    *,
    signing_time: bytes | None = b"260713143045Z",
) -> tuple[bytes, bytes, bytes]:
    issuer = _name("Acme Root", "Acme CA")
    subject = _name("Test Signer", "Acme, Inc.")
    certificate = _certificate(
        serial=0x1234,
        subject=subject,
        issuer=issuer,
    )
    table = _win_certificate(
        _pkcs7(
            certificate,
            issuer=issuer,
            serial=0x1234,
            signing_time=signing_time,
        )
    )
    data = b"MZ" + b"\x00" * (CERTIFICATE_OFFSET - 2) + table
    return data, table, certificate


class CertificateParserTests(unittest.TestCase):
    def test_parses_win_certificate_pkcs7_and_x509_metadata(self) -> None:
        data, table, certificate = _signed_fixture()
        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus):
                result = CertificateParser(
                    data,
                    _optional_header(
                        pe32_plus=pe32_plus,
                        certificate_offset=CERTIFICATE_OFFSET,
                        certificate_size=len(table),
                    ),
                ).parse()

                self.assertTrue(result.present)
                self.assertTrue(result.parsed)
                self.assertEqual(
                    result.subject,
                    "CN=Test Signer, O=Acme\\, Inc., C=US",
                )
                self.assertEqual(result.issuer, "CN=Acme Root, O=Acme CA, C=US")
                self.assertEqual(
                    result.signing_timestamp,
                    "2026-07-13T14:30:45Z",
                )
                self.assertEqual(
                    result.sha1_thumbprint,
                    hashlib.sha1(certificate).hexdigest().upper(),
                )
                self.assertEqual(result.signature_algorithm, "SHA-256 with RSA")
                self.assertEqual(result.valid_from, "2025-01-01T00:00:00Z")
                self.assertEqual(result.valid_to, "2030-01-01T00:00:00Z")
                self.assertFalse(result.trust_validation_performed)
                self.assertIn("not validated", result.trust_statement)
                self.assertIsNone(result.unavailable_reason)
                self.assertEqual(len(result.entries), 1)
                self.assertEqual(result.entries[0].file_offset, CERTIFICATE_OFFSET)
                self.assertEqual(
                    result.entries[0].certificates[0].serial_number,
                    "12:34",
                )

    def test_security_directory_address_is_used_as_a_file_offset(self) -> None:
        data, table, _ = _signed_fixture(signing_time=None)
        result = parse_certificates(
            data,
            _optional_header(
                pe32_plus=True,
                certificate_offset=CERTIFICATE_OFFSET,
                certificate_size=len(table),
            ),
        )
        self.assertTrue(result.parsed)
        self.assertIsNone(result.signing_timestamp)
        self.assertEqual(result.entries[0].file_offset, CERTIFICATE_OFFSET)

    def test_reports_unsigned_and_invalid_directory_ranges(self) -> None:
        empty = b"MZ" + b"\x00" * 100
        for pe32_plus in (False, True):
            with self.subTest(pe32_plus=pe32_plus, case="absent"):
                result = parse_certificates(
                    empty,
                    _optional_header(
                        pe32_plus=pe32_plus,
                        certificate_offset=0,
                        certificate_size=0,
                    ),
                )
                self.assertFalse(result.present)
                self.assertFalse(result.parsed)
                self.assertIn("absent", result.unavailable_reason or "")

            with self.subTest(pe32_plus=pe32_plus, case="pair"):
                result = parse_certificates(
                    empty,
                    _optional_header(
                        pe32_plus=pe32_plus,
                        certificate_offset=20,
                        certificate_size=0,
                    ),
                )
                self.assertFalse(result.parsed)
                self.assertIn("both", result.unavailable_reason or "")

            with self.subTest(pe32_plus=pe32_plus, case="range"):
                result = parse_certificates(
                    empty,
                    _optional_header(
                        pe32_plus=pe32_plus,
                        certificate_offset=100,
                        certificate_size=100,
                    ),
                )
                self.assertFalse(result.parsed)
                self.assertIn("outside", result.unavailable_reason or "")

    def test_unsupported_and_malformed_records_have_explicit_reasons(self) -> None:
        unsupported = _win_certificate(b"legacy", certificate_type=1)
        malformed_der = _win_certificate(b"not DER")
        table = unsupported + malformed_der
        data = b"\x00" * CERTIFICATE_OFFSET + table
        result = parse_certificates(
            data,
            _optional_header(
                pe32_plus=False,
                certificate_offset=CERTIFICATE_OFFSET,
                certificate_size=len(table),
            ),
        )
        self.assertTrue(result.present)
        self.assertFalse(result.parsed)
        self.assertEqual(len(result.entries), 2)
        self.assertIn("not PKCS#7", result.entries[0].unavailable_reason or "")
        self.assertIn("Malformed", result.entries[1].unavailable_reason or "")
        self.assertIn("not PKCS#7", result.unavailable_reason or "")

        truncated_header = struct.pack(
            "<IHH", 100, WIN_CERT_REVISION_2_0, WIN_CERT_TYPE_PKCS_SIGNED_DATA
        )
        data = b"\x00" * CERTIFICATE_OFFSET + truncated_header
        truncated = parse_certificates(
            data,
            _optional_header(
                pe32_plus=True,
                certificate_offset=CERTIFICATE_OFFSET,
                certificate_size=len(truncated_header),
            ),
        )
        self.assertFalse(truncated.parsed)
        self.assertIn("truncated", truncated.unavailable_reason or "")

    def test_models_are_immutable_and_serializable_without_trust_claims(self) -> None:
        data, table, _ = _signed_fixture()
        result = parse_certificates(
            data,
            _optional_header(
                pe32_plus=False,
                certificate_offset=CERTIFICATE_OFFSET,
                certificate_size=len(table),
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            result.subject = "Changed"  # type: ignore[misc]

        value = result.to_dict()
        self.assertTrue(value["present"])
        self.assertFalse(value["trust_validation_performed"])
        self.assertIsInstance(value["entries"], list)
        self.assertIsInstance(value["entries"][0]["certificates"], list)
        self.assertEqual(
            value["entries"][0]["certificates"][0]["signature_algorithm_oid"],
            "1.2.840.113549.1.1.11",
        )

    def test_rejects_certificate_tables_over_the_byte_budget(self) -> None:
        table = _win_certificate(b"legacy", certificate_type=1)
        data = b"\x00" * CERTIFICATE_OFFSET + table
        optional_header = _optional_header(
            pe32_plus=False,
            certificate_offset=CERTIFICATE_OFFSET,
            certificate_size=len(table),
        )

        with patch(
            "pe.certificates._MAX_CERTIFICATE_TABLE_BYTES",
            len(table) - 1,
        ):
            result = parse_certificates(data, optional_header)

        self.assertTrue(result.present)
        self.assertFalse(result.parsed)
        self.assertEqual(result.entries, ())
        self.assertIn(f"{len(table):,} bytes", result.unavailable_reason or "")
        self.assertIn("inspection safety limit", result.unavailable_reason or "")

    def test_entry_budget_preserves_valid_multi_entry_results(self) -> None:
        _, signed_entry, _ = _signed_fixture()
        table = signed_entry + signed_entry
        data = b"\x00" * CERTIFICATE_OFFSET + table
        optional_header = _optional_header(
            pe32_plus=True,
            certificate_offset=CERTIFICATE_OFFSET,
            certificate_size=len(table),
        )

        complete = parse_certificates(data, optional_header)
        self.assertTrue(complete.parsed)
        self.assertEqual(len(complete.entries), 2)
        self.assertIsNone(complete.unavailable_reason)

        with patch("pe.certificates._MAX_WIN_CERTIFICATE_ENTRIES", 1):
            capped = parse_certificates(data, optional_header)

        self.assertTrue(capped.parsed)
        self.assertEqual(len(capped.entries), 1)
        self.assertIn("more than", capped.unavailable_reason or "")
        self.assertIn(
            "1-entry inspection safety limit",
            capped.unavailable_reason or "",
        )

    def test_entry_scanning_does_not_copy_each_remaining_table_suffix(self) -> None:
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

        entry = struct.pack("<IHH", 8, WIN_CERT_REVISION_2_0, 1)
        table = entry * 32
        data = TrackingBytes(b"\x00" * CERTIFICATE_OFFSET + table)
        result = parse_certificates(
            data,
            _optional_header(
                pe32_plus=False,
                certificate_offset=CERTIFICATE_OFFSET,
                certificate_size=len(table),
            ),
        )

        self.assertEqual(len(result.entries), 32)
        self.assertEqual(max(data.slice_lengths, default=0), 0)


if __name__ == "__main__":
    unittest.main()
