"""Manual PE certificate-table and limited PKCS#7/X.509 inspection.

This module intentionally performs metadata extraction only.  It does not
verify signatures, certificate chains, revocation, or trust anchors.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import struct
from typing import Any, Final

from pe.models import OptionalHeader


CERTIFICATE_DIRECTORY_INDEX: Final = 4
WIN_CERT_REVISION_1_0: Final = 0x0100
WIN_CERT_REVISION_2_0: Final = 0x0200
WIN_CERT_TYPE_PKCS_SIGNED_DATA: Final = 0x0002

_OID_SIGNED_DATA: Final = "1.2.840.113549.1.7.2"
_OID_SIGNING_TIME: Final = "1.2.840.113549.1.9.5"
_MAX_DER_DEPTH: Final = 48
_MAX_DER_NODES: Final = 100_000
_MAX_CERTIFICATE_TABLE_BYTES: Final = 64 * 1024 * 1024
_MAX_WIN_CERTIFICATE_ENTRIES: Final = 4_096

_SIGNATURE_ALGORITHMS: Final[dict[str, str]] = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.113549.1.1.5": "SHA-1 with RSA",
    "1.2.840.113549.1.1.11": "SHA-256 with RSA",
    "1.2.840.113549.1.1.12": "SHA-384 with RSA",
    "1.2.840.113549.1.1.13": "SHA-512 with RSA",
    "1.2.840.10040.4.3": "SHA-1 with DSA",
    "1.2.840.10045.4.1": "SHA-1 with ECDSA",
    "1.2.840.10045.4.3.2": "SHA-256 with ECDSA",
    "1.2.840.10045.4.3.3": "SHA-384 with ECDSA",
    "1.2.840.10045.4.3.4": "SHA-512 with ECDSA",
}

_DISTINGUISHED_NAME_KEYS: Final[dict[str, str]] = {
    "2.5.4.3": "CN",
    "2.5.4.4": "SN",
    "2.5.4.5": "SERIALNUMBER",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "STREET",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.12": "T",
    "2.5.4.42": "GIVENNAME",
    "1.2.840.113549.1.9.1": "E",
}


@dataclass(frozen=True, slots=True)
class CertificateInfo:
    """Displayable metadata from one embedded X.509 certificate."""

    subject: str
    issuer: str
    serial_number: str
    sha1_thumbprint: str
    signature_algorithm: str
    signature_algorithm_oid: str
    valid_from: str | None
    valid_to: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "sha1_thumbprint": self.sha1_thumbprint,
            "signature_algorithm": self.signature_algorithm,
            "signature_algorithm_oid": self.signature_algorithm_oid,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
        }


@dataclass(frozen=True, slots=True)
class WinCertificateInfo:
    """One aligned ``WIN_CERTIFICATE`` record."""

    index: int
    file_offset: int
    length: int
    revision: int
    certificate_type: int
    certificate_type_name: str
    certificates: tuple[CertificateInfo, ...]
    signing_timestamp: str | None
    unavailable_reason: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "file_offset": self.file_offset,
            "length": self.length,
            "revision": self.revision,
            "certificate_type": self.certificate_type,
            "certificate_type_name": self.certificate_type_name,
            "certificates": [item.to_dict() for item in self.certificates],
            "signing_timestamp": self.signing_timestamp,
            "unavailable_reason": self.unavailable_reason,
        }


@dataclass(frozen=True, slots=True)
class CertificateAnalysis:
    """Consolidated certificate-table metadata for an image."""

    present: bool
    parsed: bool
    subject: str | None
    issuer: str | None
    signing_timestamp: str | None
    sha1_thumbprint: str | None
    signature_algorithm: str | None
    valid_from: str | None
    valid_to: str | None
    entries: tuple[WinCertificateInfo, ...]
    unavailable_reason: str | None
    trust_validation_performed: bool = False
    trust_statement: str = (
        "Metadata only; cryptographic signature and certificate trust were "
        "not validated."
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "present": self.present,
            "parsed": self.parsed,
            "subject": self.subject,
            "issuer": self.issuer,
            "signing_timestamp": self.signing_timestamp,
            "sha1_thumbprint": self.sha1_thumbprint,
            "signature_algorithm": self.signature_algorithm,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "entries": [entry.to_dict() for entry in self.entries],
            "unavailable_reason": self.unavailable_reason,
            "trust_validation_performed": self.trust_validation_performed,
            "trust_statement": self.trust_statement,
        }


@dataclass(frozen=True, slots=True)
class _DERNode:
    tag_class: int
    constructed: bool
    tag: int
    start: int
    value_start: int
    end: int
    children: tuple[_DERNode, ...]

    def encoded(self, data: bytes) -> bytes:
        return data[self.start : self.end]

    def value(self, data: bytes) -> bytes:
        return data[self.value_start : self.end]


@dataclass(slots=True)
class _DERBudget:
    nodes: int = 0


@dataclass(frozen=True, slots=True)
class _CertificateCandidate:
    info: CertificateInfo
    serial_number: int
    issuer_der: bytes


class _CertificateFormatError(ValueError):
    pass


class CertificateParser:
    """Parse the file-offset-based PE security directory and PKCS#7 blobs."""

    _WIN_CERTIFICATE_HEADER = struct.Struct("<IHH")

    def __init__(self, data: bytes, optional_header: OptionalHeader) -> None:
        self._data = data
        self._optional_header = optional_header

    def parse(self) -> CertificateAnalysis:
        directories = self._optional_header.data_directories
        if len(directories) <= CERTIFICATE_DIRECTORY_INDEX:
            return self._unavailable(
                present=False,
                reason="No Certificate Table data-directory entry is present.",
            )

        directory = directories[CERTIFICATE_DIRECTORY_INDEX]
        file_offset = directory.virtual_address
        table_size = directory.size
        if file_offset == 0 and table_size == 0:
            return self._unavailable(
                present=False,
                reason="The Certificate Table is absent.",
            )
        if file_offset == 0 or table_size == 0:
            return self._unavailable(
                present=False,
                reason=(
                    "Certificate Table file offset and size must either both "
                    "be zero or both be nonzero."
                ),
            )
        if file_offset < 0 or table_size < 0:
            return self._unavailable(
                present=False,
                reason="Certificate Table has a negative file range.",
            )
        if (
            file_offset > len(self._data)
            or table_size > len(self._data) - file_offset
        ):
            return self._unavailable(
                present=False,
                reason="Certificate Table file range is outside the image.",
            )
        if table_size > _MAX_CERTIFICATE_TABLE_BYTES:
            return self._unavailable(
                present=True,
                reason=(
                    f"Certificate Table declares {table_size:,} bytes, which "
                    f"exceeds the {_MAX_CERTIFICATE_TABLE_BYTES:,}-byte "
                    "inspection safety limit."
                ),
            )

        entries: list[WinCertificateInfo] = []
        cursor = file_offset
        table_end = file_offset + table_size
        index = 1
        table_error: str | None = None
        while cursor < table_end:
            remaining = table_end - cursor
            if remaining < self._WIN_CERTIFICATE_HEADER.size:
                if self._range_has_nonzero(cursor, table_end):
                    table_error = "Certificate Table has a truncated trailing header."
                break

            length, revision, certificate_type = (
                self._WIN_CERTIFICATE_HEADER.unpack_from(self._data, cursor)
            )
            if length == 0 and revision == 0 and certificate_type == 0:
                if self._range_has_nonzero(cursor, table_end):
                    table_error = (
                        "Certificate Table contains nonzero data after a "
                        "zero-filled entry boundary."
                    )
                break
            if len(entries) >= _MAX_WIN_CERTIFICATE_ENTRIES:
                table_error = (
                    "Certificate Table contains more than the "
                    f"{_MAX_WIN_CERTIFICATE_ENTRIES:,}-entry inspection "
                    "safety limit."
                )
                break
            if length < self._WIN_CERTIFICATE_HEADER.size:
                table_error = (
                    f"WIN_CERTIFICATE entry {index} has invalid length {length}."
                )
                break
            if length > remaining:
                table_error = f"WIN_CERTIFICATE entry {index} is truncated."
                break
            blob_start = cursor + self._WIN_CERTIFICATE_HEADER.size
            blob = self._data[blob_start : cursor + length]
            entries.append(
                self._parse_win_certificate(
                    index=index,
                    file_offset=cursor,
                    length=length,
                    revision=revision,
                    certificate_type=certificate_type,
                    blob=blob,
                )
            )
            aligned_length = (length + 7) & ~7
            if aligned_length > remaining:
                if length != remaining:
                    table_error = (
                        f"WIN_CERTIFICATE entry {index} has truncated alignment "
                        "padding."
                    )
                cursor += length
            else:
                cursor += aligned_length
            index += 1

        primary_entry: WinCertificateInfo | None = None
        primary_certificate: CertificateInfo | None = None
        for entry in entries:
            if entry.certificates:
                primary_entry = entry
                primary_certificate = entry.certificates[0]
                break

        reasons = [
            entry.unavailable_reason
            for entry in entries
            if entry.unavailable_reason is not None
        ]
        if table_error:
            reasons.append(table_error)
        if primary_certificate is None:
            reason = "; ".join(reasons) or (
                "No supported PKCS#7 signer certificate was found."
            )
            return self._unavailable(
                present=True,
                reason=reason,
                entries=tuple(entries),
            )

        return CertificateAnalysis(
            present=True,
            parsed=True,
            subject=primary_certificate.subject,
            issuer=primary_certificate.issuer,
            signing_timestamp=(
                primary_entry.signing_timestamp
                if primary_entry is not None
                else None
            ),
            sha1_thumbprint=primary_certificate.sha1_thumbprint,
            signature_algorithm=primary_certificate.signature_algorithm,
            valid_from=primary_certificate.valid_from,
            valid_to=primary_certificate.valid_to,
            entries=tuple(entries),
            unavailable_reason="; ".join(reasons) if reasons else None,
        )

    def _range_has_nonzero(self, start: int, end: int) -> bool:
        """Inspect a bounded range without allocating a remainder-sized copy."""

        return any(memoryview(self._data)[start:end])

    @staticmethod
    def _unavailable(
        *,
        present: bool,
        reason: str,
        entries: tuple[WinCertificateInfo, ...] = (),
    ) -> CertificateAnalysis:
        return CertificateAnalysis(
            present=present,
            parsed=False,
            subject=None,
            issuer=None,
            signing_timestamp=None,
            sha1_thumbprint=None,
            signature_algorithm=None,
            valid_from=None,
            valid_to=None,
            entries=entries,
            unavailable_reason=reason,
        )

    def _parse_win_certificate(
        self,
        *,
        index: int,
        file_offset: int,
        length: int,
        revision: int,
        certificate_type: int,
        blob: bytes,
    ) -> WinCertificateInfo:
        type_name = (
            "PKCS#7 SignedData"
            if certificate_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA
            else f"Unsupported type 0x{certificate_type:04X}"
        )
        if revision not in {WIN_CERT_REVISION_1_0, WIN_CERT_REVISION_2_0}:
            return WinCertificateInfo(
                index=index,
                file_offset=file_offset,
                length=length,
                revision=revision,
                certificate_type=certificate_type,
                certificate_type_name=type_name,
                certificates=(),
                signing_timestamp=None,
                unavailable_reason=(
                    f"Unsupported WIN_CERTIFICATE revision 0x{revision:04X}."
                ),
            )
        if certificate_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA:
            return WinCertificateInfo(
                index=index,
                file_offset=file_offset,
                length=length,
                revision=revision,
                certificate_type=certificate_type,
                certificate_type_name=type_name,
                certificates=(),
                signing_timestamp=None,
                unavailable_reason=(
                    f"WIN_CERTIFICATE type 0x{certificate_type:04X} is not "
                    "PKCS#7 SignedData."
                ),
            )

        try:
            candidates, timestamp = self._parse_pkcs7(blob)
            certificates = tuple(candidate.info for candidate in candidates)
            if not certificates:
                raise _CertificateFormatError(
                    "PKCS#7 SignedData contains no parseable X.509 certificate"
                )
            return WinCertificateInfo(
                index=index,
                file_offset=file_offset,
                length=length,
                revision=revision,
                certificate_type=certificate_type,
                certificate_type_name=type_name,
                certificates=certificates,
                signing_timestamp=timestamp,
                unavailable_reason=None,
            )
        except _CertificateFormatError as error:
            return WinCertificateInfo(
                index=index,
                file_offset=file_offset,
                length=length,
                revision=revision,
                certificate_type=certificate_type,
                certificate_type_name=type_name,
                certificates=(),
                signing_timestamp=None,
                unavailable_reason=f"Malformed or unsupported PKCS#7 data: {error}.",
            )

    def _parse_pkcs7(
        self,
        blob: bytes,
    ) -> tuple[tuple[_CertificateCandidate, ...], str | None]:
        root, end = self._read_der_node(
            blob,
            0,
            len(blob),
            depth=0,
            budget=_DERBudget(),
        )
        if end != len(blob) and any(blob[end:]):
            raise _CertificateFormatError("trailing bytes follow PKCS#7 ContentInfo")
        self._require_tag(root, 0, 16, "PKCS#7 ContentInfo SEQUENCE")
        if len(root.children) < 2:
            raise _CertificateFormatError("truncated PKCS#7 ContentInfo")
        content_type = self._decode_oid_node(blob, root.children[0])
        if content_type != _OID_SIGNED_DATA:
            raise _CertificateFormatError(
                f"content type {content_type} is not SignedData"
            )
        wrapper = root.children[1]
        self._require_tag(wrapper, 2, 0, "SignedData explicit wrapper")
        if not wrapper.children:
            raise _CertificateFormatError("SignedData wrapper is empty")
        signed_data = wrapper.children[0]
        self._require_tag(signed_data, 0, 16, "SignedData SEQUENCE")

        certificate_container = next(
            (
                child
                for child in signed_data.children
                if child.tag_class == 2 and child.tag == 0
            ),
            None,
        )
        candidates: list[_CertificateCandidate] = []
        if certificate_container is not None:
            for node in certificate_container.children:
                if node.tag_class == 0 and node.tag == 16:
                    try:
                        candidates.append(self._parse_x509(blob, node))
                    except _CertificateFormatError:
                        continue

        signer_issuer, signer_serial = self._signer_identifier(blob, signed_data)
        if signer_serial is not None:
            candidates.sort(
                key=lambda candidate: not (
                    candidate.serial_number == signer_serial
                    and (
                        signer_issuer is None
                        or candidate.issuer_der == signer_issuer
                    )
                )
            )
        timestamp = self._find_signing_time(blob, signed_data)
        return tuple(candidates), timestamp

    def _parse_x509(
        self,
        data: bytes,
        certificate: _DERNode,
    ) -> _CertificateCandidate:
        if len(certificate.children) < 3:
            raise _CertificateFormatError("truncated X.509 Certificate")
        tbs = certificate.children[0]
        self._require_tag(tbs, 0, 16, "TBSCertificate SEQUENCE")
        children = tbs.children
        index = 0
        if children and children[0].tag_class == 2 and children[0].tag == 0:
            index += 1
        if len(children) < index + 6:
            raise _CertificateFormatError("truncated TBSCertificate")

        serial_node = children[index]
        self._require_tag(serial_node, 0, 2, "certificate serial INTEGER")
        serial_number = int.from_bytes(serial_node.value(data), "big", signed=False)
        issuer_node = children[index + 2]
        validity_node = children[index + 3]
        subject_node = children[index + 4]
        issuer = self._decode_name(data, issuer_node)
        subject = self._decode_name(data, subject_node)
        valid_from, valid_to = self._decode_validity(data, validity_node)

        algorithm_node = certificate.children[1]
        self._require_tag(
            algorithm_node, 0, 16, "certificate signature AlgorithmIdentifier"
        )
        if not algorithm_node.children:
            raise _CertificateFormatError("empty signature AlgorithmIdentifier")
        algorithm_oid = self._decode_oid_node(data, algorithm_node.children[0])
        algorithm = _SIGNATURE_ALGORITHMS.get(
            algorithm_oid,
            f"Unknown ({algorithm_oid})",
        )
        encoded = certificate.encoded(data)
        thumbprint = hashlib.sha1(encoded).hexdigest().upper()
        info = CertificateInfo(
            subject=subject,
            issuer=issuer,
            serial_number=self._format_serial(serial_node.value(data)),
            sha1_thumbprint=thumbprint,
            signature_algorithm=algorithm,
            signature_algorithm_oid=algorithm_oid,
            valid_from=valid_from,
            valid_to=valid_to,
        )
        return _CertificateCandidate(
            info=info,
            serial_number=serial_number,
            issuer_der=issuer_node.encoded(data),
        )

    @staticmethod
    def _format_serial(value: bytes) -> str:
        normalized = value.lstrip(b"\x00") or b"\x00"
        return ":".join(f"{byte:02X}" for byte in normalized)

    def _decode_name(self, data: bytes, node: _DERNode) -> str:
        self._require_tag(node, 0, 16, "X.509 Name SEQUENCE")
        attributes: list[str] = []
        for rdn in node.children:
            if rdn.tag_class != 0 or rdn.tag != 17:
                continue
            for attribute in rdn.children:
                if (
                    attribute.tag_class != 0
                    or attribute.tag != 16
                    or len(attribute.children) < 2
                ):
                    continue
                oid = self._decode_oid_node(data, attribute.children[0])
                key = _DISTINGUISHED_NAME_KEYS.get(oid, oid)
                value = self._decode_asn1_string(data, attribute.children[1])
                escaped = value.replace("\\", "\\\\").replace(",", "\\,")
                attributes.append(f"{key}={escaped}")
        return ", ".join(attributes) if attributes else "(unavailable)"

    def _decode_validity(
        self,
        data: bytes,
        node: _DERNode,
    ) -> tuple[str | None, str | None]:
        self._require_tag(node, 0, 16, "certificate Validity SEQUENCE")
        if len(node.children) < 2:
            return None, None
        return (
            self._decode_time_node(data, node.children[0]),
            self._decode_time_node(data, node.children[1]),
        )

    def _signer_identifier(
        self,
        data: bytes,
        signed_data: _DERNode,
    ) -> tuple[bytes | None, int | None]:
        signer_sets = [
            child
            for child in signed_data.children
            if child.tag_class == 0 and child.tag == 17
        ]
        if not signer_sets:
            return None, None
        signer_set = signer_sets[-1]
        for signer in signer_set.children:
            if signer.tag_class != 0 or signer.tag != 16:
                continue
            if len(signer.children) < 2:
                continue
            sid = signer.children[1]
            if sid.tag_class != 0 or sid.tag != 16 or len(sid.children) < 2:
                continue
            serial = sid.children[1]
            if serial.tag_class != 0 or serial.tag != 2:
                continue
            return sid.children[0].encoded(data), int.from_bytes(
                serial.value(data), "big", signed=False
            )
        return None, None

    def _find_signing_time(
        self,
        data: bytes,
        node: _DERNode,
    ) -> str | None:
        if node.tag_class == 0 and node.tag == 16 and len(node.children) >= 2:
            first = node.children[0]
            if first.tag_class == 0 and first.tag == 6:
                try:
                    oid = self._decode_oid_node(data, first)
                except _CertificateFormatError:
                    oid = ""
                if oid == _OID_SIGNING_TIME:
                    for child in node.children[1].children:
                        decoded = self._decode_time_node(data, child)
                        if decoded is not None:
                            return decoded
        for child in node.children:
            decoded = self._find_signing_time(data, child)
            if decoded is not None:
                return decoded
        return None

    @staticmethod
    def _decode_time_node(data: bytes, node: _DERNode) -> str | None:
        if node.tag_class != 0 or node.tag not in {23, 24}:
            return None
        try:
            value = node.value(data).decode("ascii")
            parsed = CertificateParser._parse_asn1_time(value, node.tag == 23)
        except (UnicodeDecodeError, ValueError):
            return None
        return parsed.isoformat().replace("+00:00", "Z")

    @staticmethod
    def _parse_asn1_time(value: str, utc_time: bool) -> datetime:
        zone: timezone
        if value.endswith("Z"):
            zone = timezone.utc
            body = value[:-1]
        elif len(value) >= 5 and value[-5] in {"+", "-"}:
            sign = 1 if value[-5] == "+" else -1
            hours = int(value[-4:-2])
            minutes = int(value[-2:])
            zone = timezone(sign * timedelta(hours=hours, minutes=minutes))
            body = value[:-5]
        else:
            raise ValueError("ASN.1 time has no timezone")

        if utc_time:
            if len(body) not in {10, 12}:
                raise ValueError("invalid UTCTime length")
            year_two_digits = int(body[:2])
            year = (
                2000 + year_two_digits
                if year_two_digits < 50
                else 1900 + year_two_digits
            )
            remainder = body[2:]
            format_string = (
                "%Y%m%d%H%M%S" if len(remainder) == 10 else "%Y%m%d%H%M"
            )
            parsed = datetime.strptime(f"{year:04d}{remainder}", format_string)
        else:
            if "." in body:
                main, fraction = body.split(".", 1)
                microseconds = int((fraction + "000000")[:6])
            else:
                main = body
                microseconds = 0
            if len(main) not in {12, 14}:
                raise ValueError("invalid GeneralizedTime length")
            format_string = "%Y%m%d%H%M%S" if len(main) == 14 else "%Y%m%d%H%M"
            parsed = datetime.strptime(main, format_string).replace(
                microsecond=microseconds
            )
        return parsed.replace(tzinfo=zone).astimezone(timezone.utc)

    @staticmethod
    def _decode_asn1_string(data: bytes, node: _DERNode) -> str:
        value = node.value(data)
        try:
            if node.tag in {12}:
                return value.decode("utf-8")
            if node.tag in {18, 19, 20, 22, 26}:
                return value.decode("ascii", errors="replace")
            if node.tag == 30:
                return value.decode("utf-16-be")
            if node.tag == 28:
                return value.decode("utf-32-be")
        except UnicodeDecodeError:
            pass
        return value.hex().upper()

    def _decode_oid_node(self, data: bytes, node: _DERNode) -> str:
        self._require_tag(node, 0, 6, "OBJECT IDENTIFIER")
        value = node.value(data)
        if not value:
            raise _CertificateFormatError("empty OBJECT IDENTIFIER")
        components: list[int] = []
        accumulator = 0
        in_component = False
        for byte in value:
            in_component = True
            accumulator = (accumulator << 7) | (byte & 0x7F)
            if accumulator > 0xFFFFFFFFFFFFFFFF:
                raise _CertificateFormatError("OBJECT IDENTIFIER arc is too large")
            if not byte & 0x80:
                components.append(accumulator)
                accumulator = 0
                in_component = False
        if in_component:
            raise _CertificateFormatError("truncated OBJECT IDENTIFIER")
        if not components:
            raise _CertificateFormatError("empty OBJECT IDENTIFIER")
        first_component = components[0]
        first_arc = min(first_component // 40, 2)
        arcs = [first_arc, first_component - first_arc * 40]
        arcs.extend(components[1:])
        return ".".join(str(arc) for arc in arcs)

    def _read_der_node(
        self,
        data: bytes,
        offset: int,
        limit: int,
        *,
        depth: int,
        budget: _DERBudget,
    ) -> tuple[_DERNode, int]:
        if depth > _MAX_DER_DEPTH:
            raise _CertificateFormatError("DER nesting is too deep")
        budget.nodes += 1
        if budget.nodes > _MAX_DER_NODES:
            raise _CertificateFormatError("DER input has too many elements")
        if offset < 0 or limit > len(data) or offset >= limit:
            raise _CertificateFormatError("truncated DER identifier")

        start = offset
        identifier = data[offset]
        offset += 1
        tag_class = identifier >> 6
        constructed = bool(identifier & 0x20)
        tag = identifier & 0x1F
        if tag == 0x1F:
            tag = 0
            tag_octets = 0
            while True:
                if offset >= limit:
                    raise _CertificateFormatError("truncated high-tag DER identifier")
                byte = data[offset]
                offset += 1
                tag_octets += 1
                if tag_octets > 5:
                    raise _CertificateFormatError("DER tag is too large")
                tag = (tag << 7) | (byte & 0x7F)
                if not byte & 0x80:
                    break

        if offset >= limit:
            raise _CertificateFormatError("truncated DER length")
        first_length = data[offset]
        offset += 1
        if first_length < 0x80:
            length = first_length
        else:
            length_octets = first_length & 0x7F
            if length_octets == 0:
                raise _CertificateFormatError(
                    "indefinite-length BER is unsupported"
                )
            if length_octets > 8 or offset + length_octets > limit:
                raise _CertificateFormatError("invalid DER long-form length")
            encoded_length = data[offset : offset + length_octets]
            if encoded_length[0] == 0:
                raise _CertificateFormatError("non-minimal DER length")
            length = int.from_bytes(encoded_length, "big")
            offset += length_octets
            if length < 0x80:
                raise _CertificateFormatError("non-minimal DER long-form length")
        if length > limit - offset:
            raise _CertificateFormatError("DER value exceeds its container")
        value_start = offset
        end = offset + length

        children: list[_DERNode] = []
        if constructed:
            cursor = value_start
            while cursor < end:
                child, cursor = self._read_der_node(
                    data,
                    cursor,
                    end,
                    depth=depth + 1,
                    budget=budget,
                )
                children.append(child)
        return (
            _DERNode(
                tag_class=tag_class,
                constructed=constructed,
                tag=tag,
                start=start,
                value_start=value_start,
                end=end,
                children=tuple(children),
            ),
            end,
        )

    @staticmethod
    def _require_tag(
        node: _DERNode,
        tag_class: int,
        tag: int,
        context: str,
    ) -> None:
        if node.tag_class != tag_class or node.tag != tag:
            raise _CertificateFormatError(f"invalid {context}")


def parse_certificates(
    data: bytes,
    optional_header: OptionalHeader,
) -> CertificateAnalysis:
    """Convenience wrapper for certificate-table inspection."""

    return CertificateParser(data, optional_header).parse()


__all__ = [
    "CERTIFICATE_DIRECTORY_INDEX",
    "CertificateAnalysis",
    "CertificateInfo",
    "CertificateParser",
    "WinCertificateInfo",
    "parse_certificates",
]
