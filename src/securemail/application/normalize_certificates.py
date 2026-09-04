"""Normalize extracted certificate DER into canonical `CertificateEvidence` records."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import SignatureAlgorithmOID

from securemail.domain.evidence.certificate import (
    MAX_ASN1_DEPTH,
    MAX_CERTIFICATE_DER_BYTES,
    MAX_CERTIFICATES_PER_RUN,
    CertificateEvidence,
    CertificateRole,
)
from securemail.domain.evidence.handshake import HandshakeMessageKind, TlsHandshake
from securemail.domain.evidence.run import EvidenceState
from securemail.domain.policies.pki.key_strength import effective_strength_bits
from securemail.ports.analyzers import ExtractedCertificate
from securemail.ports.artifacts import ArtifactStore

_MAX_UID_LEN = 64
_MAX_FUID_LEN = 64
_MAX_FP_LEN = 64
_MAX_RECORDS = 10_000
_MAX_NAME_LEN = 512
_MAX_ERROR_LEN = 128
_MAX_SERIAL_LEN = 128
_MAX_CHAIN = 16

_SIGNATURE_ALGORITHM_NAMES: dict[x509.ObjectIdentifier, str] = {
    SignatureAlgorithmOID.RSA_WITH_SHA1: "sha1WithRSAEncryption",
    SignatureAlgorithmOID.RSA_WITH_SHA224: "sha224WithRSAEncryption",
    SignatureAlgorithmOID.RSA_WITH_SHA256: "sha256WithRSAEncryption",
    SignatureAlgorithmOID.RSA_WITH_SHA384: "sha384WithRSAEncryption",
    SignatureAlgorithmOID.RSA_WITH_SHA512: "sha512WithRSAEncryption",
    SignatureAlgorithmOID.RSASSA_PSS: "rsassaPss",
    SignatureAlgorithmOID.ECDSA_WITH_SHA1: "ecdsa-with-SHA1",
    SignatureAlgorithmOID.ECDSA_WITH_SHA224: "ecdsa-with-SHA224",
    SignatureAlgorithmOID.ECDSA_WITH_SHA256: "ecdsa-with-SHA256",
    SignatureAlgorithmOID.ECDSA_WITH_SHA384: "ecdsa-with-SHA384",
    SignatureAlgorithmOID.ECDSA_WITH_SHA512: "ecdsa-with-SHA512",
    SignatureAlgorithmOID.DSA_WITH_SHA1: "dsaWithSHA1",
    SignatureAlgorithmOID.DSA_WITH_SHA224: "dsa-with-SHA224",
    SignatureAlgorithmOID.DSA_WITH_SHA256: "dsa-with-SHA256",
    SignatureAlgorithmOID.ED25519: "Ed25519",
    SignatureAlgorithmOID.ED448: "Ed448",
}


class _ParsedCertificate:
    __slots__ = (
        "effective_strength_bits",
        "issuer",
        "not_after",
        "not_before",
        "public_key_algorithm",
        "public_key_curve",
        "public_key_size",
        "serial_number",
        "signature_algorithm",
        "subject",
        "syntax_error",
        "syntax_valid",
    )

    def __init__(
        self,
        *,
        syntax_valid: bool,
        syntax_error: str | None = None,
        subject: str | None = None,
        issuer: str | None = None,
        serial_number: str | None = None,
        not_before: datetime | None = None,
        not_after: datetime | None = None,
        public_key_algorithm: str | None = None,
        public_key_size: int | None = None,
        public_key_curve: str | None = None,
        effective_strength_bits: int | None = None,
        signature_algorithm: str | None = None,
    ) -> None:
        self.syntax_valid = syntax_valid
        self.syntax_error = syntax_error
        self.subject = subject
        self.issuer = issuer
        self.serial_number = serial_number
        self.not_before = not_before
        self.not_after = not_after
        self.public_key_algorithm = public_key_algorithm
        self.public_key_size = public_key_size
        self.public_key_curve = public_key_curve
        self.effective_strength_bits = effective_strength_bits
        self.signature_algorithm = signature_algorithm


def _as_mapping(value: object) -> Mapping[str, object] | None:
    if isinstance(value, Mapping):
        return cast(Mapping[str, object], value)
    return None


def _as_str(value: object, *, max_len: int) -> str | None:
    if isinstance(value, str):
        if not value or len(value) > max_len:
            return None
        return value
    return None


def _as_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and value.is_integer() and value >= 0:
        return int(value)
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _as_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    return None


def _as_str_list(value: object, *, max_len: int, limit: int) -> list[str]:
    if isinstance(value, str):
        parts = [part.strip() for part in value.split(",") if part.strip()]
        return [part.lower() for part in parts[:limit] if len(part) <= max_len]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        out: list[str] = []
        for item in list(value)[:limit]:
            text = _as_str(item, max_len=max_len)
            if text is not None:
                out.append(text.lower())
        return out
    return []


def _bounded_records(rows: object, *, limit: int = _MAX_RECORDS) -> list[Mapping[str, object]]:
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        return []
    out: list[Mapping[str, object]] = []
    for item in rows[:limit]:
        mapping = _as_mapping(item)
        if mapping is not None:
            out.append(mapping)
    return out


def _bound_text(value: str | None, *, max_len: int) -> str | None:
    if value is None:
        return None
    if len(value) <= max_len:
        return value
    return value[:max_len]


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def der_nesting_depth(data: bytes, *, max_depth: int = MAX_ASN1_DEPTH) -> int:
    """Return observed constructed-type depth, or max_depth+1 on hostile length."""

    def walk(offset: int, end: int, depth: int) -> int:
        if depth > max_depth:
            return depth
        deepest = depth
        cursor = offset
        while cursor < end:
            if cursor >= len(data):
                return max_depth + 1
            tag = data[cursor]
            cursor += 1
            if (tag & 0x1F) == 0x1F:
                while cursor < end and data[cursor] & 0x80:
                    cursor += 1
                cursor += 1
            if cursor >= end:
                return max_depth + 1
            first = data[cursor]
            cursor += 1
            if first == 0x80:
                return max_depth + 1
            if first & 0x80:
                length_bytes = first & 0x7F
                if length_bytes == 0 or length_bytes > 4 or cursor + length_bytes > end:
                    return max_depth + 1
                length = int.from_bytes(data[cursor : cursor + length_bytes], "big")
                cursor += length_bytes
            else:
                length = first
            value_end = cursor + length
            if length < 0 or value_end > end:
                return max_depth + 1
            if tag & 0x20:
                deepest = max(deepest, walk(cursor, value_end, depth + 1))
                if deepest > max_depth:
                    return deepest
            cursor = value_end
        return deepest

    if not data:
        return 0
    return walk(0, len(data), 0)


def _fingerprint(value: str) -> str:
    return value.replace(":", "").strip().lower()


def _epoch_to_datetime(value: object) -> datetime | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if value < 0:
            return None
        return datetime.fromtimestamp(float(value), tz=UTC)
    if isinstance(value, str):
        try:
            return datetime.fromtimestamp(float(value), tz=UTC)
        except ValueError:
            return None
    return None


def _public_key_facts(
    certificate: x509.Certificate,
) -> tuple[str | None, int | None, str | None]:
    key = certificate.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size, None
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size, None
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ECDSA", key.curve.key_size, key.curve.name
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, "ed25519"
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 456, "ed448"
    return key.__class__.__name__.removesuffix("PublicKey") or None, None, None


def parse_certificate_der(payload: bytes) -> _ParsedCertificate:
    """Bound and parse DER bytes. Never raises for malformed input."""

    if len(payload) > MAX_CERTIFICATE_DER_BYTES:
        return _ParsedCertificate(
            syntax_valid=False,
            syntax_error="certificate_exceeds_size_limit",
        )
    if der_nesting_depth(payload) > MAX_ASN1_DEPTH:
        return _ParsedCertificate(
            syntax_valid=False,
            syntax_error="certificate_asn1_nesting_exceeds_limit",
        )
    try:
        certificate = x509.load_der_x509_certificate(payload)
    except ValueError:
        return _ParsedCertificate(
            syntax_valid=False,
            syntax_error="certificate_der_invalid",
        )
    except Exception:
        return _ParsedCertificate(
            syntax_valid=False,
            syntax_error="certificate_parse_failed",
        )
    algorithm, size, curve = _public_key_facts(certificate)
    serial = format(certificate.serial_number, "x")
    return _ParsedCertificate(
        syntax_valid=True,
        subject=_bound_text(certificate.subject.rfc4514_string(), max_len=_MAX_NAME_LEN),
        issuer=_bound_text(certificate.issuer.rfc4514_string(), max_len=_MAX_NAME_LEN),
        serial_number=_bound_text(serial, max_len=_MAX_SERIAL_LEN),
        not_before=_as_utc(certificate.not_valid_before_utc),
        not_after=_as_utc(certificate.not_valid_after_utc),
        public_key_algorithm=algorithm,
        public_key_size=size,
        public_key_curve=curve,
        effective_strength_bits=effective_strength_bits(
            algorithm=algorithm,
            size=size,
            curve=curve,
        ),
        signature_algorithm=_SIGNATURE_ALGORITHM_NAMES.get(
            certificate.signature_algorithm_oid,
            certificate.signature_algorithm_oid.dotted_string,
        ),
    )


def validity_at(instant: datetime, not_before: datetime, not_after: datetime) -> bool:
    """RFC 5280 inclusive validity window at an explicit instant."""

    return not_before <= instant <= not_after


def expires_within_warning(
    *,
    instant: datetime,
    not_after: datetime,
    window: timedelta,
) -> bool:
    if instant > not_after:
        return False
    remaining = not_after - instant
    return remaining <= window


def _certificate_frames(handshake: TlsHandshake | None) -> list[int]:
    if handshake is None:
        return []
    frames: list[int] = []
    for message in handshake.messages:
        if message.kind is not HandshakeMessageKind.CERTIFICATE:
            continue
        if message.frame_number is None:
            continue
        if message.frame_number not in frames:
            frames.append(message.frame_number)
    return frames


def _index_extracted(
    extracted: Sequence[ExtractedCertificate],
) -> tuple[
    dict[str, ExtractedCertificate],
    dict[str, ExtractedCertificate],
    dict[str, ExtractedCertificate],
]:
    by_sha256: dict[str, ExtractedCertificate] = {}
    by_sha1: dict[str, ExtractedCertificate] = {}
    by_fuid: dict[str, ExtractedCertificate] = {}
    for item in extracted[:MAX_CERTIFICATES_PER_RUN]:
        by_sha256[item.sha256] = item
        by_sha1[hashlib.sha1(item.payload, usedforsecurity=False).hexdigest()] = item
        if item.fuid:
            by_fuid[item.fuid] = item
    return by_sha256, by_sha1, by_fuid


def _match_fingerprint(
    fingerprint: str,
    *,
    by_sha256: Mapping[str, ExtractedCertificate],
    by_sha1: Mapping[str, ExtractedCertificate],
) -> ExtractedCertificate | None:
    token = _fingerprint(fingerprint)
    if len(token) == 64:
        return by_sha256.get(token)
    if len(token) == 40:
        return by_sha1.get(token)
    return None


def _files_for_uid(
    logs: Mapping[str, list[dict[str, object]]],
    uid: str,
    *,
    by_sha256: Mapping[str, ExtractedCertificate],
    by_sha1: Mapping[str, ExtractedCertificate],
    by_fuid: Mapping[str, ExtractedCertificate],
) -> list[ExtractedCertificate]:
    found: list[ExtractedCertificate] = []
    seen: set[str] = set()
    for log_name in ("sm_cert.log", "files.log"):
        for row in _bounded_records(logs.get(log_name, [])):
            row_uid = _as_str(row.get("uid"), max_len=_MAX_UID_LEN)
            if row_uid is None:
                uids = _as_str_list(row.get("conn_uids"), max_len=_MAX_UID_LEN, limit=8)
                if uid not in uids:
                    continue
            elif row_uid != uid:
                continue
            source = _as_str(row.get("source"), max_len=16)
            if log_name == "files.log" and source not in {None, "SSL"}:
                continue
            matched: ExtractedCertificate | None = None
            sha256 = _as_str(row.get("sha256"), max_len=64)
            if sha256 is not None:
                matched = by_sha256.get(sha256.lower())
            if matched is None:
                sha1 = _as_str(row.get("sha1"), max_len=40)
                if sha1 is not None:
                    matched = by_sha1.get(sha1.lower())
            if matched is None:
                fuid = _as_str(row.get("fuid"), max_len=_MAX_FUID_LEN)
                if fuid is not None:
                    matched = by_fuid.get(fuid)
            if matched is None or matched.sha256 in seen:
                continue
            seen.add(matched.sha256)
            found.append(matched)
    return found


def _to_evidence(
    *,
    payload: bytes,
    digest: str,
    uid: str,
    chain_index: int,
    role: CertificateRole,
    source_frames: list[int],
    capture_time: datetime | None,
    analysis_time: datetime,
    warning_window: timedelta,
    truncated: bool,
) -> CertificateEvidence:
    parsed = parse_certificate_der(payload)
    syntax_valid = parsed.syntax_valid and not truncated
    syntax_error = parsed.syntax_error
    if truncated and syntax_valid:
        syntax_valid = False
        syntax_error = "certificate_extract_truncated"
    valid_capture: bool | None = None
    valid_analysis: bool | None = None
    warning: bool | None = None
    if parsed.not_before is not None and parsed.not_after is not None:
        if capture_time is not None:
            valid_capture = validity_at(capture_time, parsed.not_before, parsed.not_after)
        valid_analysis = validity_at(analysis_time, parsed.not_before, parsed.not_after)
        warning = expires_within_warning(
            instant=analysis_time,
            not_after=parsed.not_after,
            window=warning_window,
        )
    if not syntax_valid:
        evidence_state = EvidenceState.INCOMPLETE if truncated else EvidenceState.OBSERVED
        return CertificateEvidence(
            der_sha256=digest,
            uid=uid,
            chain_index=chain_index,
            role=role,
            source_frames=source_frames,
            syntax_valid=False,
            syntax_error=_bound_text(syntax_error, max_len=_MAX_ERROR_LEN),
            evidence_state=evidence_state,
        )
    return CertificateEvidence(
        der_sha256=digest,
        uid=uid,
        chain_index=chain_index,
        role=role,
        source_frames=source_frames,
        syntax_valid=True,
        syntax_error=None,
        subject=parsed.subject,
        issuer=parsed.issuer,
        serial_number=parsed.serial_number,
        not_before=parsed.not_before,
        not_after=parsed.not_after,
        valid_at_capture_time=valid_capture,
        valid_at_analysis_time=valid_analysis,
        expires_within_warning_window=warning,
        public_key_algorithm=parsed.public_key_algorithm,
        public_key_size=parsed.public_key_size,
        public_key_curve=parsed.public_key_curve,
        effective_strength_bits=parsed.effective_strength_bits,
        signature_algorithm=parsed.signature_algorithm,
        evidence_state=EvidenceState.OBSERVED,
    )


def normalize_certificates(
    logs: Mapping[str, list[dict[str, object]]],
    extracted: Sequence[ExtractedCertificate],
    handshakes: Sequence[TlsHandshake],
    *,
    analysis_time: datetime,
    expiry_warning: timedelta,
    artifact_store: ArtifactStore,
) -> list[CertificateEvidence]:
    """Build top-level certificate records from Zeek-extracted DER plus ssl.log linkage."""

    by_sha256, by_sha1, by_fuid = _index_extracted(extracted)
    handshake_by_uid = {handshake.uid: handshake for handshake in handshakes}
    records: list[CertificateEvidence] = []
    seen: set[tuple[str, int, str, str]] = set()

    def add_record(item: CertificateEvidence) -> None:
        if len(records) >= MAX_CERTIFICATES_PER_RUN:
            return
        key = (item.uid, item.chain_index, item.role.value, item.der_sha256)
        if key in seen:
            return
        seen.add(key)
        records.append(item)

    for row in _bounded_records(logs.get("ssl.log", [])):
        uid = _as_str(row.get("uid"), max_len=_MAX_UID_LEN)
        if uid is None:
            continue
        handshake = handshake_by_uid.get(uid)
        if handshake is not None:
            hidden = handshake.server_certificate_state is EvidenceState.NOT_OBSERVABLE
            if hidden and "x" not in handshake.ssl_history and "X" not in handshake.ssl_history:
                continue
        capture_time = _epoch_to_datetime(row.get("ts"))
        frames = _certificate_frames(handshake)
        server_fps = _as_str_list(row.get("cert_chain_fps"), max_len=_MAX_FP_LEN, limit=_MAX_CHAIN)
        client_fps = _as_str_list(
            row.get("client_cert_chain_fps"),
            max_len=_MAX_FP_LEN,
            limit=_MAX_CHAIN,
        )
        for role, fingerprints in (
            (CertificateRole.SERVER, server_fps),
            (CertificateRole.CLIENT, client_fps),
        ):
            for index, fingerprint in enumerate(fingerprints):
                matched = _match_fingerprint(
                    fingerprint,
                    by_sha256=by_sha256,
                    by_sha1=by_sha1,
                )
                if matched is None:
                    continue
                digest = artifact_store.put(matched.payload)
                add_record(
                    _to_evidence(
                        payload=matched.payload,
                        digest=digest,
                        uid=uid,
                        chain_index=index,
                        role=role,
                        source_frames=frames,
                        capture_time=capture_time,
                        analysis_time=analysis_time,
                        warning_window=expiry_warning,
                        truncated=False,
                    )
                )

        if server_fps:
            continue
        history = _as_str(row.get("ssl_history"), max_len=100) or ""
        if "x" not in history and "X" not in history:
            continue
        fallback = _files_for_uid(
            logs,
            uid,
            by_sha256=by_sha256,
            by_sha1=by_sha1,
            by_fuid=by_fuid,
        )
        truncated_fuids = {
            _as_str(item.get("fuid"), max_len=_MAX_FUID_LEN)
            for item in _bounded_records(logs.get("sm_cert.log", []))
            if _as_bool(item.get("truncated")) is True
        }
        for index, matched in enumerate(fallback):
            digest = artifact_store.put(matched.payload)
            add_record(
                _to_evidence(
                    payload=matched.payload,
                    digest=digest,
                    uid=uid,
                    chain_index=index,
                    role=CertificateRole.SERVER,
                    source_frames=frames,
                    capture_time=capture_time,
                    analysis_time=analysis_time,
                    warning_window=expiry_warning,
                    truncated=matched.fuid in truncated_fuids,
                )
            )

    records.sort(key=lambda item: (item.uid, item.role.value, item.chain_index, item.der_sha256))
    return records
