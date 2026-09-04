"""Bounded certificate DER parsing and validity instants."""

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from securemail.application.normalize_certificates import (
    der_nesting_depth,
    expires_within_warning,
    parse_certificate_der,
    validity_at,
)
from securemail.domain.evidence.certificate import MAX_ASN1_DEPTH, MAX_CERTIFICATE_DER_BYTES


def _leaf(*, not_before: datetime, not_after: datetime, key_size: int = 2048) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "securemail.test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_parse_rsa2048_sha256_certificate() -> None:
    der = _leaf(
        not_before=datetime(2020, 1, 1, tzinfo=UTC),
        not_after=datetime(2099, 1, 1, tzinfo=UTC),
    )
    parsed = parse_certificate_der(der)
    assert parsed.syntax_valid is True
    assert parsed.public_key_algorithm == "RSA"
    assert parsed.public_key_size == 2048
    assert parsed.effective_strength_bits == 112
    assert parsed.signature_algorithm == "sha256WithRSAEncryption"
    assert parsed.subject is not None
    assert "securemail.test" in parsed.subject


def test_expired_at_analysis_but_valid_at_capture() -> None:
    not_before = datetime(2018, 1, 1, tzinfo=UTC)
    not_after = datetime(2019, 1, 1, tzinfo=UTC)
    capture = datetime(2018, 6, 1, tzinfo=UTC)
    analysis = datetime(2026, 9, 4, tzinfo=UTC)
    assert validity_at(capture, not_before, not_after) is True
    assert validity_at(analysis, not_before, not_after) is False


def test_expiry_warning_window_is_independent_of_already_expired() -> None:
    not_after = datetime(2026, 9, 18, tzinfo=UTC)
    window = timedelta(days=30)
    inside = datetime(2026, 9, 4, tzinfo=UTC)
    expired = datetime(2026, 9, 20, tzinfo=UTC)
    assert expires_within_warning(instant=inside, not_after=not_after, window=window) is True
    assert expires_within_warning(instant=expired, not_after=not_after, window=window) is False


def test_malformed_and_oversized_der_fail_closed() -> None:
    nested = b"\x05\x00"
    for _ in range(MAX_ASN1_DEPTH + 4):
        nested = b"\x30" + bytes([len(nested)]) + nested
    parsed_nested = parse_certificate_der(nested)
    assert parsed_nested.syntax_valid is False
    assert parsed_nested.syntax_error == "certificate_asn1_nesting_exceeds_limit"
    parsed_garbage = parse_certificate_der(b"\x30\x82\xff\xff\x00\x00")
    assert parsed_garbage.syntax_valid is False
    parsed_oversize = parse_certificate_der(b"\x30" * (MAX_CERTIFICATE_DER_BYTES + 8))
    assert parsed_oversize.syntax_valid is False
    assert parsed_oversize.syntax_error == "certificate_exceeds_size_limit"
    assert der_nesting_depth(nested) > MAX_ASN1_DEPTH
