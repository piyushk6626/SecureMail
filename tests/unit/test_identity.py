"""RFC 9525 SAN matching. Common Name is never used."""

from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from securemail.domain.policies.pki.identity import (
    IdentityReasonCode,
    SanEntry,
    extract_san_entries,
    match_service_identity,
)


def _cert(*, san: x509.SubjectAlternativeName | None, common_name: str) -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2099, 1, 1, tzinfo=UTC))
    )
    if san is not None:
        builder = builder.add_extension(san, False)
    return builder.sign(key, hashes.SHA256())


def test_dns_san_matches_and_is_case_insensitive() -> None:
    result = match_service_identity(
        reference_identity="Mail.Example.TEST",
        san_entries=(SanEntry(kind="dns", value="mail.example.test"),),
    )
    assert result.match is True
    assert result.reason_codes == ()


def test_wildcard_matches_one_leftmost_label_only() -> None:
    pattern = (SanEntry(kind="dns", value="*.example.test"),)
    assert (
        match_service_identity(
            reference_identity="foo.example.test",
            san_entries=pattern,
        ).match
        is True
    )
    assert (
        match_service_identity(
            reference_identity="example.test",
            san_entries=pattern,
        ).match
        is False
    )
    assert (
        match_service_identity(
            reference_identity="bar.foo.example.test",
            san_entries=pattern,
        ).match
        is False
    )
    assert (
        match_service_identity(
            reference_identity="foo.example.test",
            san_entries=(SanEntry(kind="dns", value="f*.example.test"),),
        ).match
        is False
    )


def test_ip_san_matches_literal_reference() -> None:
    result = match_service_identity(
        reference_identity="192.0.2.10",
        san_entries=(SanEntry(kind="ip", value="192.0.2.10"),),
    )
    assert result.match is True
    dns_only = match_service_identity(
        reference_identity="192.0.2.10",
        san_entries=(SanEntry(kind="dns", value="192.0.2.10"),),
    )
    assert dns_only.match is False
    assert IdentityReasonCode.SAN_MISMATCH in dns_only.reason_codes


def test_cn_is_ignored_when_san_is_missing() -> None:
    certificate = _cert(san=None, common_name="securemail.test")
    assert extract_san_entries(certificate) == ()
    result = match_service_identity(
        reference_identity="securemail.test",
        san_entries=extract_san_entries(certificate),
    )
    assert result.match is False
    assert IdentityReasonCode.SAN_MISSING in result.reason_codes


def test_missing_reference_is_indeterminate() -> None:
    result = match_service_identity(
        reference_identity=None,
        san_entries=(SanEntry(kind="dns", value="securemail.test"),),
    )
    assert result.match is None
    assert IdentityReasonCode.REFERENCE_IDENTITY_UNAVAILABLE in result.reason_codes
