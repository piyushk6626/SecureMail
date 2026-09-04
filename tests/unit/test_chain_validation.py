"""Path validation at explicit verification times."""

from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from securemail.domain.policies.pki.chain_validation import (
    ChainValidationInput,
    PathReasonCode,
    build_trust_snapshot,
    validate_certificate_path,
)


def _name(common_name: str, org: str = "SecureMail Lab") -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _rsa() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _ca_cert(
    key: rsa.RSAPrivateKey,
    *,
    subject: x509.Name,
    issuer_key: rsa.RSAPrivateKey,
    issuer_name: x509.Name,
    path_length: int | None,
    not_before: datetime,
    not_after: datetime,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            True,
        )
    )
    return builder.sign(issuer_key, hashes.SHA256())


def _leaf_cert(
    key: rsa.RSAPrivateKey,
    *,
    issuer_key: rsa.RSAPrivateKey,
    issuer_name: x509.Name,
    san: str,
    not_before: datetime,
    not_after: datetime,
    self_signed: bool = False,
) -> x509.Certificate:
    subject = _name(san, org="Leaf")
    issuer = subject if self_signed else issuer_name
    signer = key if self_signed else issuer_key
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .sign(signer, hashes.SHA256())
    )


def _pki() -> tuple[x509.Certificate, x509.Certificate, x509.Certificate]:
    nb = datetime(2020, 1, 1, tzinfo=UTC)
    na = datetime(2099, 1, 1, tzinfo=UTC)
    root_key = _rsa()
    int_key = _rsa()
    leaf_key = _rsa()
    root_name = _name("Test Root")
    int_name = _name("Test Intermediate")
    root = _ca_cert(
        root_key,
        subject=root_name,
        issuer_key=root_key,
        issuer_name=root_name,
        path_length=None,
        not_before=nb,
        not_after=na,
    )
    intermediate = _ca_cert(
        int_key,
        subject=int_name,
        issuer_key=root_key,
        issuer_name=root_name,
        path_length=0,
        not_before=nb,
        not_after=na,
    )
    leaf = _leaf_cert(
        leaf_key,
        issuer_key=int_key,
        issuer_name=int_name,
        san="securemail.test",
        not_before=nb,
        not_after=na,
    )
    return root, intermediate, leaf


def test_trusted_chain_valid_at_both_instants() -> None:
    root, intermediate, leaf = _pki()
    snapshot = build_trust_snapshot([root], profile_id="test", digest="a" * 64)
    capture = validate_certificate_path(
        ChainValidationInput(
            leaf=leaf,
            intermediates=(intermediate,),
            trust_store=snapshot,
            verification_time=datetime(2024, 6, 1, tzinfo=UTC),
        )
    )
    analysis = validate_certificate_path(
        ChainValidationInput(
            leaf=leaf,
            intermediates=(intermediate,),
            trust_store=snapshot,
            verification_time=datetime(2026, 9, 4, tzinfo=UTC),
        )
    )
    assert capture.valid is True
    assert capture.reason_codes == ()
    assert analysis.valid is True
    assert analysis.reason_codes == ()


def test_self_signed_is_false_with_reason() -> None:
    nb = datetime(2020, 1, 1, tzinfo=UTC)
    na = datetime(2099, 1, 1, tzinfo=UTC)
    root, _, _ = _pki()
    key = _rsa()
    leaf = _leaf_cert(
        key,
        issuer_key=key,
        issuer_name=_name("unused"),
        san="securemail.test",
        not_before=nb,
        not_after=na,
        self_signed=True,
    )
    snapshot = build_trust_snapshot([root], profile_id="test", digest="a" * 64)
    result = validate_certificate_path(
        ChainValidationInput(
            leaf=leaf,
            intermediates=(),
            trust_store=snapshot,
            verification_time=datetime(2026, 9, 4, tzinfo=UTC),
        )
    )
    assert result.valid is False
    assert PathReasonCode.SELF_SIGNED in result.reason_codes


def test_missing_intermediate_is_false_with_reason() -> None:
    root, _intermediate, leaf = _pki()
    snapshot = build_trust_snapshot([root], profile_id="test", digest="a" * 64)
    result = validate_certificate_path(
        ChainValidationInput(
            leaf=leaf,
            intermediates=(),
            trust_store=snapshot,
            verification_time=datetime(2026, 9, 4, tzinfo=UTC),
        )
    )
    assert result.valid is False
    assert PathReasonCode.MISSING_INTERMEDIATE in result.reason_codes


def test_expired_leaf_is_invalid_only_at_later_instant() -> None:
    root_key = _rsa()
    int_key = _rsa()
    leaf_key = _rsa()
    root_name = _name("Test Root")
    int_name = _name("Test Intermediate")
    root = _ca_cert(
        root_key,
        subject=root_name,
        issuer_key=root_key,
        issuer_name=root_name,
        path_length=None,
        not_before=datetime(2018, 1, 1, tzinfo=UTC),
        not_after=datetime(2099, 1, 1, tzinfo=UTC),
    )
    intermediate = _ca_cert(
        int_key,
        subject=int_name,
        issuer_key=root_key,
        issuer_name=root_name,
        path_length=0,
        not_before=datetime(2018, 1, 1, tzinfo=UTC),
        not_after=datetime(2099, 1, 1, tzinfo=UTC),
    )
    leaf = _leaf_cert(
        leaf_key,
        issuer_key=int_key,
        issuer_name=int_name,
        san="securemail.test",
        not_before=datetime(2020, 1, 1, tzinfo=UTC),
        not_after=datetime(2022, 6, 10, tzinfo=UTC),
    )
    snapshot = build_trust_snapshot([root], profile_id="test", digest="a" * 64)
    capture = validate_certificate_path(
        ChainValidationInput(
            leaf=leaf,
            intermediates=(intermediate,),
            trust_store=snapshot,
            verification_time=datetime(2021, 1, 1, tzinfo=UTC),
        )
    )
    analysis = validate_certificate_path(
        ChainValidationInput(
            leaf=leaf,
            intermediates=(intermediate,),
            trust_store=snapshot,
            verification_time=datetime(2026, 9, 4, tzinfo=UTC),
        )
    )
    assert capture.valid is True
    assert analysis.valid is False
    assert PathReasonCode.EXPIRED_AT_VERIFICATION_TIME in analysis.reason_codes
