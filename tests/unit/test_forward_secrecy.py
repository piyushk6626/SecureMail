"""Forward-secrecy table: present / absent / indeterminate. Never infers reuse."""

from securemail.domain.evidence.handshake import (
    CipherSuiteEvidence,
    HandshakeSignatureEvidence,
    HandshakeVisibility,
    KeyExchangeEvidence,
    TlsHandshake,
    TlsVersionEvidence,
    VersionSource,
)
from securemail.domain.evidence.run import EvidenceState
from securemail.domain.policies.tls.forward_secrecy import (
    ForwardSecrecyOutcome,
    assess_forward_secrecy,
)


def _handshake(
    *,
    version: str | None,
    version_state: EvidenceState = EvidenceState.OBSERVED,
    mechanism: str | None,
    kx_state: EvidenceState = EvidenceState.INFERRED,
    handshake_state: EvidenceState = EvidenceState.OBSERVED,
    resumed: bool = False,
) -> TlsHandshake:
    return TlsHandshake(
        uid="Ctls",
        ssl_history="Csxn",
        established=handshake_state is EvidenceState.OBSERVED,
        resumed=resumed,
        hello_retry_request=False,
        visibility=HandshakeVisibility.FULL,
        version=TlsVersionEvidence(
            selected=version,
            source=VersionSource.LEGACY_RECORD,
            evidence_state=version_state,
        ),
        cipher_suite=CipherSuiteEvidence(
            name="TLS_AES_128_GCM_SHA256",
            code="0x1301",
            evidence_state=EvidenceState.OBSERVED,
        ),
        key_exchange=KeyExchangeEvidence(
            mechanism=mechanism,
            evidence_state=kx_state,
        ),
        server_certificate_state=EvidenceState.NOT_OBSERVABLE,
        certificate_verify_state=EvidenceState.NOT_OBSERVABLE,
        certificate_verify_signature=HandshakeSignatureEvidence(
            algorithm=None,
            evidence_state=EvidenceState.NOT_OBSERVABLE,
        ),
        evidence_state=handshake_state,
    )


def test_tls12_ecdhe_and_dhe_are_present() -> None:
    ecdhe = assess_forward_secrecy(_handshake(version="TLSv12", mechanism="ECDHE"))
    dhe = assess_forward_secrecy(_handshake(version="TLSv12", mechanism="DHE"))
    assert ecdhe.outcome is ForwardSecrecyOutcome.PRESENT
    assert dhe.outcome is ForwardSecrecyOutcome.PRESENT
    assert ecdhe.reason_code == "tls12_ephemeral"


def test_tls12_static_mechanisms_are_absent() -> None:
    for mechanism in ("RSA", "DH", "ECDH"):
        result = assess_forward_secrecy(_handshake(version="TLSv12", mechanism=mechanism))
        assert result.outcome is ForwardSecrecyOutcome.ABSENT
        assert result.reason_code == "static_key_exchange"


def test_tls13_ephemeral_is_present() -> None:
    ecdhe = assess_forward_secrecy(
        _handshake(version="TLSv13", mechanism="ECDHE", kx_state=EvidenceState.OBSERVED)
    )
    psk_dhe = assess_forward_secrecy(
        _handshake(
            version="TLSv13",
            mechanism="PSK-(EC)DHE",
            kx_state=EvidenceState.OBSERVED,
            resumed=True,
        )
    )
    assert ecdhe.outcome is ForwardSecrecyOutcome.PRESENT
    assert psk_dhe.outcome is ForwardSecrecyOutcome.PRESENT


def test_tls13_psk_only_is_indeterminate() -> None:
    result = assess_forward_secrecy(_handshake(version="TLSv13", mechanism="PSK", resumed=True))
    assert result.outcome is ForwardSecrecyOutcome.INDETERMINATE
    assert result.reason_code == "tls13_psk_only"


def test_incomplete_or_missing_handshake_is_indeterminate() -> None:
    truncated = assess_forward_secrecy(
        _handshake(
            version=None,
            version_state=EvidenceState.INCOMPLETE,
            mechanism=None,
            kx_state=EvidenceState.INCOMPLETE,
            handshake_state=EvidenceState.INCOMPLETE,
        )
    )
    missing_version = assess_forward_secrecy(
        _handshake(
            version=None,
            version_state=EvidenceState.NOT_OBSERVABLE,
            mechanism="ECDHE",
        )
    )
    assert truncated.outcome is ForwardSecrecyOutcome.INDETERMINATE
    assert missing_version.outcome is ForwardSecrecyOutcome.INDETERMINATE
    assert "reuse" not in truncated.reason_code
    assert "ticket" not in truncated.reason_code
