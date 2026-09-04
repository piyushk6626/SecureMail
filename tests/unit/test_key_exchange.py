"""TLS key-exchange classification is version-aware and never guesses TLS 1.3 from suite names."""

from securemail.domain.evidence.run import EvidenceState
from securemail.domain.policies.tls.key_exchange import classify_key_exchange


def test_tls12_ecdhe_from_iana_suite_name() -> None:
    result = classify_key_exchange(
        negotiated_version="TLSv12",
        cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        curve="x25519",
    )
    assert result.mechanism == "ECDHE"
    assert result.evidence_state is EvidenceState.INFERRED
    assert result.source_fields == ("cipher", "curve")


def test_tls12_static_rsa_and_static_ecdh() -> None:
    rsa = classify_key_exchange(
        negotiated_version="TLSv12",
        cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
    )
    assert rsa.mechanism == "RSA"
    assert rsa.evidence_state is EvidenceState.INFERRED
    ecdh = classify_key_exchange(
        negotiated_version="TLSv12",
        cipher_suite="TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
        curve="secp256r1",
    )
    assert ecdh.mechanism == "ECDH"
    assert ecdh.source_fields == ("cipher", "curve")


def test_tls13_uses_key_share_not_cipher_name() -> None:
    result = classify_key_exchange(
        negotiated_version="TLSv13",
        cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
        server_key_share_group=29,
        group_name="x25519",
    )
    assert result.mechanism == "ECDHE"
    assert result.evidence_state is EvidenceState.OBSERVED
    assert "cipher" not in result.source_fields
    assert "server_key_share_group" in result.source_fields


def test_tls13_cipher_suite_name_never_classifies_key_exchange() -> None:
    result = classify_key_exchange(
        negotiated_version="TLSv13",
        cipher_suite="TLS_AES_128_GCM_SHA256",
        resumed=True,
        psk_key_exchange_modes=(0,),
    )
    assert result.mechanism == "PSK"
    assert result.evidence_state is EvidenceState.INFERRED
    assert "cipher" not in result.source_fields


def test_tls13_psk_with_key_share_is_psk_ecdhe() -> None:
    result = classify_key_exchange(
        negotiated_version="TLSv13",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        server_key_share_group=4588,
        group_name="X25519MLKEM768",
        resumed=True,
        psk_key_exchange_modes=(1,),
    )
    assert result.mechanism == "PSK-(EC)DHE"
    assert result.evidence_state is EvidenceState.OBSERVED


def test_tls13_missing_key_share_without_resumption_is_incomplete() -> None:
    result = classify_key_exchange(
        negotiated_version="TLSv13",
        cipher_suite="TLS_AES_128_GCM_SHA256",
        client_key_share_groups=(29,),
    )
    assert result.mechanism is None
    assert result.evidence_state is EvidenceState.INCOMPLETE


def test_missing_version_is_incomplete() -> None:
    result = classify_key_exchange(
        negotiated_version=None,
        cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    )
    assert result.mechanism is None
    assert result.evidence_state is EvidenceState.INCOMPLETE
