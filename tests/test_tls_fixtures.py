"""Step 4 TLS handshake fixtures through the real CLI path."""

from __future__ import annotations

import json

import pytest
from tests.support.fixture_harness import repo_root, run_fixture

from securemail.domain.evidence.handshake import HandshakeVisibility, VersionSource
from securemail.domain.evidence.run import EvidenceState

STEP4_CASES = (
    "tls12_ecdhe",
    "tls12_static_rsa",
    "tls12_static_ecdh",
    "tls13_full_handshake",
    "tls13_hello_retry_request",
    "tls13_psk_only_resumption",
    "tls12_legacy_weak_suite",
    "tls_supported_versions_precedence",
    "tls_truncated_client_hello",
    "tls12_public_corpus",
    "tls13_public_corpus",
)

TLS13_CASES = (
    "tls13_full_handshake",
    "tls13_hello_retry_request",
    "tls13_psk_only_resumption",
    "tls13_public_corpus",
)


@pytest.mark.parametrize("case_id", STEP4_CASES)
def test_tls_fixture_matches_expected_json(case_id: str) -> None:
    run_fixture(case_id)


def _document(case_id: str) -> dict[str, object]:
    path = repo_root() / "tests" / "fixtures" / case_id / "expected.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _handshakes(case_id: str) -> list[dict[str, object]]:
    handshakes = _document(case_id)["handshakes"]
    assert isinstance(handshakes, list)
    return handshakes


def _handshake(case_id: str) -> dict[str, object]:
    handshakes = _handshakes(case_id)
    assert handshakes, f"{case_id} must contain at least one TLS handshake"
    return handshakes[0]


@pytest.mark.parametrize(
    ("case_id", "version", "source"),
    [
        ("tls12_ecdhe", "TLSv12", VersionSource.LEGACY_RECORD),
        ("tls12_static_rsa", "TLSv12", VersionSource.LEGACY_RECORD),
        ("tls12_static_ecdh", "TLSv12", VersionSource.LEGACY_RECORD),
        ("tls12_legacy_weak_suite", "TLSv12", VersionSource.LEGACY_RECORD),
        ("tls13_full_handshake", "TLSv13", VersionSource.SUPPORTED_VERSIONS),
        ("tls13_hello_retry_request", "TLSv13", VersionSource.SUPPORTED_VERSIONS),
        ("tls_supported_versions_precedence", "TLSv12", VersionSource.SUPPORTED_VERSIONS),
    ],
)
def test_selected_version_and_source(case_id: str, version: str, source: VersionSource) -> None:
    handshake = _handshake(case_id)
    selected = handshake["version"]
    assert isinstance(selected, dict)
    assert selected["selected"] == version
    assert selected["source"] == source
    assert selected["evidence_state"] == EvidenceState.OBSERVED
    if source is VersionSource.SUPPORTED_VERSIONS:
        assert selected["server_supported_version"] == version
        if case_id == "tls_supported_versions_precedence":
            assert selected["legacy_record_version"] != version


def test_truncated_client_hello_is_incomplete() -> None:
    handshake = _handshake("tls_truncated_client_hello")
    version = handshake["version"]
    assert isinstance(version, dict)
    assert version["selected"] is None
    assert version["evidence_state"] == EvidenceState.INCOMPLETE
    assert handshake["evidence_state"] == EvidenceState.INCOMPLETE
    assert handshake["cipher_suite"]["name"] is None


@pytest.mark.parametrize(
    ("case_id", "mechanism"),
    [
        ("tls12_ecdhe", "ECDHE"),
        ("tls12_static_rsa", "RSA"),
        ("tls12_static_ecdh", "ECDH"),
        ("tls12_legacy_weak_suite", "RSA"),
    ],
)
def test_tls12_key_exchange_from_suite_grammar(case_id: str, mechanism: str) -> None:
    handshake = _handshake(case_id)
    key_exchange = handshake["key_exchange"]
    cipher = handshake["cipher_suite"]
    assert isinstance(key_exchange, dict)
    assert isinstance(cipher, dict)
    assert key_exchange["mechanism"] == mechanism
    assert cipher["name"]
    assert cipher["code"]
    assert "cipher" in key_exchange["source_fields"]


def test_tls13_key_exchange_never_uses_cipher_name() -> None:
    handshake = _handshake("tls13_full_handshake")
    key_exchange = handshake["key_exchange"]
    assert isinstance(key_exchange, dict)
    assert "cipher" not in key_exchange["source_fields"]
    assert key_exchange["mechanism"] in {"ECDHE", "DHE", "(EC)DHE"}


def test_hello_retry_request_is_evidence_linked() -> None:
    handshake = _handshake("tls13_hello_retry_request")
    assert handshake["hello_retry_request"] is True
    assert "j" in str(handshake["ssl_history"])
    messages = handshake["messages"]
    assert isinstance(messages, list)
    hrr = [item for item in messages if item["kind"] == "hello_retry_request"]
    assert hrr, "HRR must appear in reconstructed messages"
    assert any(item.get("frame_number") for item in hrr)


def test_psk_only_resumption_does_not_use_cipher_name() -> None:
    psk = [
        handshake
        for handshake in _handshakes("tls13_psk_only_resumption")
        if handshake.get("resumed") is True
        or (
            isinstance(handshake.get("key_exchange"), dict)
            and handshake["key_exchange"].get("mechanism") == "PSK"
        )
    ]
    assert psk, "tls13_psk_only_resumption must include a PSK-only handshake"
    key_exchange = psk[0]["key_exchange"]
    assert isinstance(key_exchange, dict)
    assert key_exchange["mechanism"] == "PSK"
    assert "cipher" not in key_exchange["source_fields"]


@pytest.mark.parametrize("case_id", TLS13_CASES)
def test_tls13_certificate_and_verify_are_not_fabricated(case_id: str) -> None:
    document = _document(case_id)
    assert document["certificates"] == []
    for handshake in _handshakes(case_id):
        version = handshake["version"]
        assert isinstance(version, dict)
        if version.get("selected") != "TLSv13":
            continue
        assert handshake["server_certificate_state"] == EvidenceState.NOT_OBSERVABLE
        assert handshake["certificate_verify_state"] == EvidenceState.NOT_OBSERVABLE
        assert handshake["visibility"] != HandshakeVisibility.FULL
        messages = handshake["messages"]
        assert isinstance(messages, list)
        kinds = {item["kind"] for item in messages}
        assert "certificate" not in kinds
        assert "certificate_verify" not in kinds


@pytest.mark.parametrize("case_id", STEP4_CASES)
def test_ssl_history_is_asserted(case_id: str) -> None:
    for handshake in _handshakes(case_id):
        history = handshake["ssl_history"]
        assert isinstance(history, str)
        assert history
        messages = handshake["messages"]
        assert isinstance(messages, list)
        reconstructed = "".join(item["history_letter"] for item in messages)
        assert reconstructed == history
