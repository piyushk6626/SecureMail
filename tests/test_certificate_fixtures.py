"""Step 5 certificate fixtures through the real CLI path."""

from __future__ import annotations

import json
import time

import pytest
from tests.support.fixture_harness import repo_root, run_fixture

from securemail.adapters.analyzers.sandbox import ANALYZER_TIMEOUT_SECONDS
from securemail.domain.evidence.run import EvidenceState

STEP5_CASES = (
    "cert_valid_current",
    "cert_expired_rsa1024",
    "cert_not_yet_valid",
    "cert_ecdsa_p256",
    "cert_sha1_signed",
    "cert_expiry_warning",
    "cert_malformed_asn1",
    "cert_chain_public_corpus",
)


@pytest.mark.parametrize("case_id", STEP5_CASES)
def test_certificate_fixture_matches_expected_json(case_id: str) -> None:
    run_fixture(case_id)


def _document(case_id: str) -> dict[str, object]:
    path = repo_root() / "tests" / "fixtures" / case_id / "expected.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _certificates(case_id: str) -> list[dict[str, object]]:
    certificates = _document(case_id)["certificates"]
    assert isinstance(certificates, list)
    return certificates


def _leaf(case_id: str) -> dict[str, object]:
    certificates = _certificates(case_id)
    assert certificates, f"{case_id} must contain at least one certificate"
    return certificates[0]


def test_expired_rsa1024_is_a_fact_with_both_validity_booleans() -> None:
    cert = _leaf("cert_expired_rsa1024")
    assert cert["syntax_valid"] is True
    assert cert["public_key_algorithm"] == "RSA"
    assert cert["public_key_size"] == 1024
    assert cert["effective_strength_bits"] == 80
    assert cert["valid_at_capture_time"] is False
    assert cert["valid_at_analysis_time"] is False
    handshake = _document("cert_expired_rsa1024")["handshakes"][0]
    assert isinstance(handshake, dict)
    verify = handshake["certificate_verify_signature"]
    assert isinstance(verify, dict)
    assert verify["algorithm"] != cert["signature_algorithm"] or verify["algorithm"] is None


def test_valid_current_rsa2048_sha256() -> None:
    cert = _leaf("cert_valid_current")
    assert cert["syntax_valid"] is True
    assert cert["public_key_algorithm"] == "RSA"
    assert cert["public_key_size"] == 2048
    assert cert["effective_strength_bits"] == 112
    assert cert["signature_algorithm"] == "sha256WithRSAEncryption"
    assert cert["valid_at_capture_time"] is True
    assert cert["valid_at_analysis_time"] is True
    assert cert["expires_within_warning_window"] is False


def test_not_yet_valid_is_invalid_at_both_instants() -> None:
    cert = _leaf("cert_not_yet_valid")
    assert cert["valid_at_capture_time"] is False
    assert cert["valid_at_analysis_time"] is False


def test_ecdsa_p256_uses_effective_strength_not_raw_bits() -> None:
    cert = _leaf("cert_ecdsa_p256")
    assert cert["public_key_algorithm"] == "ECDSA"
    assert cert["public_key_curve"] == "secp256r1"
    assert cert["public_key_size"] == 256
    assert cert["effective_strength_bits"] == 128
    rsa2048 = _leaf("cert_valid_current")
    assert cert["effective_strength_bits"] != rsa2048["public_key_size"]
    assert cert["effective_strength_bits"] != rsa2048["effective_strength_bits"]


def test_sha1_signature_is_recorded_separately_from_handshake_verify() -> None:
    cert = _leaf("cert_sha1_signed")
    assert cert["signature_algorithm"] == "sha1WithRSAEncryption"
    handshake = _document("cert_sha1_signed")["handshakes"][0]
    assert isinstance(handshake, dict)
    verify = handshake["certificate_verify_signature"]
    assert isinstance(verify, dict)
    assert verify["evidence_state"] in {
        EvidenceState.NOT_OBSERVABLE,
        EvidenceState.INCOMPLETE,
    }
    assert verify.get("algorithm") != cert["signature_algorithm"]


def test_expiry_warning_window_is_true_for_near_expiry_fixture() -> None:
    cert = _leaf("cert_expiry_warning")
    assert cert["valid_at_capture_time"] is True
    assert cert["valid_at_analysis_time"] is True
    assert cert["expires_within_warning_window"] is True


def test_public_corpus_records_a_chain() -> None:
    certificates = _certificates("cert_chain_public_corpus")
    assert len(certificates) >= 2
    indexes = [item["chain_index"] for item in certificates]
    assert indexes == list(range(len(certificates)))
    assert all(item.get("uid") for item in certificates)
    assert all(item.get("der_sha256") for item in certificates)
    leaf, *rest = certificates
    assert leaf["chain_index"] == 0
    assert any(item["der_sha256"] != leaf["der_sha256"] for item in rest)


def test_malformed_certificate_fails_closed_under_resource_limits() -> None:
    started = time.monotonic()
    run_fixture("cert_malformed_asn1")
    elapsed = time.monotonic() - started
    assert elapsed < ANALYZER_TIMEOUT_SECONDS
    cert = _leaf("cert_malformed_asn1")
    assert cert["syntax_valid"] is False
    assert cert["syntax_error"]
    assert cert["public_key_algorithm"] is None
