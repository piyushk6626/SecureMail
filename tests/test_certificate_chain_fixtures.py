"""Step 6 certificate chain and identity fixtures through the real CLI path."""

from __future__ import annotations

import json
import socket
from datetime import UTC, datetime

import pytest
from tests.support.fixture_harness import repo_root, run_fixture
from tests.unit.test_chain_validation import _pki

from securemail.adapters.pki.trust_store import load_trust_store_snapshot
from securemail.domain.policies.pki.chain_validation import (
    ChainValidationInput,
    build_trust_snapshot,
    validate_certificate_path,
)
from securemail.domain.policies.pki.identity import match_service_identity

STEP6_CASES = (
    "cert_chain_lab_trusted",
    "cert_chain_self_signed",
    "cert_chain_missing_intermediate",
    "cert_chain_san_match",
    "cert_chain_san_mismatch",
    "cert_chain_public_corpus",
)


@pytest.mark.parametrize("case_id", STEP6_CASES)
def test_chain_fixture_matches_expected_json(case_id: str) -> None:
    run_fixture(case_id)


def _document(case_id: str) -> dict[str, object]:
    path = repo_root() / "tests" / "fixtures" / case_id / "expected.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _leaf_validation(case_id: str) -> dict[str, object]:
    certificates = _document(case_id)["certificates"]
    assert isinstance(certificates, list)
    assert certificates
    leaf = certificates[0]
    assert isinstance(leaf, dict)
    validation = leaf["validation"]
    assert isinstance(validation, dict)
    return validation


def test_san_mismatch_path_valid_identity_false() -> None:
    validation = _leaf_validation("cert_chain_san_mismatch")
    assert validation["path_valid_at_capture_time"] is True
    assert validation["path_valid_at_analysis_time"] is True
    assert validation["identity_match"] is False
    assert validation["identity_mismatch_reasons"]
    assert validation["revocation_status"] == "unknown"
    assert validation["reference_identity"] == "wrong.example.test"
    assert validation["reference_identity_source"] == "sni"


def test_san_match_and_trusted_chain_are_independent_passes() -> None:
    for case_id in ("cert_chain_lab_trusted", "cert_chain_san_match"):
        validation = _leaf_validation(case_id)
        assert validation["path_valid_at_capture_time"] is True
        assert validation["path_valid_at_analysis_time"] is True
        assert validation["identity_match"] is True
        assert validation["path_invalid_reasons_at_capture_time"] == []
        assert validation["identity_mismatch_reasons"] == []
        assert validation["revocation_status"] == "unknown"


def test_self_signed_and_broken_chain_have_reasons() -> None:
    self_signed = _leaf_validation("cert_chain_self_signed")
    assert self_signed["path_valid_at_capture_time"] is False
    assert self_signed["path_valid_at_analysis_time"] is False
    assert self_signed["path_invalid_reasons_at_capture_time"]
    assert self_signed["identity_match"] is True
    missing = _leaf_validation("cert_chain_missing_intermediate")
    assert missing["path_valid_at_capture_time"] is False
    assert missing["path_valid_at_analysis_time"] is False
    assert missing["path_invalid_reasons_at_capture_time"]
    assert missing["revocation_status"] == "unknown"


def test_public_corpus_capture_and_analysis_times_differ() -> None:
    validation = _leaf_validation("cert_chain_public_corpus")
    assert validation["certificate_observed"] is True
    assert validation["syntax_valid"] is True
    assert validation["path_valid_at_capture_time"] is True
    assert validation["path_valid_at_analysis_time"] is False
    assert validation["path_invalid_reasons_at_analysis_time"]
    assert validation["revocation_status"] == "unknown"


def test_all_step6_leaves_use_unknown_revocation_and_digest() -> None:
    digest = None
    for case_id in STEP6_CASES:
        identity = _document(case_id)["run_identity"]
        assert isinstance(identity, dict)
        assert identity["trust_store_digest"]
        if digest is None:
            digest = identity["trust_store_digest"]
        assert identity["trust_store_digest"] == digest
        validation = _leaf_validation(case_id)
        assert validation["revocation_status"] == "unknown"
        assert validation["trust_store_digest"] == digest
        assert validation["trust_profile_id"] == "offline_v1"


def test_step6_python_makes_no_inet_connections(monkeypatch: pytest.MonkeyPatch) -> None:
    original = socket.socket.connect

    def _deny_inet(
        self: socket.socket,
        address: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        if self.family in {socket.AF_INET, socket.AF_INET6}:
            raise AssertionError(f"unexpected Python inet connection: {address}")
        connect = original.__get__(self, type(self))
        return connect(address, *args, **kwargs)  # type: ignore[no-any-return]

    monkeypatch.setattr(socket.socket, "connect", _deny_inet)
    pinned = load_trust_store_snapshot()
    assert pinned.anchors
    root, intermediate, leaf = _pki()
    snapshot = build_trust_snapshot([root], profile_id="test", digest="a" * 64)
    result = validate_certificate_path(
        ChainValidationInput(
            leaf=leaf,
            intermediates=(intermediate,),
            trust_store=snapshot,
            verification_time=datetime(2026, 9, 4, tzinfo=UTC),
        )
    )
    assert result.valid is True
    identity = match_service_identity(
        reference_identity="securemail.test",
        san_entries=(),
    )
    assert identity.match is False


def test_pki_modules_do_not_import_network_clients() -> None:
    root = repo_root() / "src" / "securemail"
    forbidden = ("import urllib", "from urllib", "import requests", "import http.client")
    files = [
        root / "adapters" / "pki" / "trust_store.py",
        root / "adapters" / "pki" / "openssl_crosscheck.py",
        root / "domain" / "policies" / "pki" / "chain_validation.py",
        root / "domain" / "policies" / "pki" / "identity.py",
        root / "application" / "normalize_certificates.py",
    ]
    for path in files:
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in text, f"{path} contains {token}"
