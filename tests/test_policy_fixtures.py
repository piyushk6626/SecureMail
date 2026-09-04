"""Step 7 policy fixtures: findings, forward secrecy, and profile switch."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from tests.support.fixture_harness import DEFAULT_FIXTURE_ANALYSIS_TIME, repo_root, run_fixture
from typer.testing import CliRunner

from securemail.bootstrap import create_cli
from securemail.domain.evidence.run import EvidenceState

STEP7_CASES = (
    "tls10_negotiated",
    "tls11_negotiated",
    "tls12_null_cipher",
    "tls12_export_cipher",
    "tls12_static_dh",
    "tls12_sha1_certificate_verify",
    "cert_rsa1536",
)

REUSED_CASES = (
    "tls12_legacy_weak_suite",
    "tls12_static_rsa",
    "tls12_static_ecdh",
    "tls12_ecdhe",
    "tls13_psk_only_resumption",
    "tls_truncated_client_hello",
)


def _expected(case_id: str) -> dict[str, object]:
    path = repo_root() / "tests" / "fixtures" / case_id / "expected.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _finding_codes(case_id: str) -> set[str]:
    findings = _expected(case_id)["findings"]
    assert isinstance(findings, list)
    codes: set[str] = set()
    for item in findings:
        assert isinstance(item, dict)
        code = item["code"]
        assert isinstance(code, str)
        codes.add(code)
        assert item["policy_profile"] == "ietf_current"
        assert item["outcome"] in {"negative", "indeterminate"}
        assert item["standards"]
        assert item["rule_effective_from"]
        assert item["rationale"]
    return codes


@pytest.mark.parametrize("case_id", STEP7_CASES)
def test_step7_fixture_matches_expected_json(case_id: str) -> None:
    run_fixture(case_id)


@pytest.mark.parametrize(
    ("case_id", "required_codes"),
    [
        ("tls10_negotiated", {"TLS_NEGOTIATED_TLS10"}),
        ("tls11_negotiated", {"TLS_NEGOTIATED_TLS11"}),
        ("tls12_null_cipher", {"TLS_CIPHER_NULL"}),
        ("tls12_export_cipher", {"TLS_CIPHER_EXPORT"}),
        ("tls12_legacy_weak_suite", {"TLS_CIPHER_RC4"}),
        ("tls12_static_rsa", {"TLS12_STATIC_RSA_NEGOTIATED", "TLS_FORWARD_SECRECY_ABSENT"}),
        ("tls12_static_dh", {"TLS12_STATIC_DH_NEGOTIATED", "TLS_FORWARD_SECRECY_ABSENT"}),
        ("tls12_static_ecdh", {"TLS12_STATIC_ECDH_NEGOTIATED", "TLS_FORWARD_SECRECY_ABSENT"}),
        ("tls12_sha1_certificate_verify", {"TLS_HANDSHAKE_SIGNATURE_SHA1"}),
        ("cert_rsa1536", {"CERT_RSA_KEY_LT2048"}),
        ("tls13_psk_only_resumption", {"TLS_FORWARD_SECRECY_INDETERMINATE"}),
        ("tls_truncated_client_hello", {"TLS_FORWARD_SECRECY_INDETERMINATE"}),
    ],
)
def test_step7_required_finding_codes(case_id: str, required_codes: set[str]) -> None:
    codes = _finding_codes(case_id)
    missing = required_codes - codes
    assert not missing, f"{case_id} missing {sorted(missing)}; have {sorted(codes)}"


def test_ecdhe_does_not_emit_forward_secrecy_finding() -> None:
    codes = _finding_codes("tls12_ecdhe")
    assert "TLS_FORWARD_SECRECY_ABSENT" not in codes
    assert "TLS_FORWARD_SECRECY_INDETERMINATE" not in codes


def test_truncated_handshake_does_not_guess_cipher_findings() -> None:
    codes = _finding_codes("tls_truncated_client_hello")
    assert "TLS_CIPHER_NULL" not in codes
    assert "TLS_CIPHER_EXPORT" not in codes
    assert "TLS_CIPHER_RC4" not in codes
    assert "TLS_CIPHER_CBC" not in codes


def test_findings_never_claim_key_reuse() -> None:
    for case_id in (*STEP7_CASES, *REUSED_CASES):
        findings = _expected(case_id)["findings"]
        assert isinstance(findings, list)
        for item in findings:
            assert isinstance(item, dict)
            rationale = str(item.get("rationale", "")).lower()
            assert "reused" not in rationale
            assert "ticket rotation" not in rationale


def _analyze_profile(capture: Path, profile: str) -> dict[str, object]:
    runner = CliRunner()
    app = create_cli()
    with tempfile.TemporaryDirectory(prefix="securemail-profile-") as tmp:
        out = Path(tmp) / "actual.json"
        result = runner.invoke(
            app,
            [
                "analyze",
                str(capture),
                "--out",
                str(out),
                "--analysis-time",
                DEFAULT_FIXTURE_ANALYSIS_TIME,
                "--policy-profile",
                profile,
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_profile_switch_changes_static_rsa_findings() -> None:
    capture = repo_root() / "tests" / "fixtures" / "tls12_static_rsa" / "capture.pcapng"
    ietf = _analyze_profile(capture, "ietf_current")
    nist = _analyze_profile(capture, "nist_federal")
    ietf_codes = {item["code"] for item in ietf["findings"]}
    nist_codes = {item["code"] for item in nist["findings"]}
    assert "TLS12_STATIC_RSA_NEGOTIATED" in ietf_codes
    assert "TLS12_STATIC_RSA_NEGOTIATED" not in nist_codes
    assert "TLS_CIPHER_CBC" in ietf_codes
    assert "TLS_CIPHER_CBC" not in nist_codes
    assert ietf_codes != nist_codes
    assert ietf["run_identity"]["policy_profile"] == "ietf_current"
    assert nist["run_identity"]["policy_profile"] == "nist_federal"


def test_unknown_policy_profile_exits_2(tmp_path: Path) -> None:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 32)
    runner = CliRunner()
    result = runner.invoke(
        create_cli(),
        [
            "analyze",
            str(capture),
            "--out",
            str(tmp_path / "out.json"),
            "--policy-profile",
            "not_a_profile",
        ],
    )
    assert result.exit_code == 2


def test_forward_secrecy_evidence_states_on_psk_only() -> None:
    findings = _expected("tls13_psk_only_resumption")["findings"]
    assert isinstance(findings, list)
    fs = next(item for item in findings if item["code"] == "TLS_FORWARD_SECRECY_INDETERMINATE")
    assert fs["outcome"] == "indeterminate"
    assert fs["evaluation_state"] == EvidenceState.INDETERMINATE
