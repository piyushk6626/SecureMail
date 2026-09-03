"""Step 3 STARTTLS/STLS fixtures through the real CLI path."""

from __future__ import annotations

import json

import pytest
from tests.support.fixture_harness import repo_root, run_fixture

from securemail.domain.evidence.run import EvidenceState
from securemail.domain.evidence.session import MailProtocol, PayloadEvidence, PortHint, UpgradeState

STEP3_CASES = (
    "smtp_starttls_success",
    "imap_starttls_success",
    "pop3_stls_success",
    "smtp_implicit_tls",
    "imap_implicit_tls",
    "pop3_implicit_tls",
    "tls_mail_port_no_alpn",
    "smtp_starttls_rejected",
    "imap_starttls_rejected",
    "pop3_stls_rejected",
    "imap_starttls_capability_stripped",
    "smtp_starttls_capability_stripped",
    "pop3_stls_capability_stripped",
    "smtp_starttls_mid_transition_violation",
    "imap_starttls_mid_transition_violation",
    "pop3_stls_mid_transition_violation",
    "smtp_plaintext_auth_after_failed_upgrade",
    "imap_plaintext_login_after_failed_upgrade",
    "pop3_plaintext_auth_after_failed_upgrade",
    "smtp_starttls_public_corpus",
    "imap_starttls_public_corpus",
    "pop3_stls_public_corpus",
)

ADVERTISED_NOT_REQUESTED = (
    "smtp_nonstandard_port",
    "imap_nonstandard_port",
    "pop3_nonstandard_port",
)


@pytest.mark.parametrize("case_id", STEP3_CASES)
def test_starttls_fixture_matches_expected_json(case_id: str) -> None:
    run_fixture(case_id)


def _sessions(case_id: str) -> list[dict[str, object]]:
    path = repo_root() / "tests" / "fixtures" / case_id / "expected.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    sessions = payload["sessions"]
    assert isinstance(sessions, list)
    return sessions


def _session(case_id: str) -> dict[str, object]:
    sessions = _sessions(case_id)
    assert sessions, f"{case_id} must contain at least one email session"
    return sessions[0]


def _upgrade(case_id: str) -> dict[str, object]:
    upgrade = _session(case_id)["explicit_upgrade"]
    assert isinstance(upgrade, dict)
    return upgrade


@pytest.mark.parametrize(
    ("case_id", "protocol"),
    [
        ("smtp_starttls_success", MailProtocol.SMTP),
        ("imap_starttls_success", MailProtocol.IMAP),
        ("pop3_stls_success", MailProtocol.POP3),
    ],
)
def test_success_is_tls_established_with_client_hello_frames(
    case_id: str, protocol: MailProtocol
) -> None:
    session = _session(case_id)
    upgrade = _upgrade(case_id)
    assert session["protocol"] == protocol
    assert upgrade["state"] == UpgradeState.TLS_ESTABLISHED
    assert upgrade["evidence_state"] == EvidenceState.OBSERVED
    frames = upgrade["evidence_frames"]
    assert isinstance(frames, list)
    assert frames, f"{case_id} must cite the frames that produced tls_established"


@pytest.mark.parametrize(
    "case_id",
    [
        "smtp_starttls_rejected",
        "imap_starttls_rejected",
        "pop3_stls_rejected",
        "smtp_starttls_capability_stripped",
        "imap_starttls_capability_stripped",
        "pop3_stls_capability_stripped",
        "smtp_starttls_mid_transition_violation",
        "imap_starttls_mid_transition_violation",
        "pop3_stls_mid_transition_violation",
        "smtp_plaintext_auth_after_failed_upgrade",
        "imap_plaintext_login_after_failed_upgrade",
        "pop3_plaintext_auth_after_failed_upgrade",
        *ADVERTISED_NOT_REQUESTED,
    ],
)
def test_never_reports_tls_established_without_client_hello(case_id: str) -> None:
    upgrade = _upgrade(case_id)
    assert upgrade["state"] != UpgradeState.TLS_ESTABLISHED


def test_capability_stripped_sets_downgrade_consistent_not_absent() -> None:
    upgrade = _upgrade("imap_starttls_capability_stripped")
    assert upgrade["state"] == UpgradeState.ACCEPTED
    assert upgrade["downgrade_consistent"] is True
    smtp = _upgrade("smtp_starttls_capability_stripped")
    pop3 = _upgrade("pop3_stls_capability_stripped")
    assert smtp["downgrade_consistent"] is True
    assert pop3["downgrade_consistent"] is True


@pytest.mark.parametrize("case_id", ADVERTISED_NOT_REQUESTED)
def test_advertised_not_requested_is_not_downgrade_consistent(case_id: str) -> None:
    upgrade = _upgrade(case_id)
    assert upgrade["state"] == UpgradeState.ADVERTISED
    assert upgrade["downgrade_consistent"] is False


@pytest.mark.parametrize(
    "case_id",
    [
        "smtp_starttls_mid_transition_violation",
        "imap_starttls_mid_transition_violation",
        "pop3_stls_mid_transition_violation",
    ],
)
def test_mid_transition_plaintext_is_violation(case_id: str) -> None:
    assert _upgrade(case_id)["state"] == UpgradeState.VIOLATION


@pytest.mark.parametrize(
    "case_id",
    [
        "smtp_plaintext_auth_after_failed_upgrade",
        "imap_plaintext_login_after_failed_upgrade",
        "pop3_plaintext_auth_after_failed_upgrade",
    ],
)
def test_plaintext_credentials_after_failed_upgrade(case_id: str) -> None:
    assert _upgrade(case_id)["state"] == UpgradeState.PLAINTEXT_FALLBACK


@pytest.mark.parametrize(
    ("case_id", "protocol", "port_hint"),
    [
        ("smtp_implicit_tls", MailProtocol.SMTP, PortHint.SMTP),
        ("imap_implicit_tls", MailProtocol.IMAP, PortHint.IMAP),
        ("pop3_implicit_tls", MailProtocol.POP3, PortHint.POP3),
    ],
)
def test_implicit_tls_correlates_protocol_not_port_only(
    case_id: str, protocol: MailProtocol, port_hint: PortHint
) -> None:
    session = _session(case_id)
    implicit = session["implicit_tls"]
    assert isinstance(implicit, dict)
    assert session["port_hint"] == port_hint
    assert session["payload_evidence"] == protocol
    assert implicit["correlated_protocol"] == protocol
    assert implicit["source"] == "alpn"
    assert implicit["evidence_state"] == EvidenceState.OBSERVED
    assert session["port_hint"] == session["payload_evidence"]


def test_tls_on_mail_port_without_alpn_is_indeterminate() -> None:
    session = _session("tls_mail_port_no_alpn")
    implicit = session["implicit_tls"]
    assert isinstance(implicit, dict)
    assert session["port_hint"] == PortHint.IMAP
    assert session["protocol"] is None
    assert session["payload_evidence"] == PayloadEvidence.INDETERMINATE
    assert session["evidence_state"] == EvidenceState.INDETERMINATE
    assert implicit["correlated_protocol"] is None
    assert implicit["source"] == "none"
    assert implicit["evidence_state"] == EvidenceState.INDETERMINATE
    assert session["payload_evidence"] != MailProtocol.IMAP
