"""Step 2 SMTP/IMAP/POP3 identification fixtures through the real CLI path."""

from __future__ import annotations

import json

import pytest
from tests.support.fixture_harness import repo_root, run_fixture

from securemail.domain.evidence.run import EvidenceState
from securemail.domain.evidence.session import MailProtocol, PayloadEvidence, PortHint

STEP2_CASES = (
    "tcp_smtp_clean_baseline",
    "smtp_submission_port",
    "imap_standard_port",
    "pop3_standard_port",
    "smtp_nonstandard_port",
    "imap_nonstandard_port",
    "pop3_nonstandard_port",
    "email_ambiguous_banner",
    "smtp_public_corpus",
    "imap_public_corpus",
)


@pytest.mark.parametrize("case_id", STEP2_CASES)
def test_protocol_fixture_matches_expected_json(case_id: str) -> None:
    run_fixture(case_id)


def _sessions(case_id: str) -> list[dict[str, object]]:
    path = repo_root() / "tests" / "fixtures" / case_id / "expected.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    sessions = payload["sessions"]
    assert isinstance(sessions, list)
    return sessions


def _identified(case_id: str) -> dict[str, object]:
    sessions = _sessions(case_id)
    assert sessions, f"{case_id} must contain at least one email session"
    return sessions[0]


@pytest.mark.parametrize(
    ("case_id", "protocol", "port_hint"),
    [
        ("tcp_smtp_clean_baseline", MailProtocol.SMTP, PortHint.SMTP),
        ("smtp_submission_port", MailProtocol.SMTP, PortHint.SMTP),
        ("imap_standard_port", MailProtocol.IMAP, PortHint.IMAP),
        ("pop3_standard_port", MailProtocol.POP3, PortHint.POP3),
        ("smtp_public_corpus", MailProtocol.SMTP, PortHint.SMTP),
        ("imap_public_corpus", MailProtocol.IMAP, PortHint.IMAP),
    ],
)
def test_standard_and_corpus_payload_matches_port_hint(
    case_id: str, protocol: MailProtocol, port_hint: PortHint
) -> None:
    session = _identified(case_id)
    assert session["protocol"] == protocol
    assert session["port_hint"] == port_hint
    assert session["payload_evidence"] == protocol
    assert session["evidence_state"] == EvidenceState.OBSERVED
    assert session["port_hint"] == session["payload_evidence"]


@pytest.mark.parametrize(
    ("case_id", "protocol"),
    [
        ("smtp_nonstandard_port", MailProtocol.SMTP),
        ("imap_nonstandard_port", MailProtocol.IMAP),
        ("pop3_nonstandard_port", MailProtocol.POP3),
    ],
)
def test_nonstandard_port_payload_is_independent_of_port_hint(
    case_id: str, protocol: MailProtocol
) -> None:
    session = _identified(case_id)
    assert session["protocol"] == protocol
    assert session["payload_evidence"] == protocol
    assert session["port_hint"] == PortHint.NONE
    assert session["evidence_state"] == EvidenceState.OBSERVED
    assert session["port_hint"] != session["payload_evidence"]


def test_ambiguous_banner_is_indeterminate() -> None:
    session = _identified("email_ambiguous_banner")
    assert session["protocol"] is None
    assert session["port_hint"] == PortHint.SMTP
    assert session["payload_evidence"] == PayloadEvidence.INDETERMINATE
    assert session["evidence_state"] == EvidenceState.INDETERMINATE
    assert session["payload_evidence"] != MailProtocol.SMTP
    assert session["payload_evidence"] != MailProtocol.IMAP
    assert session["payload_evidence"] != MailProtocol.POP3
