"""Session normalization: port_hint stays independent of payload evidence."""

from securemail.application.normalize_sessions import normalize_sessions, port_hint_for_flow
from securemail.domain.evidence.flow import Flow, ReconstructionQuality
from securemail.domain.evidence.run import EvidenceState
from securemail.domain.evidence.session import (
    MailProtocol,
    PayloadEvidence,
    PortHint,
    SessionEventKind,
)


def _flow(
    uid: str = "Cmail",
    *,
    orig_port: int = 49152,
    resp_port: int = 25,
) -> Flow:
    return Flow(
        uid=uid,
        orig={"host": "192.0.2.10", "port": orig_port},
        resp={"host": "192.0.2.25", "port": resp_port},
        proto="tcp",
        history="ShADadFf",
        conn_state="SF",
        missed_bytes=0,
        orig_bytes=64,
        resp_bytes=64,
        reconstruction_quality=ReconstructionQuality.COMPLETE,
        gap_bytes=0,
        gap_bytes_exact=True,
        evidence_state=EvidenceState.OBSERVED,
    )


def test_port_hint_uses_well_known_service_port() -> None:
    assert port_hint_for_flow(_flow(resp_port=25)) is PortHint.SMTP
    assert port_hint_for_flow(_flow(resp_port=587)) is PortHint.SMTP
    assert port_hint_for_flow(_flow(resp_port=143)) is PortHint.IMAP
    assert port_hint_for_flow(_flow(resp_port=110)) is PortHint.POP3
    assert port_hint_for_flow(_flow(resp_port=2525)) is PortHint.NONE


def test_nonstandard_port_identifies_from_payload_only() -> None:
    logs = {
        "sm_email.log": [
            {
                "uid": "Cpop",
                "protocol": "pop3",
                "is_orig": False,
                "event_type": "reply",
                "text": "OK POP3 ready",
            },
            {
                "uid": "Cpop",
                "protocol": "pop3",
                "is_orig": True,
                "event_type": "request",
                "command": "CAPA",
            },
        ]
    }
    sessions = normalize_sessions(logs, [_flow("Cpop", resp_port=1110)])
    assert len(sessions) == 1
    session = sessions[0]
    assert session.port_hint is PortHint.NONE
    assert session.payload_evidence is PayloadEvidence.POP3
    assert session.protocol is MailProtocol.POP3
    assert session.evidence_state is EvidenceState.OBSERVED
    assert session.port_hint is not PortHint.POP3


def test_ambiguous_banner_is_indeterminate_not_a_guess() -> None:
    logs = {
        "sm_email.log": [
            {
                "uid": "Cguess",
                "protocol": "unknown",
                "is_orig": False,
                "event_type": "ambiguous_banner",
            }
        ]
    }
    sessions = normalize_sessions(logs, [_flow("Cguess", resp_port=25)])
    assert len(sessions) == 1
    session = sessions[0]
    assert session.port_hint is PortHint.SMTP
    assert session.payload_evidence is PayloadEvidence.INDETERMINATE
    assert session.protocol is None
    assert session.evidence_state is EvidenceState.INDETERMINATE


def test_skips_malformed_rows_and_unknown_uids() -> None:
    logs = {
        "sm_email.log": [
            {"uid": "missing-flow", "protocol": "smtp", "event_type": "request", "command": "EHLO"},
            {"uid": "Cmail", "event_type": "not-a-kind"},
            {
                "uid": "Cmail",
                "protocol": "smtp",
                "is_orig": True,
                "event_type": "request",
                "command": "EHLO",
                "argument": "client.example.test",
            },
        ]
    }
    sessions = normalize_sessions(logs, [_flow()])
    assert len(sessions) == 1
    assert sessions[0].payload_evidence is PayloadEvidence.SMTP
    assert sessions[0].events[0].command == "EHLO"
    assert sessions[0].events[0].argument == "client.example.test"


def test_redacts_secret_command_arguments() -> None:
    logs = {
        "sm_email.log": [
            {
                "uid": "Cmail",
                "protocol": "smtp",
                "is_orig": True,
                "event_type": "request",
                "command": "AUTH",
                "argument": "PLAIN AHVzZXIAc2VjcmV0",
            },
            {
                "uid": "Cmail",
                "protocol": "smtp",
                "is_orig": True,
                "event_type": "request",
                "command": "**",
                "argument": "cHVuamFiQDEyMw==",
            },
        ]
    }
    sessions = normalize_sessions(logs, [_flow()])
    assert sessions[0].events[0].argument == "<redacted>"
    assert sessions[0].events[1].argument == "<redacted>"


def test_conflicting_payload_protocols_are_not_guessed() -> None:
    logs = {
        "sm_email.log": [
            {"uid": "Cmix", "protocol": "smtp", "event_type": "request", "command": "EHLO"},
            {"uid": "Cmix", "protocol": "imap", "event_type": "capability", "text": "IMAP4rev1"},
        ]
    }
    sessions = normalize_sessions(logs, [_flow("Cmix", resp_port=2525)])
    assert sessions[0].protocol is None
    assert sessions[0].payload_evidence is PayloadEvidence.INDETERMINATE
    assert sessions[0].evidence_state is EvidenceState.CONFLICTING


def test_tshark_disagreement_sets_confidence() -> None:
    logs = {
        "sm_email.log": [
            {"uid": "Cmail", "protocol": "imap", "event_type": "capability", "text": "IMAP4rev1"}
        ]
    }
    frames = [
        {
            "ip.src": "192.0.2.10",
            "tcp.srcport": "49152",
            "ip.dst": "192.0.2.25",
            "tcp.dstport": "143",
            "pop.request.command": "CAPA",
        }
    ]
    sessions = normalize_sessions(logs, [_flow("Cmail", resp_port=143)], tshark_frames=frames)
    assert sessions[0].evidence_state is EvidenceState.CONFLICTING
    assert sessions[0].identification_confidence == 0.5
    assert sessions[0].corroboration == "zeek+tshark"
    assert sessions[0].payload_evidence is PayloadEvidence.INDETERMINATE


def test_event_order_is_preserved_and_bounded() -> None:
    rows = [
        {
            "uid": "Cmail",
            "protocol": "smtp",
            "event_type": "reply",
            "reply_code": 220,
            "text": "ready",
        },
        {
            "uid": "Cmail",
            "protocol": "smtp",
            "event_type": "request",
            "command": "EHLO",
        },
    ]
    sessions = normalize_sessions({"sm_email.log": rows}, [_flow()])
    assert [event.kind for event in sessions[0].events] == [
        SessionEventKind.REPLY,
        SessionEventKind.REQUEST,
    ]
    assert sessions[0].events[0].reply_code == 220
