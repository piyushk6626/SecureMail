"""Session normalization: port_hint stays independent of payload evidence."""

from securemail.application.normalize_sessions import (
    needs_tshark_corroboration,
    normalize_sessions,
    port_hint_for_flow,
)
from securemail.domain.evidence.flow import Flow, ReconstructionQuality
from securemail.domain.evidence.run import EvidenceState
from securemail.domain.evidence.session import (
    MailProtocol,
    PayloadEvidence,
    PortHint,
    SessionEventKind,
    UpgradeState,
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


def test_tshark_frames_merge_by_timestamp_and_attach_frame_numbers() -> None:
    logs = {
        "sm_email.log": [
            {
                "uid": "Cmail",
                "ts": 1.0,
                "protocol": "imap",
                "is_orig": False,
                "event_type": "capability",
                "text": "IMAP4rev1 STARTTLS",
            }
        ]
    }
    frames = [
        {
            "frame.number": "4",
            "frame.time_epoch": "0.5",
            "ip.src": "192.0.2.10",
            "tcp.srcport": "49152",
            "ip.dst": "192.0.2.25",
            "tcp.dstport": "143",
            "imap.request.command": "CAPABILITY",
            "imap.tag": "a001",
        },
        {
            "frame.number": "6",
            "frame.time_epoch": "1.5",
            "ip.src": "192.0.2.10",
            "tcp.srcport": "49152",
            "ip.dst": "192.0.2.25",
            "tcp.dstport": "143",
            "imap.request.command": "STARTTLS",
            "imap.tag": "a002",
        },
    ]
    sessions = normalize_sessions(logs, [_flow("Cmail", resp_port=143)], tshark_frames=frames)
    commands = [event.command for event in sessions[0].events]
    assert commands[0] == "CAPABILITY"
    assert sessions[0].events[0].frame_number == 4
    assert sessions[0].events[0].tag == "a001"
    assert "STARTTLS" in commands
    assert sessions[0].explicit_upgrade is not None
    assert sessions[0].explicit_upgrade.state is not None


def test_duplicate_zeek_capabilities_are_deduped() -> None:
    logs = {
        "sm_email.log": [
            {
                "uid": "Cmail",
                "ts": 1.0,
                "protocol": "imap",
                "event_type": "capability",
                "text": "IMAP4rev1 STARTTLS",
            },
            {
                "uid": "Cmail",
                "ts": 1.01,
                "protocol": "imap",
                "event_type": "capability",
                "text": "IMAP4rev1 STARTTLS",
            },
        ]
    }
    sessions = normalize_sessions(logs, [_flow("Cmail", resp_port=143)])
    capability_events = [
        event for event in sessions[0].events if event.kind is SessionEventKind.CAPABILITY
    ]
    assert len(capability_events) == 1


def test_ssl_client_hello_promotes_accepted_to_tls_established() -> None:
    logs = {
        "sm_email.log": [
            {
                "uid": "Cmail",
                "ts": 1.0,
                "protocol": "smtp",
                "event_type": "reply",
                "command": "EHLO",
                "reply_code": 250,
                "text": "STARTTLS",
            },
            {
                "uid": "Cmail",
                "ts": 2.0,
                "protocol": "smtp",
                "is_orig": True,
                "event_type": "request",
                "command": "STARTTLS",
            },
            {
                "uid": "Cmail",
                "ts": 3.0,
                "protocol": "smtp",
                "event_type": "reply",
                "reply_code": 220,
                "text": "Ready",
            },
        ],
        "ssl.log": [{"uid": "Cmail", "ssl_history": "Csx", "established": True}],
    }
    sessions = normalize_sessions(logs, [_flow()])
    assert sessions[0].explicit_upgrade is not None
    assert sessions[0].explicit_upgrade.state is UpgradeState.TLS_ESTABLISHED


def test_implicit_tls_without_alpn_is_indeterminate_not_identified() -> None:
    logs = {
        "ssl.log": [{"uid": "Cmail", "ssl_history": "Csx", "established": True}],
    }
    sessions = normalize_sessions(logs, [_flow("Cmail", resp_port=993)])
    assert len(sessions) == 1
    assert sessions[0].port_hint is PortHint.IMAP
    assert sessions[0].protocol is None
    assert sessions[0].payload_evidence is PayloadEvidence.INDETERMINATE
    assert sessions[0].evidence_state is EvidenceState.INDETERMINATE
    assert sessions[0].implicit_tls is not None
    assert sessions[0].implicit_tls.correlated_protocol is None
    assert sessions[0].implicit_tls.evidence_state is EvidenceState.INDETERMINATE


def test_implicit_tls_alpn_identifies_payload_not_port() -> None:
    logs = {
        "ssl.log": [
            {
                "uid": "Cmail",
                "ssl_history": "Csx",
                "established": True,
                "next_protocol": "imap",
            }
        ],
    }
    sessions = normalize_sessions(logs, [_flow("Cmail", resp_port=993)])
    assert sessions[0].protocol is MailProtocol.IMAP
    assert sessions[0].payload_evidence is PayloadEvidence.IMAP
    assert sessions[0].port_hint is PortHint.IMAP
    assert sessions[0].implicit_tls is not None
    assert sessions[0].implicit_tls.source == "alpn"
    assert sessions[0].implicit_tls.evidence_state is EvidenceState.OBSERVED


def test_tshark_smtp_star_maps_to_starttls_and_merges() -> None:
    logs = {
        "sm_email.log": [
            {
                "uid": "Cmail",
                "ts": 1.0,
                "protocol": "smtp",
                "is_orig": True,
                "event_type": "request",
                "command": "STARTTLS",
            }
        ]
    }
    frames = [
        {
            "frame.number": "9",
            "frame.time_epoch": "1.0",
            "ip.src": "192.0.2.10",
            "tcp.srcport": "49152",
            "ip.dst": "192.0.2.25",
            "tcp.dstport": "25",
            "smtp.req.command": "STAR",
        }
    ]
    sessions = normalize_sessions(logs, [_flow()], tshark_frames=frames)
    starttls = [event for event in sessions[0].events if event.command == "STARTTLS"]
    assert len(starttls) == 1
    assert starttls[0].frame_number == 9
    assert starttls[0].source is not None
    assert "STAR" not in {event.command for event in sessions[0].events}


def test_smtp_and_implicit_tls_ports_need_tshark_corroboration() -> None:
    smtp = normalize_sessions(
        {
            "sm_email.log": [
                {"uid": "Cmail", "protocol": "smtp", "event_type": "request", "command": "EHLO"}
            ]
        },
        [_flow()],
    )
    assert needs_tshark_corroboration(smtp, [_flow()])
    implicit_flow = _flow("Ctls", resp_port=993)
    assert needs_tshark_corroboration(
        [],
        [implicit_flow],
        {"ssl.log": [{"uid": "Ctls", "ssl_history": "C"}]},
    )
    standalone_tls = _flow("Cplain", resp_port=4433)
    assert needs_tshark_corroboration(
        [],
        [standalone_tls],
        {"ssl.log": [{"uid": "Cplain", "ssl_history": "Cs"}]},
    )
