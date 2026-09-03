"""SMTP STARTTLS transition table."""

from securemail.domain.evidence.flow import StreamDirection
from securemail.domain.evidence.run import EvidenceState
from securemail.domain.evidence.session import ProtocolEvent, SessionEventKind, UpgradeState
from securemail.domain.policies.starttls.smtp_upgrade import smtp_upgrade


def _event(
    kind: SessionEventKind,
    *,
    command: str | None = None,
    text: str | None = None,
    reply_code: int | None = None,
    direction: StreamDirection = StreamDirection.ORIG,
    frame_number: int | None = None,
) -> ProtocolEvent:
    return ProtocolEvent(
        direction=direction,
        kind=kind,
        command=command,
        text=text,
        reply_code=reply_code,
        frame_number=frame_number,
    )


def test_advertised_only() -> None:
    events = [
        _event(SessionEventKind.REQUEST, command="EHLO"),
        _event(
            SessionEventKind.REPLY,
            command="EHLO",
            text="STARTTLS",
            reply_code=250,
            direction=StreamDirection.RESP,
            frame_number=4,
        ),
        _event(SessionEventKind.REQUEST, command="QUIT"),
    ]
    result = smtp_upgrade(events, client_hello_observed=False)
    assert result.state is UpgradeState.ADVERTISED
    assert result.downgrade_consistent is False
    assert result.evidence_state is EvidenceState.OBSERVED
    assert result.evidence_frames == [4]


def test_rejected_stays_requested() -> None:
    events = [
        _event(
            SessionEventKind.REPLY,
            command="EHLO",
            text="STARTTLS",
            reply_code=250,
            direction=StreamDirection.RESP,
        ),
        _event(SessionEventKind.REQUEST, command="STARTTLS", frame_number=6),
        _event(
            SessionEventKind.REPLY,
            command="STARTTLS",
            reply_code=454,
            direction=StreamDirection.RESP,
            frame_number=7,
        ),
    ]
    result = smtp_upgrade(events, client_hello_observed=False)
    assert result.state is UpgradeState.REQUESTED
    assert result.downgrade_consistent is False


def test_accepted_without_client_hello_is_not_established() -> None:
    events = [
        _event(
            SessionEventKind.REPLY,
            command="EHLO",
            text="STARTTLS",
            reply_code=250,
            direction=StreamDirection.RESP,
        ),
        _event(SessionEventKind.REQUEST, command="STARTTLS"),
        _event(SessionEventKind.REPLY, reply_code=220, direction=StreamDirection.RESP),
        _event(SessionEventKind.STARTTLS, direction=StreamDirection.ORIG),
    ]
    result = smtp_upgrade(events, client_hello_observed=False)
    assert result.state is UpgradeState.ACCEPTED


def test_tls_established_requires_client_hello() -> None:
    events = [
        _event(
            SessionEventKind.REPLY,
            command="EHLO",
            text="STARTTLS",
            reply_code=250,
            direction=StreamDirection.RESP,
        ),
        _event(SessionEventKind.REQUEST, command="STARTTLS"),
        _event(SessionEventKind.REPLY, reply_code=220, direction=StreamDirection.RESP),
        _event(SessionEventKind.STARTTLS, direction=StreamDirection.ORIG),
    ]
    result = smtp_upgrade(events, client_hello_observed=True, client_hello_frames=(12,))
    assert result.state is UpgradeState.TLS_ESTABLISHED
    assert 12 in result.evidence_frames


def test_capability_stripped_sets_downgrade_consistent() -> None:
    events = [
        _event(SessionEventKind.REQUEST, command="EHLO"),
        _event(
            SessionEventKind.REPLY,
            command="EHLO",
            text="AUTH PLAIN",
            reply_code=250,
            direction=StreamDirection.RESP,
        ),
        _event(SessionEventKind.REQUEST, command="STARTTLS", frame_number=8),
        _event(
            SessionEventKind.REPLY, reply_code=220, direction=StreamDirection.RESP, frame_number=9
        ),
    ]
    result = smtp_upgrade(events, client_hello_observed=False)
    assert result.state is UpgradeState.ACCEPTED
    assert result.downgrade_consistent is True


def test_plaintext_auth_after_reject_is_fallback() -> None:
    events = [
        _event(
            SessionEventKind.REPLY,
            command="EHLO",
            text="STARTTLS",
            reply_code=250,
            direction=StreamDirection.RESP,
        ),
        _event(SessionEventKind.REQUEST, command="STARTTLS"),
        _event(SessionEventKind.REPLY, reply_code=454, direction=StreamDirection.RESP),
        _event(SessionEventKind.REQUEST, command="AUTH"),
    ]
    result = smtp_upgrade(events, client_hello_observed=False)
    assert result.state is UpgradeState.PLAINTEXT_FALLBACK


def test_plaintext_after_accept_is_violation() -> None:
    events = [
        _event(
            SessionEventKind.REPLY,
            command="EHLO",
            text="STARTTLS",
            reply_code=250,
            direction=StreamDirection.RESP,
        ),
        _event(SessionEventKind.REQUEST, command="STARTTLS"),
        _event(SessionEventKind.REPLY, reply_code=220, direction=StreamDirection.RESP),
        _event(SessionEventKind.REQUEST, command="AUTH"),
    ]
    result = smtp_upgrade(events, client_hello_observed=False)
    assert result.state is UpgradeState.VIOLATION


def test_absent_upgrade_auth_is_fallback() -> None:
    events = [
        _event(SessionEventKind.REQUEST, command="EHLO"),
        _event(
            SessionEventKind.REPLY,
            command="EHLO",
            text="PIPELINING",
            reply_code=250,
            direction=StreamDirection.RESP,
        ),
        _event(SessionEventKind.REQUEST, command="AUTH"),
    ]
    result = smtp_upgrade(events, client_hello_observed=False)
    assert result.state is UpgradeState.PLAINTEXT_FALLBACK
    assert result.downgrade_consistent is False
