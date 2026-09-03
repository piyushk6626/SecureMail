"""IMAP STARTTLS transition table."""

from securemail.domain.evidence.flow import StreamDirection
from securemail.domain.evidence.session import ProtocolEvent, SessionEventKind, UpgradeState
from securemail.domain.policies.starttls.imap_upgrade import imap_upgrade


def _event(
    kind: SessionEventKind,
    *,
    command: str | None = None,
    text: str | None = None,
    tag: str | None = None,
    direction: StreamDirection = StreamDirection.ORIG,
    frame_number: int | None = None,
) -> ProtocolEvent:
    return ProtocolEvent(
        direction=direction,
        kind=kind,
        command=command,
        text=text,
        tag=tag,
        frame_number=frame_number,
    )


def test_advertised_capability_tokens() -> None:
    events = [
        _event(
            SessionEventKind.CAPABILITY,
            text="IMAP4rev1 STARTTLS",
            direction=StreamDirection.RESP,
            frame_number=5,
        ),
        _event(SessionEventKind.REQUEST, command="LOGOUT", tag="a002"),
    ]
    result = imap_upgrade(events, client_hello_observed=False)
    assert result.state is UpgradeState.ADVERTISED
    assert result.downgrade_consistent is False


def test_rejected_tagged_starttls() -> None:
    events = [
        _event(
            SessionEventKind.CAPABILITY,
            text="IMAP4rev1 STARTTLS",
            direction=StreamDirection.RESP,
        ),
        _event(SessionEventKind.REQUEST, command="STARTTLS", tag="a002", frame_number=7),
        _event(
            SessionEventKind.REPLY,
            text="NO TLS unavailable",
            tag="a002",
            direction=StreamDirection.RESP,
            frame_number=8,
        ),
    ]
    result = imap_upgrade(events, client_hello_observed=False)
    assert result.state is UpgradeState.REQUESTED


def test_ok_after_rejected_starttls_is_not_acceptance() -> None:
    events = [
        _event(
            SessionEventKind.CAPABILITY,
            text="IMAP4rev1 STARTTLS",
            direction=StreamDirection.RESP,
        ),
        _event(SessionEventKind.REQUEST, command="STARTTLS", tag="a002", frame_number=7),
        _event(
            SessionEventKind.REPLY,
            text="NO TLS unavailable",
            tag="a002",
            direction=StreamDirection.RESP,
            frame_number=8,
        ),
        _event(SessionEventKind.REQUEST, command="LOGOUT", tag="a003"),
        _event(
            SessionEventKind.REPLY,
            text="OK LOGOUT completed",
            tag="a003",
            direction=StreamDirection.RESP,
        ),
    ]
    result = imap_upgrade(events, client_hello_observed=False)
    assert result.state is UpgradeState.REQUESTED


def test_stripped_capability_accept_is_downgrade_consistent() -> None:
    events = [
        _event(
            SessionEventKind.CAPABILITY,
            text="IMAP4rev1 AUTH=PLAIN",
            direction=StreamDirection.RESP,
            frame_number=4,
        ),
        _event(SessionEventKind.REQUEST, command="STARTTLS", tag="a002", frame_number=6),
        _event(
            SessionEventKind.REPLY,
            text="OK begin TLS",
            tag="a002",
            direction=StreamDirection.RESP,
            frame_number=7,
        ),
    ]
    result = imap_upgrade(events, client_hello_observed=False)
    assert result.state is UpgradeState.ACCEPTED
    assert result.downgrade_consistent is True


def test_login_after_accept_without_hello_is_violation() -> None:
    events = [
        _event(
            SessionEventKind.CAPABILITY,
            text="IMAP4rev1 STARTTLS",
            direction=StreamDirection.RESP,
        ),
        _event(SessionEventKind.REQUEST, command="STARTTLS", tag="a002"),
        _event(SessionEventKind.REPLY, text="OK", tag="a002", direction=StreamDirection.RESP),
        _event(SessionEventKind.REQUEST, command="LOGIN"),
    ]
    result = imap_upgrade(events, client_hello_observed=False)
    assert result.state is UpgradeState.VIOLATION


def test_login_after_absent_upgrade_is_fallback() -> None:
    events = [
        _event(
            SessionEventKind.CAPABILITY,
            text="IMAP4rev1",
            direction=StreamDirection.RESP,
        ),
        _event(SessionEventKind.REQUEST, command="LOGIN"),
    ]
    result = imap_upgrade(events, client_hello_observed=False)
    assert result.state is UpgradeState.PLAINTEXT_FALLBACK
    assert result.downgrade_consistent is False


def test_tls_established_with_client_hello() -> None:
    events = [
        _event(
            SessionEventKind.CAPABILITY,
            text="IMAP4rev1 STARTTLS",
            direction=StreamDirection.RESP,
        ),
        _event(SessionEventKind.REQUEST, command="STARTTLS", tag="a002"),
        _event(SessionEventKind.REPLY, text="OK", tag="a002", direction=StreamDirection.RESP),
        _event(SessionEventKind.STARTTLS, direction=StreamDirection.ORIG),
    ]
    result = imap_upgrade(events, client_hello_observed=True, client_hello_frames=(11,))
    assert result.state is UpgradeState.TLS_ESTABLISHED
    assert result.evidence_frames[-1] == 11
