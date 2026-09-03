"""POP3 STLS transition table."""

from securemail.domain.evidence.flow import StreamDirection
from securemail.domain.evidence.session import ProtocolEvent, SessionEventKind, UpgradeState
from securemail.domain.policies.starttls.pop3_upgrade import pop3_upgrade


def _event(
    kind: SessionEventKind,
    *,
    command: str | None = None,
    text: str | None = None,
    direction: StreamDirection = StreamDirection.ORIG,
    frame_number: int | None = None,
) -> ProtocolEvent:
    return ProtocolEvent(
        direction=direction,
        kind=kind,
        command=command,
        text=text,
        frame_number=frame_number,
    )


def test_stls_advertised_via_capa_token() -> None:
    events = [
        _event(SessionEventKind.REQUEST, command="CAPA"),
        _event(
            SessionEventKind.CAPABILITY, text="STLS", direction=StreamDirection.RESP, frame_number=5
        ),
        _event(SessionEventKind.REQUEST, command="QUIT"),
    ]
    result = pop3_upgrade(events, client_hello_observed=False)
    assert result.state is UpgradeState.ADVERTISED
    assert result.downgrade_consistent is False


def test_stls_rejected() -> None:
    events = [
        _event(SessionEventKind.CAPABILITY, text="STLS", direction=StreamDirection.RESP),
        _event(SessionEventKind.REQUEST, command="STLS", frame_number=6),
        _event(
            SessionEventKind.REPLY,
            text="-ERR TLS unavailable",
            direction=StreamDirection.RESP,
            frame_number=7,
        ),
    ]
    result = pop3_upgrade(events, client_hello_observed=False)
    assert result.state is UpgradeState.REQUESTED


def test_stripped_capa_accept_is_downgrade_consistent() -> None:
    events = [
        _event(SessionEventKind.REQUEST, command="CAPA"),
        _event(SessionEventKind.CAPABILITY, text="USER", direction=StreamDirection.RESP),
        _event(SessionEventKind.REQUEST, command="STLS"),
        _event(SessionEventKind.REPLY, text="+OK Begin TLS", direction=StreamDirection.RESP),
    ]
    result = pop3_upgrade(events, client_hello_observed=False)
    assert result.state is UpgradeState.ACCEPTED
    assert result.downgrade_consistent is True


def test_user_after_accept_is_violation() -> None:
    events = [
        _event(SessionEventKind.CAPABILITY, text="STLS", direction=StreamDirection.RESP),
        _event(SessionEventKind.REQUEST, command="STLS"),
        _event(SessionEventKind.REPLY, text="+OK", direction=StreamDirection.RESP),
        _event(SessionEventKind.REQUEST, command="USER"),
    ]
    result = pop3_upgrade(events, client_hello_observed=False)
    assert result.state is UpgradeState.VIOLATION


def test_user_after_failed_stls_is_fallback() -> None:
    events = [
        _event(SessionEventKind.CAPABILITY, text="STLS", direction=StreamDirection.RESP),
        _event(SessionEventKind.REQUEST, command="STLS"),
        _event(SessionEventKind.REPLY, text="-ERR", direction=StreamDirection.RESP),
        _event(SessionEventKind.REQUEST, command="USER"),
    ]
    result = pop3_upgrade(events, client_hello_observed=False)
    assert result.state is UpgradeState.PLAINTEXT_FALLBACK


def test_tls_established_needs_client_hello() -> None:
    events = [
        _event(SessionEventKind.CAPABILITY, text="STLS", direction=StreamDirection.RESP),
        _event(SessionEventKind.REQUEST, command="STLS"),
        _event(SessionEventKind.REPLY, text="+OK", direction=StreamDirection.RESP),
        _event(SessionEventKind.STARTTLS, direction=StreamDirection.ORIG),
    ]
    without_hello = pop3_upgrade(events, client_hello_observed=False)
    with_hello = pop3_upgrade(events, client_hello_observed=True, client_hello_frames=(9,))
    assert without_hello.state is UpgradeState.ACCEPTED
    assert with_hello.state is UpgradeState.TLS_ESTABLISHED
