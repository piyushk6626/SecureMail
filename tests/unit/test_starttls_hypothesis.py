"""Hypothesis: STARTTLS machines stay on the named alphabet and never invent TLS."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from hypothesis import given
from hypothesis import strategies as st

from securemail.domain.evidence.flow import StreamDirection
from securemail.domain.evidence.session import (
    ExplicitUpgrade,
    ProtocolEvent,
    SessionEventKind,
    UpgradeState,
)
from securemail.domain.policies.starttls.imap_upgrade import imap_upgrade
from securemail.domain.policies.starttls.pop3_upgrade import pop3_upgrade
from securemail.domain.policies.starttls.smtp_upgrade import smtp_upgrade

_SMTP_COMMANDS = ("EHLO", "STARTTLS", "AUTH", "MAIL", "QUIT", "NOOP")
_IMAP_COMMANDS = ("CAPABILITY", "STARTTLS", "LOGIN", "LOGOUT", "NOOP")
_POP3_COMMANDS = ("CAPA", "STLS", "USER", "PASS", "QUIT", "NOOP")


def _smtp_event(command: str, kind: str) -> ProtocolEvent:
    if kind == "advert":
        return ProtocolEvent(
            direction=StreamDirection.RESP,
            kind=SessionEventKind.REPLY,
            command="EHLO",
            text="STARTTLS",
            reply_code=250,
        )
    if kind == "accept":
        return ProtocolEvent(
            direction=StreamDirection.RESP,
            kind=SessionEventKind.REPLY,
            reply_code=220,
        )
    if kind == "reject":
        return ProtocolEvent(
            direction=StreamDirection.RESP,
            kind=SessionEventKind.REPLY,
            reply_code=454,
        )
    if kind == "boundary":
        return ProtocolEvent(direction=StreamDirection.ORIG, kind=SessionEventKind.STARTTLS)
    return ProtocolEvent(
        direction=StreamDirection.ORIG,
        kind=SessionEventKind.REQUEST,
        command=command,
    )


def _imap_event(command: str, kind: str) -> ProtocolEvent:
    if kind == "advert":
        return ProtocolEvent(
            direction=StreamDirection.RESP,
            kind=SessionEventKind.CAPABILITY,
            text="IMAP4rev1 STARTTLS",
        )
    if kind == "accept":
        return ProtocolEvent(
            direction=StreamDirection.RESP,
            kind=SessionEventKind.REPLY,
            text="OK",
            tag="a1",
        )
    if kind == "reject":
        return ProtocolEvent(
            direction=StreamDirection.RESP,
            kind=SessionEventKind.REPLY,
            text="NO",
            tag="a1",
        )
    if kind == "boundary":
        return ProtocolEvent(direction=StreamDirection.ORIG, kind=SessionEventKind.STARTTLS)
    return ProtocolEvent(
        direction=StreamDirection.ORIG,
        kind=SessionEventKind.REQUEST,
        command=command,
        tag="a1",
    )


def _pop3_event(command: str, kind: str) -> ProtocolEvent:
    if kind == "advert":
        return ProtocolEvent(
            direction=StreamDirection.RESP,
            kind=SessionEventKind.CAPABILITY,
            text="STLS",
        )
    if kind == "accept":
        return ProtocolEvent(
            direction=StreamDirection.RESP,
            kind=SessionEventKind.REPLY,
            text="+OK",
        )
    if kind == "reject":
        return ProtocolEvent(
            direction=StreamDirection.RESP,
            kind=SessionEventKind.REPLY,
            text="-ERR",
        )
    if kind == "boundary":
        return ProtocolEvent(direction=StreamDirection.ORIG, kind=SessionEventKind.STARTTLS)
    return ProtocolEvent(
        direction=StreamDirection.ORIG,
        kind=SessionEventKind.REQUEST,
        command=command,
    )


def _assert_machine(
    result: ExplicitUpgrade,
    *,
    client_hello_observed: bool,
) -> None:
    assert result.state is None or result.state in UpgradeState
    if result.state is UpgradeState.TLS_ESTABLISHED:
        assert client_hello_observed
    if not client_hello_observed:
        assert result.state is not UpgradeState.TLS_ESTABLISHED


_KIND_ALPHABET = st.sampled_from(["advert", "accept", "reject", "boundary", "request"])


def _sequences(
    commands: Sequence[str],
    factory: Callable[[str, str], ProtocolEvent],
) -> st.SearchStrategy[list[ProtocolEvent]]:
    return st.lists(
        st.tuples(_KIND_ALPHABET, st.sampled_from(list(commands))),
        max_size=12,
    ).map(lambda items: [factory(command, kind) for kind, command in items])


@given(_sequences(_SMTP_COMMANDS, _smtp_event), st.booleans())
def test_smtp_never_undefined_or_false_established(
    events: list[ProtocolEvent], client_hello_observed: bool
) -> None:
    result = smtp_upgrade(events, client_hello_observed=client_hello_observed)
    _assert_machine(result, client_hello_observed=client_hello_observed)


@given(_sequences(_IMAP_COMMANDS, _imap_event), st.booleans())
def test_imap_never_undefined_or_false_established(
    events: list[ProtocolEvent], client_hello_observed: bool
) -> None:
    result = imap_upgrade(events, client_hello_observed=client_hello_observed)
    _assert_machine(result, client_hello_observed=client_hello_observed)


@given(_sequences(_POP3_COMMANDS, _pop3_event), st.booleans())
def test_pop3_never_undefined_or_false_established(
    events: list[ProtocolEvent], client_hello_observed: bool
) -> None:
    result = pop3_upgrade(events, client_hello_observed=client_hello_observed)
    _assert_machine(result, client_hello_observed=client_hello_observed)
