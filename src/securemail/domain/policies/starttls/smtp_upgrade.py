"""SMTP STARTTLS state machine. Pure transition table over observed events."""

from __future__ import annotations

from collections.abc import Sequence

from securemail.domain.evidence.run import EvidenceState
from securemail.domain.evidence.session import (
    ExplicitUpgrade,
    ProtocolEvent,
    SessionEventKind,
    UpgradeState,
)

_STARTTLS = "STARTTLS"
_CAPABILITY_COMMANDS = frozenset({"EHLO", "HELO", "LHLO"})
_CREDENTIAL_COMMANDS = frozenset({"AUTH"})
_HARMLESS_COMMANDS = frozenset({"EHLO", "HELO", "LHLO", "STARTTLS", "QUIT", "NOOP", "RSET", "HELP"})


def _add_frame(frames: list[int], event: ProtocolEvent) -> None:
    if event.frame_number is not None and event.frame_number not in frames:
        frames.append(event.frame_number)


def _is_starttls_advertisement(event: ProtocolEvent) -> bool:
    text = (event.text or "").upper()
    command = (event.command or "").upper()
    if event.kind is SessionEventKind.CAPABILITY and _STARTTLS in text.split():
        return True
    if event.kind is SessionEventKind.REPLY and _STARTTLS in text.split():
        return True
    return command == _STARTTLS and event.kind is SessionEventKind.REPLY and event.reply_code == 250


def _is_capability_reply(event: ProtocolEvent) -> bool:
    command = (event.command or "").upper()
    if event.kind is SessionEventKind.REPLY and command in _CAPABILITY_COMMANDS:
        return True
    return event.kind is SessionEventKind.CAPABILITY


def smtp_upgrade(
    events: Sequence[ProtocolEvent],
    *,
    client_hello_observed: bool,
    client_hello_frames: Sequence[int] = (),
) -> ExplicitUpgrade:
    """Map SMTP observations to a terminal upgrade state. Never invent TLS."""

    advertised = False
    requested = False
    accepted = False
    saw_capability_exchange = False
    violation = False
    plaintext_fallback = False
    awaiting_reply = False
    frames: list[int] = []

    for event in events:
        command = (event.command or "").upper()
        if _is_capability_reply(event):
            saw_capability_exchange = True
        if _is_starttls_advertisement(event):
            advertised = True
            _add_frame(frames, event)
        if event.kind is SessionEventKind.REQUEST and command == _STARTTLS:
            requested = True
            awaiting_reply = True
            _add_frame(frames, event)
            continue
        if awaiting_reply and event.kind is SessionEventKind.REPLY:
            code = event.reply_code
            if code is not None and 200 <= code < 300:
                accepted = True
                _add_frame(frames, event)
            elif code is not None and code >= 400:
                _add_frame(frames, event)
            awaiting_reply = False
            continue
        if event.kind is SessionEventKind.STARTTLS:
            accepted = True
            _add_frame(frames, event)
            continue
        if event.kind is SessionEventKind.UNEXPECTED:
            if accepted and not client_hello_observed:
                violation = True
                _add_frame(frames, event)
            continue
        if event.kind is SessionEventKind.REQUEST and command in _CREDENTIAL_COMMANDS:
            _add_frame(frames, event)
            if accepted and not client_hello_observed:
                violation = True
            elif not accepted:
                plaintext_fallback = True
            continue
        if (
            event.kind is SessionEventKind.REQUEST
            and command not in _HARMLESS_COMMANDS
            and accepted
            and not client_hello_observed
        ):
            violation = True
            _add_frame(frames, event)

    if accepted and client_hello_observed:
        for frame in client_hello_frames:
            if frame not in frames:
                frames.append(frame)

    downgrade_consistent = saw_capability_exchange and not advertised and requested and accepted

    if violation:
        state = UpgradeState.VIOLATION
    elif plaintext_fallback:
        state = UpgradeState.PLAINTEXT_FALLBACK
    elif accepted and client_hello_observed:
        state = UpgradeState.TLS_ESTABLISHED
    elif accepted:
        state = UpgradeState.ACCEPTED
    elif requested:
        state = UpgradeState.REQUESTED
    elif advertised:
        state = UpgradeState.ADVERTISED
    else:
        state = None

    if state is UpgradeState.TLS_ESTABLISHED and not client_hello_observed:
        state = UpgradeState.ACCEPTED

    evidence_state = EvidenceState.OBSERVED if state is not None else EvidenceState.NOT_OBSERVABLE
    frames.sort()
    return ExplicitUpgrade(
        state=state,
        evidence_state=evidence_state,
        evidence_frames=frames,
        downgrade_consistent=downgrade_consistent,
    )
