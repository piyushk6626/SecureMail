"""POP3 STLS state machine. Pure transition table over observed events."""

from __future__ import annotations

from collections.abc import Sequence

from securemail.domain.evidence.run import EvidenceState
from securemail.domain.evidence.session import (
    ExplicitUpgrade,
    ProtocolEvent,
    SessionEventKind,
    UpgradeState,
)

_STLS = "STLS"
_CREDENTIAL_COMMANDS = frozenset({"USER", "PASS", "APOP", "AUTH"})
_HARMLESS_COMMANDS = frozenset({"CAPA", "STLS", "QUIT", "NOOP"})


def _add_frame(frames: list[int], event: ProtocolEvent) -> None:
    if event.frame_number is not None and event.frame_number not in frames:
        frames.append(event.frame_number)


def _tokens(event: ProtocolEvent) -> set[str]:
    text = (event.text or "").upper()
    return {token for token in text.replace(",", " ").split() if token}


def _is_ok(event: ProtocolEvent) -> bool:
    text = (event.text or "").upper()
    return text.startswith("+OK") or text.startswith("OK")


def _is_err(event: ProtocolEvent) -> bool:
    text = (event.text or "").upper()
    return text.startswith("-ERR") or text.startswith("ERR")


def pop3_upgrade(
    events: Sequence[ProtocolEvent],
    *,
    client_hello_observed: bool,
    client_hello_frames: Sequence[int] = (),
) -> ExplicitUpgrade:
    """Map POP3 observations to a terminal upgrade state. Never invent TLS."""

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
        tokens = _tokens(event)
        if event.kind is SessionEventKind.REQUEST and command == "CAPA":
            saw_capability_exchange = True
        if event.kind is SessionEventKind.CAPABILITY:
            saw_capability_exchange = True
            if _STLS in tokens or command == _STLS:
                advertised = True
                _add_frame(frames, event)
        if event.kind is SessionEventKind.REPLY and _STLS in tokens:
            advertised = True
            saw_capability_exchange = True
            _add_frame(frames, event)
        if event.kind is SessionEventKind.REQUEST and command == _STLS:
            requested = True
            awaiting_reply = True
            _add_frame(frames, event)
            continue
        if awaiting_reply and event.kind is SessionEventKind.REPLY:
            if _is_ok(event):
                accepted = True
                _add_frame(frames, event)
            elif _is_err(event):
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
