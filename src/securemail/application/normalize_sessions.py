"""Normalize Zeek `sm_email.log` (and optional TShark frames) into `EmailSession` records."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Literal, cast

from securemail.domain.evidence.flow import Flow, StreamDirection
from securemail.domain.evidence.run import EvidenceState
from securemail.domain.evidence.session import (
    EmailSession,
    MailProtocol,
    PayloadEvidence,
    PortHint,
    ProtocolEvent,
    SessionEventKind,
)

Corroboration = Literal["zeek", "zeek+tshark"]

_MAX_UID_LEN = 64
_MAX_HOST_LEN = 253
_MAX_TEXT_LEN = 128
_MAX_COMMAND_LEN = 32
_MAX_RECORDS = 10_000
_MAX_EVENTS_PER_SESSION = 256
_MAX_FRAMES = 10_000

SMTP_PORTS = frozenset({25, 465, 587})
IMAP_PORTS = frozenset({143, 993})
POP3_PORTS = frozenset({110, 995})

_SECRET_COMMANDS = frozenset(
    {
        "AUTH",
        "LOGIN",
        "USER",
        "PASS",
        "APOP",
        "AUTHENTICATE",
        "AUTH_ANSWER",
        "**",
        "MAIL",
        "RCPT",
    }
)
_CONFIRMING_KINDS = frozenset(
    {
        SessionEventKind.REQUEST,
        SessionEventKind.REPLY,
        SessionEventKind.CAPABILITY,
        SessionEventKind.STARTTLS,
        SessionEventKind.CONFIRMATION,
    }
)
_PROTOCOL_BY_NAME: dict[str, MailProtocol] = {
    "smtp": MailProtocol.SMTP,
    "imap": MailProtocol.IMAP,
    "pop3": MailProtocol.POP3,
}
_KIND_BY_NAME: dict[str, SessionEventKind] = {kind.value: kind for kind in SessionEventKind}


def _as_mapping(value: object) -> Mapping[str, object] | None:
    if isinstance(value, Mapping):
        return cast(Mapping[str, object], value)
    return None


def _as_str(value: object, *, max_len: int) -> str | None:
    if not isinstance(value, str):
        return None
    if not value or len(value) > max_len:
        return None
    return value


def _as_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and value.is_integer() and value >= 0:
        return int(value)
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _as_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    return None


def _bounded_records(rows: object, *, limit: int = _MAX_RECORDS) -> list[Mapping[str, object]]:
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        return []
    out: list[Mapping[str, object]] = []
    for item in rows[:limit]:
        mapping = _as_mapping(item)
        if mapping is not None:
            out.append(mapping)
    return out


def _bound_text(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    if len(stripped) > _MAX_TEXT_LEN:
        return stripped[:_MAX_TEXT_LEN]
    return stripped


def _redact_argument(command: str | None, argument: str | None) -> str | None:
    bounded = _bound_text(argument)
    if bounded is None:
        return None
    if command is not None and command.upper() in _SECRET_COMMANDS:
        return "<redacted>"
    return bounded


def _redact_text(command: str | None, text: str | None) -> str | None:
    bounded = _bound_text(text)
    if bounded is None:
        return None
    if command is not None and command.upper() in _SECRET_COMMANDS:
        return "<redacted>"
    return bounded


def port_hint_for_flow(flow: Flow) -> PortHint:
    """Infer a service hint from well-known ports. Responder port wins."""

    for port in (flow.resp.port, flow.orig.port):
        if port in SMTP_PORTS:
            return PortHint.SMTP
        if port in IMAP_PORTS:
            return PortHint.IMAP
        if port in POP3_PORTS:
            return PortHint.POP3
    return PortHint.NONE


def _protocol_from_name(raw: str | None) -> MailProtocol | None:
    if raw is None:
        return None
    return _PROTOCOL_BY_NAME.get(raw.lower())


def _kind_from_name(raw: str | None) -> SessionEventKind | None:
    if raw is None:
        return None
    return _KIND_BY_NAME.get(raw.lower())


def _direction(is_orig: bool | None) -> StreamDirection:
    return StreamDirection.ORIG if is_orig is not False else StreamDirection.RESP


def _event_from_email_row(row: Mapping[str, object]) -> ProtocolEvent | None:
    kind = _kind_from_name(_as_str(row.get("event_type"), max_len=32))
    if kind is None:
        return None
    command = _as_str(row.get("command"), max_len=_MAX_COMMAND_LEN)
    if command is not None:
        command = command.upper()
    argument = _redact_argument(command, _as_str(row.get("argument"), max_len=_MAX_TEXT_LEN))
    text = _redact_text(command, _as_str(row.get("text"), max_len=_MAX_TEXT_LEN * 2))
    reply_code = _as_int(row.get("reply_code"))
    return ProtocolEvent(
        direction=_direction(_as_bool(row.get("is_orig"))),
        kind=kind,
        command=command,
        argument=argument,
        reply_code=reply_code,
        text=text,
    )


def _resolve_identity(
    confirming: set[MailProtocol],
    *,
    saw_ambiguous: bool,
    tshark_protocols: set[MailProtocol],
) -> tuple[MailProtocol | None, PayloadEvidence, EvidenceState, float | None]:
    zeek_only = set(confirming)
    combined = set(confirming) | set(tshark_protocols)
    sources_disagree = bool(tshark_protocols) and bool(zeek_only) and zeek_only != tshark_protocols
    if sources_disagree:
        return None, PayloadEvidence.INDETERMINATE, EvidenceState.CONFLICTING, 0.5
    if len(combined) > 1:
        return None, PayloadEvidence.INDETERMINATE, EvidenceState.CONFLICTING, None
    identified = next(iter(combined), None)
    if identified is not None:
        payload = PayloadEvidence(identified.value)
        return identified, payload, EvidenceState.OBSERVED, None
    if saw_ambiguous:
        return None, PayloadEvidence.INDETERMINATE, EvidenceState.INDETERMINATE, None
    return None, PayloadEvidence.NONE, EvidenceState.INDETERMINATE, None


def _flow_addresses(flow: Flow) -> set[tuple[str, int]]:
    return {(flow.orig.host, flow.orig.port), (flow.resp.host, flow.resp.port)}


def _frame_endpoints(frame: Mapping[str, object]) -> list[tuple[str, int]]:
    src_port = _as_int(frame.get("tcp.srcport"))
    dst_port = _as_int(frame.get("tcp.dstport"))
    endpoints: list[tuple[str, int]] = []
    for host_key in ("ip.src", "ipv6.src"):
        host = _as_str(frame.get(host_key), max_len=_MAX_HOST_LEN)
        if host is not None and src_port is not None and src_port <= 65535:
            endpoints.append((host, src_port))
    for host_key in ("ip.dst", "ipv6.dst"):
        host = _as_str(frame.get(host_key), max_len=_MAX_HOST_LEN)
        if host is not None and dst_port is not None and dst_port <= 65535:
            endpoints.append((host, dst_port))
    return endpoints


def _tshark_protocol(frame: Mapping[str, object]) -> MailProtocol | None:
    if _as_str(frame.get("imap.request.command"), max_len=_MAX_COMMAND_LEN) or _as_str(
        frame.get("imap.response.status"), max_len=_MAX_COMMAND_LEN
    ):
        return MailProtocol.IMAP
    if _as_str(frame.get("pop.request.command"), max_len=_MAX_COMMAND_LEN) or _as_str(
        frame.get("pop.response.indicator"), max_len=_MAX_COMMAND_LEN
    ):
        return MailProtocol.POP3
    return None


def _tshark_event(frame: Mapping[str, object], protocol: MailProtocol) -> ProtocolEvent | None:
    if protocol is MailProtocol.IMAP:
        request = _as_str(frame.get("imap.request.command"), max_len=_MAX_COMMAND_LEN)
        if request is not None:
            command = request.upper()
            return ProtocolEvent(
                direction=StreamDirection.ORIG,
                kind=SessionEventKind.REQUEST,
                command=command,
                argument=_redact_argument(command, None),
            )
        status = _as_str(frame.get("imap.response.status"), max_len=_MAX_COMMAND_LEN)
        if status is not None:
            return ProtocolEvent(
                direction=StreamDirection.RESP,
                kind=SessionEventKind.REPLY,
                text=_bound_text(status.upper()),
            )
    if protocol is MailProtocol.POP3:
        request = _as_str(frame.get("pop.request.command"), max_len=_MAX_COMMAND_LEN)
        if request is not None:
            command = request.upper()
            return ProtocolEvent(
                direction=StreamDirection.ORIG,
                kind=SessionEventKind.REQUEST,
                command=command,
                argument=_redact_argument(command, None),
            )
        indicator = _as_str(frame.get("pop.response.indicator"), max_len=_MAX_COMMAND_LEN)
        if indicator is not None:
            return ProtocolEvent(
                direction=StreamDirection.RESP,
                kind=SessionEventKind.REPLY,
                text=_bound_text(indicator.upper()),
            )
    return None


def _match_frame_uid(frame: Mapping[str, object], flows: Sequence[Flow]) -> str | None:
    endpoints = set(_frame_endpoints(frame))
    if len(endpoints) < 2:
        return None
    matches = [
        flow.uid
        for flow in flows
        if endpoints.issubset(_flow_addresses(flow)) or endpoints == _flow_addresses(flow)
    ]
    if len(matches) != 1:
        return None
    return matches[0]


def needs_imap_pop_corroboration(sessions: Sequence[EmailSession]) -> bool:
    """True when a bounded IMAP/POP TShark pass can add command-level evidence."""

    interesting = {MailProtocol.IMAP, MailProtocol.POP3}
    payloads = {PayloadEvidence.IMAP, PayloadEvidence.POP3}
    return any(
        session.protocol in interesting or session.payload_evidence in payloads
        for session in sessions
    )


def normalize_sessions(
    logs: Mapping[str, list[dict[str, object]]],
    flows: Sequence[Flow],
    tshark_frames: Sequence[Mapping[str, object]] | None = None,
) -> list[EmailSession]:
    """Join `sm_email.log` to flows; keep `port_hint` independent of payload identity."""

    flow_by_uid = {flow.uid: flow for flow in flows}
    rows = _bounded_records(logs.get("sm_email.log", []))
    events_by_uid: dict[str, list[ProtocolEvent]] = defaultdict(list)
    confirming_by_uid: dict[str, set[MailProtocol]] = defaultdict(set)
    ambiguous_uids: set[str] = set()
    seen_uids: list[str] = []

    for row in rows:
        uid = _as_str(row.get("uid"), max_len=_MAX_UID_LEN)
        if uid is None or uid not in flow_by_uid:
            continue
        event = _event_from_email_row(row)
        if event is None:
            continue
        if uid not in events_by_uid:
            seen_uids.append(uid)
        if len(events_by_uid[uid]) < _MAX_EVENTS_PER_SESSION:
            events_by_uid[uid].append(event)
        protocol = _protocol_from_name(_as_str(row.get("protocol"), max_len=16))
        if event.kind is SessionEventKind.AMBIGUOUS_BANNER:
            ambiguous_uids.add(uid)
            continue
        if protocol is not None and event.kind in _CONFIRMING_KINDS:
            confirming_by_uid[uid].add(protocol)

    tshark_by_uid: dict[str, set[MailProtocol]] = defaultdict(set)
    used_tshark = False
    for frame in _bounded_records(tshark_frames or [], limit=_MAX_FRAMES):
        protocol = _tshark_protocol(frame)
        if protocol is None:
            continue
        uid = _match_frame_uid(frame, flows)
        if uid is None:
            continue
        used_tshark = True
        tshark_by_uid[uid].add(protocol)
        extra = _tshark_event(frame, protocol)
        if extra is None:
            continue
        if uid not in events_by_uid:
            seen_uids.append(uid)
        if len(events_by_uid[uid]) < _MAX_EVENTS_PER_SESSION:
            events_by_uid[uid].append(extra)

    session_uids = list(dict.fromkeys([*seen_uids, *tshark_by_uid]))
    sessions: list[EmailSession] = []
    for uid in session_uids:
        flow = flow_by_uid.get(uid)
        if flow is None:
            continue
        protocol, payload, state, confidence = _resolve_identity(
            confirming_by_uid.get(uid, set()),
            saw_ambiguous=uid in ambiguous_uids,
            tshark_protocols=tshark_by_uid.get(uid, set()),
        )
        if payload is PayloadEvidence.NONE and uid not in ambiguous_uids:
            continue
        corroboration: Corroboration = (
            "zeek+tshark" if used_tshark and uid in tshark_by_uid else "zeek"
        )
        sessions.append(
            EmailSession(
                uid=uid,
                protocol=protocol,
                port_hint=port_hint_for_flow(flow),
                payload_evidence=payload,
                evidence_state=state,
                identification_confidence=confidence,
                corroboration=corroboration,
                events=list(events_by_uid.get(uid, ())),
            )
        )

    sessions.sort(
        key=lambda session: (
            session.protocol.value if session.protocol is not None else "",
            flow_by_uid[session.uid].orig.host,
            flow_by_uid[session.uid].orig.port,
            flow_by_uid[session.uid].resp.host,
            flow_by_uid[session.uid].resp.port,
            session.uid,
        )
    )
    return sessions
