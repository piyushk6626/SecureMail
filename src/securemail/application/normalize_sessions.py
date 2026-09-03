"""Normalize Zeek `sm_email.log` (and optional TShark frames) into `EmailSession` records."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, cast

from securemail.domain.evidence.flow import Flow, StreamDirection
from securemail.domain.evidence.run import EvidenceState
from securemail.domain.evidence.session import (
    EmailSession,
    EventSource,
    ExplicitUpgrade,
    MailProtocol,
    PayloadEvidence,
    PortHint,
    ProtocolEvent,
    SessionEventKind,
)
from securemail.domain.policies.starttls.imap_upgrade import imap_upgrade
from securemail.domain.policies.starttls.implicit_tls import (
    IMPLICIT_TLS_PORTS,
    correlate_implicit_tls,
    protocol_from_alpn,
)
from securemail.domain.policies.starttls.pop3_upgrade import pop3_upgrade
from securemail.domain.policies.starttls.smtp_upgrade import smtp_upgrade

Corroboration = Literal["zeek", "zeek+tshark"]

_MAX_UID_LEN = 64
_MAX_HOST_LEN = 253
_MAX_TEXT_LEN = 128
_MAX_COMMAND_LEN = 32
_MAX_TAG_LEN = 32
_MAX_RECORDS = 10_000
_MAX_EVENTS_PER_SESSION = 256
_MAX_FRAMES = 10_000
_MERGE_WINDOW_SECONDS = 2.0

SMTP_PORTS = frozenset({25, 465, 587})
IMAP_PORTS = frozenset({143, 993})
POP3_PORTS = frozenset({110, 995})
MAIL_SERVICE_PORTS = SMTP_PORTS | IMAP_PORTS | POP3_PORTS

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
        SessionEventKind.UNEXPECTED,
    }
)
_PROTOCOL_BY_NAME: dict[str, MailProtocol] = {
    "smtp": MailProtocol.SMTP,
    "imap": MailProtocol.IMAP,
    "pop3": MailProtocol.POP3,
}
_KIND_BY_NAME: dict[str, SessionEventKind] = {kind.value: kind for kind in SessionEventKind}


@dataclass(frozen=True)
class _SslFacts:
    client_hello: bool
    next_protocol: str | None


@dataclass
class _Stamped:
    ts: float
    order: int
    uid: str
    protocol: MailProtocol | None
    event: ProtocolEvent
    matched: bool = False


def _as_mapping(value: object) -> Mapping[str, object] | None:
    if isinstance(value, Mapping):
        return cast(Mapping[str, object], value)
    return None


def _as_str(value: object, *, max_len: int) -> str | None:
    if isinstance(value, str):
        if not value or len(value) > max_len:
            return None
        return value
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        parts: list[str] = []
        for item in value:
            if isinstance(item, str) and item:
                parts.append(item)
        if not parts:
            return None
        joined = ",".join(parts)
        return joined[:max_len] if len(joined) > max_len else joined
    return None


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


def _as_float(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return float(value)
    if isinstance(value, float):
        return value
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
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
        source=EventSource.ZEEK,
    )


def _resolve_identity(
    confirming: set[MailProtocol],
    *,
    saw_ambiguous: bool,
    tshark_protocols: set[MailProtocol],
    alpn_protocol: MailProtocol | None = None,
) -> tuple[MailProtocol | None, PayloadEvidence, EvidenceState, float | None]:
    zeek_only = set(confirming)
    combined = set(confirming) | set(tshark_protocols)
    if alpn_protocol is not None:
        combined.add(alpn_protocol)
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
    if _as_str(frame.get("smtp.req.command"), max_len=_MAX_COMMAND_LEN) or _as_str(
        frame.get("smtp.response.code"), max_len=_MAX_COMMAND_LEN
    ):
        return MailProtocol.SMTP
    return None


def _tshark_event(frame: Mapping[str, object], protocol: MailProtocol) -> ProtocolEvent | None:
    frame_number = _as_int(frame.get("frame.number"))
    if frame_number is not None and frame_number < 1:
        frame_number = None
    tag = _as_str(frame.get("imap.tag"), max_len=_MAX_TAG_LEN)
    if protocol is MailProtocol.IMAP:
        request = _as_str(frame.get("imap.request.command"), max_len=_MAX_COMMAND_LEN)
        if request is not None:
            command = request.upper()
            return ProtocolEvent(
                direction=StreamDirection.ORIG,
                kind=SessionEventKind.REQUEST,
                command=command,
                argument=_redact_argument(command, None),
                frame_number=frame_number,
                source=EventSource.TSHARK,
                tag=tag,
            )
        status = _as_str(frame.get("imap.response.status"), max_len=_MAX_COMMAND_LEN)
        if status is not None:
            return ProtocolEvent(
                direction=StreamDirection.RESP,
                kind=SessionEventKind.REPLY,
                text=_bound_text(status.upper()),
                frame_number=frame_number,
                source=EventSource.TSHARK,
                tag=tag,
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
                frame_number=frame_number,
                source=EventSource.TSHARK,
            )
        indicator = _as_str(frame.get("pop.response.indicator"), max_len=_MAX_COMMAND_LEN)
        if indicator is not None:
            return ProtocolEvent(
                direction=StreamDirection.RESP,
                kind=SessionEventKind.REPLY,
                text=_bound_text(indicator.upper()),
                frame_number=frame_number,
                source=EventSource.TSHARK,
            )
    if protocol is MailProtocol.SMTP:
        request = _as_str(frame.get("smtp.req.command"), max_len=_MAX_COMMAND_LEN)
        if request is not None:
            command = request.upper()
            if command == "STAR":
                command = "STARTTLS"
            return ProtocolEvent(
                direction=StreamDirection.ORIG,
                kind=SessionEventKind.REQUEST,
                command=command,
                argument=_redact_argument(command, None),
                frame_number=frame_number,
                source=EventSource.TSHARK,
            )
        code = _as_int(frame.get("smtp.response.code"))
        if code is not None:
            return ProtocolEvent(
                direction=StreamDirection.RESP,
                kind=SessionEventKind.REPLY,
                reply_code=code,
                frame_number=frame_number,
                source=EventSource.TSHARK,
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


def _is_client_hello_frame(frame: Mapping[str, object]) -> bool:
    raw = frame.get("tls.handshake.type")
    if raw == 1 or raw == 1.0:
        return True
    if isinstance(raw, str) and raw.split(",")[0].strip() in {"1", "1.0"}:
        return True
    return False


def _ssl_facts(logs: Mapping[str, list[dict[str, object]]]) -> dict[str, _SslFacts]:
    facts: dict[str, _SslFacts] = {}
    for row in _bounded_records(logs.get("ssl.log", [])):
        uid = _as_str(row.get("uid"), max_len=_MAX_UID_LEN)
        if uid is None:
            continue
        history = _as_str(row.get("ssl_history"), max_len=64) or ""
        next_protocol = _as_str(row.get("next_protocol"), max_len=32)
        facts[uid] = _SslFacts(
            client_hello="C" in history,
            next_protocol=next_protocol,
        )
    return facts


def _compatible(zeek_event: ProtocolEvent, tshark_event: ProtocolEvent) -> bool:
    if zeek_event.direction != tshark_event.direction:
        return False
    if (
        zeek_event.tag is not None
        and tshark_event.tag is not None
        and zeek_event.tag != tshark_event.tag
    ):
        return False
    zcmd = (zeek_event.command or "").upper()
    tcmd = (tshark_event.command or "").upper()
    if (
        zeek_event.kind is SessionEventKind.REQUEST
        and tshark_event.kind is SessionEventKind.REQUEST
    ):
        return zcmd == tcmd
    if zeek_event.kind is SessionEventKind.REPLY and tshark_event.kind is SessionEventKind.REPLY:
        if zeek_event.reply_code is not None and tshark_event.reply_code is not None:
            return zeek_event.reply_code == tshark_event.reply_code
        ztext = (zeek_event.text or "").upper()
        ttext = (tshark_event.text or "").upper()
        first_zeek_token = ztext.split()[0] if ztext else ""
        texts_overlap = (
            bool(ttext)
            and bool(ztext)
            and (ttext in ztext or ztext.startswith(ttext) or ttext.startswith(first_zeek_token))
        )
        if texts_overlap:
            return True
        return bool(zcmd) and zcmd == tcmd
    if (
        zeek_event.kind is SessionEventKind.STARTTLS
        and tshark_event.kind is SessionEventKind.REQUEST
        and tcmd in {"STARTTLS", "STLS"}
    ):
        return False
    return False


def _with_tshark_evidence(zeek_event: ProtocolEvent, tshark_event: ProtocolEvent) -> ProtocolEvent:
    return zeek_event.model_copy(
        update={
            "frame_number": tshark_event.frame_number or zeek_event.frame_number,
            "tag": tshark_event.tag or zeek_event.tag,
        }
    )


def _is_duplicate_capability(previous: ProtocolEvent | None, current: ProtocolEvent) -> bool:
    if previous is None or current.kind is not SessionEventKind.CAPABILITY:
        return False
    if previous.kind is not SessionEventKind.CAPABILITY:
        return False
    return previous.text == current.text and previous.direction == current.direction


def _merge_events(zeek: list[_Stamped], tshark: list[_Stamped]) -> list[_Stamped]:
    for extra in tshark:
        if extra.event.kind is SessionEventKind.REQUEST and extra.event.command is None:
            extra.matched = True
            continue
        best: _Stamped | None = None
        best_delta = _MERGE_WINDOW_SECONDS
        for candidate in zeek:
            if candidate.matched or candidate.uid != extra.uid:
                continue
            if not _compatible(candidate.event, extra.event):
                continue
            delta = abs(candidate.ts - extra.ts)
            if delta <= best_delta:
                best = candidate
                best_delta = delta
        if best is None:
            continue
        best.event = _with_tshark_evidence(best.event, extra.event)
        best.matched = True
        extra.matched = True
    merged = [*zeek, *[item for item in tshark if not item.matched]]
    merged.sort(key=lambda item: (item.ts, item.order))
    return merged


def needs_tshark_corroboration(
    sessions: Sequence[EmailSession],
    flows: Sequence[Flow] = (),
    logs: Mapping[str, list[dict[str, object]]] | None = None,
) -> bool:
    """True when a bounded mail/TLS TShark pass can add frame-level evidence."""

    interesting = {MailProtocol.SMTP, MailProtocol.IMAP, MailProtocol.POP3}
    payloads = {PayloadEvidence.SMTP, PayloadEvidence.IMAP, PayloadEvidence.POP3}
    if any(
        session.protocol in interesting or session.payload_evidence in payloads
        for session in sessions
    ):
        return True
    ssl_uids: set[str] = set()
    if logs is not None:
        for row in _bounded_records(logs.get("ssl.log", [])):
            uid = _as_str(row.get("uid"), max_len=_MAX_UID_LEN)
            if uid is not None:
                ssl_uids.add(uid)
    for flow in flows:
        if flow.resp.port in IMPLICIT_TLS_PORTS:
            return True
        if flow.uid in ssl_uids and flow.resp.port in MAIL_SERVICE_PORTS:
            return True
    return False


def needs_imap_pop_corroboration(sessions: Sequence[EmailSession]) -> bool:
    """Backward-compatible alias used by Step 2 tests."""

    return needs_tshark_corroboration(sessions)


def _assess_session(
    session: EmailSession,
    flow: Flow,
    ssl: _SslFacts | None,
    hello_frames: Sequence[int],
) -> EmailSession:
    client_hello = bool(hello_frames) or (ssl.client_hello if ssl is not None else False)
    frames = list(hello_frames)
    if session.protocol is MailProtocol.SMTP:
        upgrade = smtp_upgrade(
            session.events, client_hello_observed=client_hello, client_hello_frames=frames
        )
    elif session.protocol is MailProtocol.IMAP:
        upgrade = imap_upgrade(
            session.events, client_hello_observed=client_hello, client_hello_frames=frames
        )
    elif session.protocol is MailProtocol.POP3:
        upgrade = pop3_upgrade(
            session.events, client_hello_observed=client_hello, client_hello_frames=frames
        )
    else:
        upgrade = ExplicitUpgrade(state=None, evidence_state=EvidenceState.NOT_OBSERVABLE)
    implicit = correlate_implicit_tls(
        responder_port=flow.resp.port,
        tls_on_connection=ssl is not None or bool(hello_frames),
        negotiated_alpn=ssl.next_protocol if ssl is not None else None,
        alpn_frames=frames if ssl is not None and protocol_from_alpn(ssl.next_protocol) else (),
    )
    return session.model_copy(update={"explicit_upgrade": upgrade, "implicit_tls": implicit})


def normalize_sessions(
    logs: Mapping[str, list[dict[str, object]]],
    flows: Sequence[Flow],
    tshark_frames: Sequence[Mapping[str, object]] | None = None,
) -> list[EmailSession]:
    """Join `sm_email.log` to flows; keep `port_hint` independent of payload identity."""

    flow_by_uid = {flow.uid: flow for flow in flows}
    ssl_by_uid = _ssl_facts(logs)
    rows = _bounded_records(logs.get("sm_email.log", []))
    zeek_by_uid: dict[str, list[_Stamped]] = defaultdict(list)
    confirming_by_uid: dict[str, set[MailProtocol]] = defaultdict(set)
    ambiguous_uids: set[str] = set()
    seen_uids: list[str] = []
    order = 0

    previous_by_uid: dict[str, ProtocolEvent] = {}
    for row in rows:
        uid = _as_str(row.get("uid"), max_len=_MAX_UID_LEN)
        if uid is None or uid not in flow_by_uid:
            continue
        event = _event_from_email_row(row)
        if event is None:
            continue
        if _is_duplicate_capability(previous_by_uid.get(uid), event):
            continue
        previous_by_uid[uid] = event
        ts = _as_float(row.get("ts"))
        if ts is None:
            ts = float(order)
        if uid not in zeek_by_uid:
            seen_uids.append(uid)
        stamped = _Stamped(
            ts=ts,
            order=order,
            uid=uid,
            protocol=_protocol_from_name(_as_str(row.get("protocol"), max_len=16)),
            event=event,
        )
        order += 1
        zeek_by_uid[uid].append(stamped)
        protocol = stamped.protocol
        if event.kind is SessionEventKind.AMBIGUOUS_BANNER:
            ambiguous_uids.add(uid)
            continue
        if protocol is not None and event.kind in _CONFIRMING_KINDS:
            confirming_by_uid[uid].add(protocol)

    tshark_by_uid: dict[str, set[MailProtocol]] = defaultdict(set)
    tshark_events: dict[str, list[_Stamped]] = defaultdict(list)
    hello_frames: dict[str, list[int]] = defaultdict(list)
    used_tshark = False
    for frame in _bounded_records(tshark_frames or [], limit=_MAX_FRAMES):
        uid = _match_frame_uid(frame, flows)
        if uid is None:
            continue
        used_tshark = True
        if _is_client_hello_frame(frame):
            frame_number = _as_int(frame.get("frame.number"))
            if (
                frame_number is not None
                and frame_number >= 1
                and frame_number not in hello_frames[uid]
            ):
                hello_frames[uid].append(frame_number)
        protocol = _tshark_protocol(frame)
        if protocol is None:
            continue
        tshark_by_uid[uid].add(protocol)
        extra = _tshark_event(frame, protocol)
        if extra is None:
            continue
        ts = _as_float(frame.get("frame.time_epoch"))
        if ts is None:
            ts = float(order)
        if uid not in zeek_by_uid and uid not in tshark_events:
            seen_uids.append(uid)
        tshark_events[uid].append(
            _Stamped(ts=ts, order=order, uid=uid, protocol=protocol, event=extra)
        )
        order += 1

    events_by_uid: dict[str, list[ProtocolEvent]] = {}
    for uid in dict.fromkeys([*seen_uids, *tshark_by_uid, *ssl_by_uid]):
        merged = _merge_events(zeek_by_uid.get(uid, []), tshark_events.get(uid, []))
        bounded: list[ProtocolEvent] = []
        last: ProtocolEvent | None = None
        for item in merged:
            if _is_duplicate_capability(last, item.event):
                continue
            if len(bounded) >= _MAX_EVENTS_PER_SESSION:
                break
            bounded.append(item.event)
            last = item.event
        events_by_uid[uid] = bounded

    session_uids = list(
        dict.fromkeys(
            [
                *seen_uids,
                *tshark_by_uid,
                *[uid for uid, flow in flow_by_uid.items() if uid in ssl_by_uid],
            ]
        )
    )
    sessions: list[EmailSession] = []
    for uid in session_uids:
        flow = flow_by_uid.get(uid)
        if flow is None:
            continue
        ssl = ssl_by_uid.get(uid)
        alpn_protocol = protocol_from_alpn(ssl.next_protocol) if ssl is not None else None
        protocol, payload, state, confidence = _resolve_identity(
            confirming_by_uid.get(uid, set()),
            saw_ambiguous=uid in ambiguous_uids,
            tshark_protocols=tshark_by_uid.get(uid, set()),
            alpn_protocol=alpn_protocol,
        )
        implicit_candidate = flow.resp.port in IMPLICIT_TLS_PORTS and ssl is not None
        if payload is PayloadEvidence.NONE and uid not in ambiguous_uids and not implicit_candidate:
            continue
        if implicit_candidate and payload is PayloadEvidence.NONE:
            if alpn_protocol is not None:
                protocol = alpn_protocol
                payload = PayloadEvidence(alpn_protocol.value)
                state = EvidenceState.OBSERVED
            else:
                payload = PayloadEvidence.INDETERMINATE
                state = EvidenceState.INDETERMINATE
                protocol = None
        corroboration: Corroboration = (
            "zeek+tshark" if used_tshark and uid in tshark_by_uid else "zeek"
        )
        if used_tshark and hello_frames.get(uid) and uid not in tshark_by_uid:
            corroboration = "zeek+tshark"
        session = EmailSession(
            uid=uid,
            protocol=protocol,
            port_hint=port_hint_for_flow(flow),
            payload_evidence=payload,
            evidence_state=state,
            identification_confidence=confidence,
            corroboration=corroboration,
            events=list(events_by_uid.get(uid, ())),
        )
        sessions.append(_assess_session(session, flow, ssl, hello_frames.get(uid, ())))

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
