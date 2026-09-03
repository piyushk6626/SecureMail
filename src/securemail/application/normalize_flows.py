"""Normalize Zeek logs and capinfos facts into canonical `Flow` records."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Literal, cast

from securemail.domain.evidence.flow import (
    ByteRange,
    Flow,
    FlowEndpoint,
    ReconstructionFacts,
    StreamDirection,
    classify_reconstruction,
)
from securemail.domain.evidence.run import CapturePreflight

ProtoName = Literal["tcp", "udp", "icmp", "icmp6", "unknown"]

_MAX_UID_LEN = 64
_MAX_HOST_LEN = 253
_MAX_HISTORY_LEN = 256
_MAX_CONN_STATE_LEN = 16
_MAX_PROTO_LEN = 16
_MAX_WEIRD_NAME_LEN = 128
_MAX_RECORDS = 10_000
_MAX_EVENTS_PER_FLOW = 256

_PROTO_MAP: dict[str, ProtoName] = {
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "icmp6": "icmp6",
    "ipv6-icmp": "icmp6",
}


def _proto(raw: str | None) -> ProtoName:
    if raw is None:
        return "unknown"
    return _PROTO_MAP.get(raw.lower(), "unknown")


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


def _record_get(record: Mapping[str, object], *keys: str) -> object:
    for key in keys:
        if key in record:
            return record[key]
    nested = _as_mapping(record.get("id"))
    if nested is not None:
        for key in keys:
            short = key.removeprefix("id.")
            if short in nested:
                return nested[short]
    return None


def _bounded_records(rows: object) -> list[Mapping[str, object]]:
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        return []
    out: list[Mapping[str, object]] = []
    for item in rows[:_MAX_RECORDS]:
        mapping = _as_mapping(item)
        if mapping is not None:
            out.append(mapping)
    return out


def _direction(is_orig: bool | None) -> StreamDirection:
    return StreamDirection.ORIG if is_orig is not False else StreamDirection.RESP


def _byte_range(
    *,
    start: int | None,
    end: int | None,
    length: int | None,
    is_orig: bool | None,
    exact: bool,
) -> ByteRange | None:
    resolved_start = start if start is not None else 0
    if end is not None:
        resolved_end = end
    elif length is not None:
        resolved_end = resolved_start + length
    else:
        return None
    if resolved_end < resolved_start:
        return None
    return ByteRange(
        start=resolved_start,
        end=resolved_end,
        direction=_direction(is_orig),
        exact=exact and start is not None,
    )


def normalize_flows(
    logs: Mapping[str, list[dict[str, object]]],
    preflight: CapturePreflight,
) -> list[Flow]:
    """Join conn/weird/capture_loss/sm_tcp_recon facts and classify each flow."""

    conn_rows = _bounded_records(logs.get("conn.log", []))
    weird_rows = _bounded_records(logs.get("weird.log", []))
    loss_rows = _bounded_records(logs.get("capture_loss.log", []))
    recon_rows = _bounded_records(logs.get("sm_tcp_recon.log", []))

    capture_loss_gaps = 0
    for row in loss_rows:
        gaps = _as_int(row.get("gaps"))
        if gaps is not None:
            capture_loss_gaps += gaps

    weird_by_uid: dict[str, list[str]] = defaultdict(list)
    for row in weird_rows:
        uid = _as_str(row.get("uid"), max_len=_MAX_UID_LEN)
        name = _as_str(row.get("name"), max_len=_MAX_WEIRD_NAME_LEN)
        if uid is None or name is None:
            continue
        if len(weird_by_uid[uid]) < _MAX_EVENTS_PER_FLOW:
            weird_by_uid[uid].append(name)

    recon_by_uid: dict[str, list[Mapping[str, object]]] = defaultdict(list)
    for row in recon_rows:
        uid = _as_str(row.get("uid"), max_len=_MAX_UID_LEN)
        if uid is None:
            continue
        if len(recon_by_uid[uid]) < _MAX_EVENTS_PER_FLOW:
            recon_by_uid[uid].append(row)

    flows: list[Flow] = []
    for row in conn_rows:
        uid = _as_str(row.get("uid"), max_len=_MAX_UID_LEN)
        orig_h = _as_str(_record_get(row, "id.orig_h"), max_len=_MAX_HOST_LEN)
        resp_h = _as_str(_record_get(row, "id.resp_h"), max_len=_MAX_HOST_LEN)
        orig_p = _as_int(_record_get(row, "id.orig_p"))
        resp_p = _as_int(_record_get(row, "id.resp_p"))
        proto_raw = _as_str(row.get("proto"), max_len=_MAX_PROTO_LEN)
        if uid is None or orig_h is None or resp_h is None or orig_p is None or resp_p is None:
            continue
        if orig_p > 65535 or resp_p > 65535:
            continue
        proto = _proto(proto_raw)
        history = _as_str(row.get("history"), max_len=_MAX_HISTORY_LEN) or ""
        conn_state = _as_str(row.get("conn_state"), max_len=_MAX_CONN_STATE_LEN) or ""
        missed = _as_int(row.get("missed_bytes")) or 0
        orig_bytes = _as_int(row.get("orig_bytes")) or 0
        resp_bytes = _as_int(row.get("resp_bytes")) or 0

        gap_ranges: list[ByteRange] = []
        overlap_ranges: list[ByteRange] = []
        rexmit_ranges: list[ByteRange] = []
        retransmission_count = 0
        out_of_order = False
        duplicate_segments = False
        inconsistency = False
        pending_conflict_len: int | None = None
        for event in recon_by_uid.get(uid, []):
            event_type = _as_str(event.get("event_type"), max_len=_MAX_WEIRD_NAME_LEN) or ""
            is_orig = _as_bool(event.get("is_orig"))
            seq = _as_int(event.get("seq"))
            length = _as_int(event.get("len"))
            range_start = _as_int(event.get("range_start"))
            range_end = _as_int(event.get("range_end"))
            if event_type == "seq_gap":
                item = _byte_range(
                    start=range_start if range_start is not None else seq,
                    end=range_end,
                    length=length,
                    is_orig=is_orig,
                    exact=True,
                )
                if item is not None:
                    gap_ranges.append(item)
            elif event_type == "out_of_order":
                out_of_order = True
            elif event_type == "duplicate":
                duplicate_segments = True
            elif event_type == "overlap":
                item = _byte_range(
                    start=range_start if range_start is not None else seq,
                    end=range_end,
                    length=length,
                    is_orig=is_orig,
                    exact=seq is not None or range_start is not None,
                )
                if item is not None:
                    overlap_ranges.append(item)
            elif event_type == "rexmit":
                retransmission_count += 1
                item = _byte_range(
                    start=range_start if range_start is not None else seq,
                    end=range_end,
                    length=length,
                    is_orig=is_orig,
                    exact=seq is not None,
                )
                if item is not None:
                    rexmit_ranges.append(item)
            elif event_type == "rexmit_inconsistency":
                inconsistency = True
                pending_conflict_len = length

        conflicting_ranges: list[ByteRange] = []
        if inconsistency:
            if overlap_ranges:
                conflicting_ranges = overlap_ranges
            elif rexmit_ranges:
                conflicting_ranges = rexmit_ranges
            elif pending_conflict_len is not None:
                item = _byte_range(
                    start=0,
                    end=pending_conflict_len,
                    length=pending_conflict_len,
                    is_orig=True,
                    exact=False,
                )
                if item is not None:
                    conflicting_ranges.append(item)

        facts = ReconstructionFacts(
            proto=proto,
            history=history,
            conn_state=conn_state,
            missed_bytes=missed,
            orig_bytes=orig_bytes,
            resp_bytes=resp_bytes,
            weird_names=tuple(weird_by_uid.get(uid, ())),
            capture_loss_gaps=capture_loss_gaps,
            truncated_packets=preflight.truncated_packets_present,
            gap_ranges=tuple(gap_ranges),
            conflicting_ranges=tuple(conflicting_ranges),
            retransmission_count=retransmission_count,
            out_of_order=out_of_order,
            duplicate_segments=duplicate_segments,
        )
        verdict = classify_reconstruction(facts)
        flows.append(
            Flow(
                uid=uid,
                orig=FlowEndpoint(host=orig_h, port=orig_p),
                resp=FlowEndpoint(host=resp_h, port=resp_p),
                proto=proto,
                history=history,
                conn_state=conn_state,
                missed_bytes=missed,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                reconstruction_quality=verdict.reconstruction_quality,
                reason_code=verdict.reason_code,
                observed_conditions=verdict.observed_conditions,
                gap_bytes=verdict.gap_bytes,
                gap_bytes_exact=verdict.gap_bytes_exact,
                conflicting_byte_ranges=verdict.conflicting_byte_ranges,
                evidence_state=verdict.evidence_state,
            )
        )

    flows.sort(
        key=lambda flow: (
            flow.proto,
            flow.orig.host,
            flow.orig.port,
            flow.resp.host,
            flow.resp.port,
            flow.uid,
        )
    )
    return flows
