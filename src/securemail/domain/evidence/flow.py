"""TCP/IP flow evidence and pure reconstruction-quality classification (Step 1)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from securemail.domain.evidence.run import EvidenceState


class ReconstructionQuality(StrEnum):
    """Stream-reconstruction outcome. Distinct from `EvidenceState`."""

    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    CONFLICTING = "conflicting"


class ReconstructionReasonCode(StrEnum):
    """Machine-readable primary reason when quality is not complete."""

    MISSING_SYN = "missing_syn"
    MISSING_FIN = "missing_fin"
    MIDSTREAM_START = "midstream_start"
    SNAPLEN_TRUNCATION = "snaplen_truncation"
    OVERLAPPING_RETRANSMISSION_CONFLICT = "overlapping_retransmission_conflict"
    SEGMENT_GAP = "segment_gap"
    CAPTURE_LOSS = "capture_loss"


class ObservedCondition(StrEnum):
    """Recoverable transport facts that do not by themselves degrade quality."""

    OUT_OF_ORDER_SEGMENTS = "out_of_order_segments"
    DUPLICATE_SEGMENTS = "duplicate_segments"


class StreamDirection(StrEnum):
    ORIG = "orig"
    RESP = "resp"


class ByteRange(BaseModel):
    """Half-open `[start, end)` range in relative TCP sequence space."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    start: int = Field(ge=0)
    end: int = Field(ge=0)
    direction: StreamDirection
    exact: bool = True


class FlowEndpoint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str
    port: int = Field(ge=0, le=65535)


class ReconstructionVerdict(BaseModel):
    """Result of `classify_reconstruction`. Flattened onto `Flow` in JSON."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    reconstruction_quality: ReconstructionQuality
    reason_code: ReconstructionReasonCode | None
    observed_conditions: list[ObservedCondition]
    gap_bytes: int = Field(ge=0)
    gap_bytes_exact: bool
    conflicting_byte_ranges: list[ByteRange]
    evidence_state: EvidenceState


class Flow(BaseModel):
    """Canonical per-connection evidence derived from Zeek `conn.log` plus recon facts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    uid: str
    orig: FlowEndpoint
    resp: FlowEndpoint
    proto: Literal["tcp", "udp", "icmp", "icmp6", "unknown"]
    history: str
    conn_state: str
    missed_bytes: int = Field(ge=0)
    orig_bytes: int = Field(ge=0)
    resp_bytes: int = Field(ge=0)
    reconstruction_quality: ReconstructionQuality
    reason_code: ReconstructionReasonCode | None = None
    observed_conditions: list[ObservedCondition] = Field(default_factory=list)
    gap_bytes: int = Field(ge=0)
    gap_bytes_exact: bool = True
    conflicting_byte_ranges: list[ByteRange] = Field(default_factory=list)
    evidence_state: EvidenceState


@dataclass(frozen=True)
class ReconstructionFacts:
    """Typed analyzer facts. Normalizers build this; the classifier stays pure."""

    proto: str
    history: str
    conn_state: str
    missed_bytes: int
    orig_bytes: int
    resp_bytes: int
    weird_names: tuple[str, ...]
    capture_loss_gaps: int
    truncated_packets: bool
    gap_ranges: tuple[ByteRange, ...]
    conflicting_ranges: tuple[ByteRange, ...]
    retransmission_count: int
    out_of_order: bool
    duplicate_segments: bool


_QUALITY_TO_STATE = {
    ReconstructionQuality.COMPLETE: EvidenceState.OBSERVED,
    ReconstructionQuality.INCOMPLETE: EvidenceState.INCOMPLETE,
    ReconstructionQuality.CONFLICTING: EvidenceState.CONFLICTING,
}


def _has_orig_syn(history: str) -> bool:
    return "S" in history


def _has_resp_synack(history: str) -> bool:
    return "h" in history


def _has_fin(history: str) -> bool:
    return "F" in history or "f" in history


def _has_rst(history: str) -> bool:
    return "R" in history or "r" in history


def _has_data(history: str) -> bool:
    return "D" in history or "d" in history


def _range_bytes(ranges: tuple[ByteRange, ...] | list[ByteRange]) -> int:
    total = 0
    for item in ranges:
        if item.end >= item.start:
            total += item.end - item.start
    return total


def _gap_at_stream_start(gap_ranges: tuple[ByteRange, ...]) -> bool:
    return any(item.start <= 1 for item in gap_ranges)


def _observed_conditions(
    facts: ReconstructionFacts, *, conflicting: bool
) -> list[ObservedCondition]:
    conditions: list[ObservedCondition] = []
    if facts.out_of_order:
        conditions.append(ObservedCondition.OUT_OF_ORDER_SEGMENTS)
    has_duplicate = facts.duplicate_segments or facts.retransmission_count > 0
    if has_duplicate and not conflicting:
        conditions.append(ObservedCondition.DUPLICATE_SEGMENTS)
    return conditions


def _verdict(
    quality: ReconstructionQuality,
    reason: ReconstructionReasonCode | None,
    facts: ReconstructionFacts,
    *,
    gap_bytes: int,
    gap_bytes_exact: bool,
    conflicting_ranges: list[ByteRange] | None = None,
) -> ReconstructionVerdict:
    conflicting = quality is ReconstructionQuality.CONFLICTING
    return ReconstructionVerdict(
        reconstruction_quality=quality,
        reason_code=reason,
        observed_conditions=_observed_conditions(facts, conflicting=conflicting),
        gap_bytes=gap_bytes,
        gap_bytes_exact=gap_bytes_exact,
        conflicting_byte_ranges=list(conflicting_ranges or []),
        evidence_state=_QUALITY_TO_STATE[quality],
    )


def classify_reconstruction(facts: ReconstructionFacts) -> ReconstructionVerdict:
    """Map typed recon facts to quality, reason, ranges, and evidence state.

    Precedence: conflicting overlap; snaplen truncation; capture loss;
    unresolved sequence gaps; missing stream boundaries; otherwise complete.
    Recoverable reordering and identical retransmission are recorded in
    `observed_conditions` and do not degrade quality.
    """

    if facts.proto != "tcp":
        if facts.truncated_packets:
            return _verdict(
                ReconstructionQuality.INCOMPLETE,
                ReconstructionReasonCode.SNAPLEN_TRUNCATION,
                facts,
                gap_bytes=0,
                gap_bytes_exact=False,
            )
        return _verdict(
            ReconstructionQuality.COMPLETE,
            None,
            facts,
            gap_bytes=0,
            gap_bytes_exact=True,
        )

    if facts.conflicting_ranges:
        return _verdict(
            ReconstructionQuality.CONFLICTING,
            ReconstructionReasonCode.OVERLAPPING_RETRANSMISSION_CONFLICT,
            facts,
            gap_bytes=0,
            gap_bytes_exact=True,
            conflicting_ranges=list(facts.conflicting_ranges),
        )

    if facts.truncated_packets:
        gap = facts.missed_bytes if facts.missed_bytes > 0 else _range_bytes(facts.gap_ranges)
        return _verdict(
            ReconstructionQuality.INCOMPLETE,
            ReconstructionReasonCode.SNAPLEN_TRUNCATION,
            facts,
            gap_bytes=gap,
            gap_bytes_exact=gap > 0,
        )

    unresolved_gap = facts.missed_bytes > 0 or bool(facts.gap_ranges)
    if unresolved_gap:
        gap = facts.missed_bytes if facts.missed_bytes > 0 else _range_bytes(facts.gap_ranges)
        exact = facts.missed_bytes > 0 or (
            bool(facts.gap_ranges) and all(item.exact for item in facts.gap_ranges)
        )
        no_syn = not _has_orig_syn(facts.history)
        if no_syn or _gap_at_stream_start(facts.gap_ranges):
            reason = ReconstructionReasonCode.MIDSTREAM_START
        else:
            reason = ReconstructionReasonCode.SEGMENT_GAP
        return _verdict(
            ReconstructionQuality.INCOMPLETE,
            reason,
            facts,
            gap_bytes=gap,
            gap_bytes_exact=exact,
        )

    if facts.capture_loss_gaps > 0:
        return _verdict(
            ReconstructionQuality.INCOMPLETE,
            ReconstructionReasonCode.CAPTURE_LOSS,
            facts,
            gap_bytes=0,
            gap_bytes_exact=False,
        )

    if not _has_orig_syn(facts.history):
        return _verdict(
            ReconstructionQuality.INCOMPLETE,
            ReconstructionReasonCode.MISSING_SYN,
            facts,
            gap_bytes=0,
            gap_bytes_exact=True,
        )

    handshake = _has_resp_synack(facts.history) or _has_data(facts.history)
    established = handshake or "A" in facts.history
    if established and not _has_fin(facts.history) and not _has_rst(facts.history):
        return _verdict(
            ReconstructionQuality.INCOMPLETE,
            ReconstructionReasonCode.MISSING_FIN,
            facts,
            gap_bytes=0,
            gap_bytes_exact=True,
        )

    return _verdict(
        ReconstructionQuality.COMPLETE,
        None,
        facts,
        gap_bytes=0,
        gap_bytes_exact=True,
    )


def _rebuild_evidence_document() -> None:
    """Resolve forward references on `EvidenceDocument` without a cycle."""

    from securemail.domain.evidence.certificate import CertificateEvidence
    from securemail.domain.evidence.handshake import TlsHandshake
    from securemail.domain.evidence.run import EvidenceDocument
    from securemail.domain.evidence.session import EmailSession
    from securemail.domain.findings.finding import Finding
    from securemail.domain.findings.posture import PolicyCheck, PostureAssessment

    EvidenceDocument.model_rebuild(
        _types_namespace={
            "Flow": Flow,
            "EmailSession": EmailSession,
            "TlsHandshake": TlsHandshake,
            "CertificateEvidence": CertificateEvidence,
            "Finding": Finding,
            "PolicyCheck": PolicyCheck,
            "PostureAssessment": PostureAssessment,
        }
    )


_rebuild_evidence_document()
