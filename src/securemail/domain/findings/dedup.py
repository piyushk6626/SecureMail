"""Collapse session-level findings that share a code and endpoint."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, Field

from securemail.domain.evidence.run import EvidenceState
from securemail.domain.findings.finding import (
    EvidenceRecordType,
    EvidenceReference,
    Finding,
    FindingOutcome,
    FindingSeverity,
)

_SEVERITY_RANK = {
    FindingSeverity.HIGH: 3,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 1,
    FindingSeverity.INFORMATIONAL: 0,
}
_STATE_RANK = {
    EvidenceState.CONFLICTING: 0,
    EvidenceState.INCOMPLETE: 1,
    EvidenceState.INDETERMINATE: 2,
    EvidenceState.NOT_OBSERVABLE: 3,
    EvidenceState.INFERRED: 4,
    EvidenceState.OBSERVED: 5,
    EvidenceState.VERIFIED: 6,
}
_MAX_CONTRIBUTORS = 4096
_MAX_MERGED_REFS = 1024


class OccurrenceRef(BaseModel):
    """One contributing session-level finding. Evidence is retained, not dropped."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    record_type: EvidenceRecordType
    record_key: str = Field(min_length=1, max_length=160)
    session_uid: str | None = Field(default=None, max_length=160)


class EndpointFindingCluster(BaseModel):
    """Endpoint-level finding before scoring. One cluster per code and endpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    code: str = Field(min_length=1, max_length=64)
    outcome: FindingOutcome
    title: str = Field(min_length=1, max_length=160)
    rationale: str = Field(min_length=1, max_length=1000)
    standards: list[str] = Field(default_factory=list, max_length=8)
    remediation_id: str = Field(min_length=1, max_length=64)
    severity: FindingSeverity
    evaluation_state: EvidenceState
    basis_state: EvidenceState
    policy_profile: str = Field(min_length=1, max_length=64)
    policy_pack_version: str = Field(pattern=r"^[0-9a-f]{64}$")
    rule_effective_from: date
    rule_effective_until: date | None = None
    policy_evaluation_time: datetime
    affected_endpoint: str = Field(min_length=1, max_length=300)
    recurrence_count: int = Field(ge=1, le=_MAX_CONTRIBUTORS)
    unique_occurrences: int = Field(ge=1, le=_MAX_CONTRIBUTORS)
    contributing_finding_ids: list[str] = Field(min_length=1, max_length=_MAX_CONTRIBUTORS)
    contributing_occurrences: list[OccurrenceRef] = Field(
        min_length=1, max_length=_MAX_CONTRIBUTORS
    )
    evidence_references: list[EvidenceReference] = Field(
        default_factory=list, max_length=_MAX_MERGED_REFS
    )


def session_uid_for_finding(finding: Finding) -> str | None:
    for ref in finding.evidence_references:
        if ref.record_type is EvidenceRecordType.SESSION:
            return ref.record_key
    for ref in finding.evidence_references:
        if ref.record_type is EvidenceRecordType.HANDSHAKE:
            return ref.record_key
        if ref.record_type is EvidenceRecordType.FLOW:
            return ref.record_key
        if ref.record_type is EvidenceRecordType.CERTIFICATE:
            return ref.record_key.split(":", 1)[0]
    return None


def _occurrence_key(finding: Finding) -> str:
    if not finding.evidence_references:
        return f"finding:{finding.finding_id}"
    ref = finding.evidence_references[0]
    return f"{ref.record_type.value}:{ref.record_key}"


def _occurrence_ref(finding: Finding) -> OccurrenceRef:
    if finding.evidence_references:
        ref = finding.evidence_references[0]
        record_type = ref.record_type
        record_key = ref.record_key
    else:
        record_type = EvidenceRecordType.SESSION
        record_key = finding.finding_id
    return OccurrenceRef(
        finding_id=finding.finding_id,
        record_type=record_type,
        record_key=record_key,
        session_uid=session_uid_for_finding(finding),
    )


def _group_key(finding: Finding) -> tuple[str, str, str, str]:
    return (
        finding.code,
        finding.affected_endpoint,
        finding.policy_profile,
        finding.policy_pack_version,
    )


def _aggregate_id(members: Sequence[Finding]) -> str:
    first = members[0]
    material = "|".join(
        [
            "endpoint",
            first.code,
            first.affected_endpoint,
            first.policy_profile,
            first.policy_pack_version,
            *sorted(item.finding_id for item in members),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _pick_primary(members: Sequence[Finding]) -> list[Finding]:
    negatives = [item for item in members if item.outcome is FindingOutcome.NEGATIVE]
    return negatives or list(members)


def _max_severity(members: Sequence[Finding]) -> FindingSeverity:
    return max(members, key=lambda item: _SEVERITY_RANK[item.severity]).severity


def _weakest_basis(members: Sequence[Finding]) -> EvidenceState:
    return min(members, key=lambda item: _STATE_RANK[item.basis_state]).basis_state


def _merge_references(members: Sequence[Finding]) -> list[EvidenceReference]:
    unique: dict[tuple[str, str, str, str, int | None], EvidenceReference] = {}
    for finding in members:
        for ref in finding.evidence_references:
            key = (
                ref.record_type.value,
                ref.record_key,
                ref.field_path,
                ref.evidence_state.value,
                ref.frame_number,
            )
            unique.setdefault(key, ref)
    merged = list(unique.values())
    merged.sort(
        key=lambda item: (
            item.record_type.value,
            item.record_key,
            item.field_path,
            item.evidence_state.value,
            item.frame_number or 0,
        )
    )
    return merged[:_MAX_MERGED_REFS]


def _cluster_from_group(members: Sequence[Finding]) -> EndpointFindingCluster:
    ordered = sorted(members, key=lambda item: item.finding_id)
    primary = _pick_primary(ordered)
    representative = min(primary, key=lambda item: item.finding_id)
    outcome = (
        FindingOutcome.NEGATIVE
        if any(item.outcome is FindingOutcome.NEGATIVE for item in ordered)
        else FindingOutcome.INDETERMINATE
    )
    evaluation_state = (
        EvidenceState.VERIFIED
        if outcome is FindingOutcome.NEGATIVE
        else EvidenceState.INDETERMINATE
    )
    occurrence_keys = {_occurrence_key(item) for item in ordered}
    occurrences = sorted(
        (_occurrence_ref(item) for item in ordered),
        key=lambda item: item.finding_id,
    )
    return EndpointFindingCluster(
        finding_id=_aggregate_id(ordered),
        code=representative.code,
        outcome=outcome,
        title=representative.title,
        rationale=representative.rationale,
        standards=list(representative.standards),
        remediation_id=representative.remediation_id,
        severity=_max_severity(primary),
        evaluation_state=evaluation_state,
        basis_state=_weakest_basis(primary),
        policy_profile=representative.policy_profile,
        policy_pack_version=representative.policy_pack_version,
        rule_effective_from=min(item.rule_effective_from for item in ordered),
        rule_effective_until=representative.rule_effective_until,
        policy_evaluation_time=max(item.policy_evaluation_time for item in ordered),
        affected_endpoint=representative.affected_endpoint,
        recurrence_count=len(ordered),
        unique_occurrences=len(occurrence_keys),
        contributing_finding_ids=[item.finding_id for item in ordered],
        contributing_occurrences=occurrences,
        evidence_references=_merge_references(ordered),
    )


def dedup_findings(findings: Sequence[Finding]) -> list[EndpointFindingCluster]:
    """Group by code, endpoint, and policy identity. Input order does not matter."""

    grouped: dict[tuple[str, str, str, str], list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(_group_key(finding), []).append(finding)
    clusters = [_cluster_from_group(members) for members in grouped.values()]
    clusters.sort(
        key=lambda item: (item.code, item.affected_endpoint, item.policy_profile, item.finding_id)
    )
    return clusters
