"""Coverage denominators and analyst-facing posture aggregation."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer, model_validator

from securemail.domain.evidence.run import EvidenceState
from securemail.domain.findings.dedup import EndpointFindingCluster, OccurrenceRef
from securemail.domain.findings.finding import (
    EvidenceRecordType,
    EvidenceReference,
    FindingOutcome,
    FindingSeverity,
)
from securemail.domain.findings.scoring import (
    SCORING_SCHEMA_VERSION,
    AssetCriticality,
    BlastRadius,
    ExposureClass,
    ScoreComponents,
)

POSTURE_SCHEMA_VERSION: Literal["securemail.posture/v1"] = "securemail.posture/v1"

_OUTCOME_RANK = {
    FindingOutcome.NEGATIVE: 0,
    FindingOutcome.INDETERMINATE: 1,
}
_SEVERITY_ORDER = {
    FindingSeverity.HIGH: 0,
    FindingSeverity.MEDIUM: 1,
    FindingSeverity.LOW: 2,
    FindingSeverity.INFORMATIONAL: 3,
}


class CheckCategory(StrEnum):
    TRANSPORT = "transport"
    MAIL_PROTOCOL = "mail_protocol"
    TLS_HANDSHAKE = "tls_handshake"
    CERTIFICATE = "certificate"


class CoverageProtocol(StrEnum):
    SMTP = "smtp"
    IMAP = "imap"
    POP3 = "pop3"
    UNCLASSIFIED = "unclassified"


class PolicyCheckOutcome(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    NOT_OBSERVABLE = "not_observable"


class AssessmentState(StrEnum):
    COMPLETE = "complete"
    LIMITED = "limited"
    NONE = "none"


class PolicyCheck(BaseModel):
    """One applicable policy evaluation. Genuine non-applicability is omitted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    check_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    code: str = Field(min_length=1, max_length=64)
    category: CheckCategory
    protocol: CoverageProtocol
    affected_endpoint: str = Field(min_length=1, max_length=300)
    record_type: EvidenceRecordType
    record_key: str = Field(min_length=1, max_length=160)
    outcome: PolicyCheckOutcome
    evidence_state: EvidenceState
    title: str = Field(min_length=1, max_length=160)


class CoverageCounts(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    applicable_count: int = Field(ge=0)
    passed_count: int = Field(ge=0)
    failed_count: int = Field(ge=0)
    unknown_count: int = Field(ge=0)
    not_observable_count: int = Field(ge=0)

    @model_validator(mode="after")
    def _reconcile(self) -> CoverageCounts:
        parts = (
            self.passed_count + self.failed_count + self.unknown_count + self.not_observable_count
        )
        if parts != self.applicable_count:
            raise ValueError("coverage counts must sum to applicable_count")
        return self


class CoverageMatrix(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    overall: CoverageCounts
    by_protocol: dict[str, CoverageCounts] = Field(default_factory=dict)
    by_category: dict[str, CoverageCounts] = Field(default_factory=dict)
    by_protocol_and_category: dict[str, dict[str, CoverageCounts]] = Field(default_factory=dict)


class ScoredEndpointFinding(BaseModel):
    """Prioritized endpoint finding with named score components."""

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
    recurrence_count: int = Field(ge=1)
    unique_occurrences: int = Field(ge=1)
    contributing_finding_ids: list[str] = Field(min_length=1, max_length=4096)
    contributing_occurrences: list[OccurrenceRef] = Field(min_length=1, max_length=4096)
    evidence_references: list[EvidenceReference] = Field(default_factory=list, max_length=1024)
    scoring_schema_version: Literal["securemail.scoring/v1"] = SCORING_SCHEMA_VERSION
    score: int = Field(ge=0, le=100)
    components: ScoreComponents
    exposure: ExposureClass
    asset_criticality: AssetCriticality
    blast_radius: BlastRadius

    @field_serializer("rule_effective_from", "rule_effective_until")
    def _serialize_date(self, value: date | None) -> str | None:
        if value is None:
            return None
        return value.isoformat()

    @field_serializer("policy_evaluation_time")
    def _serialize_datetime(self, value: datetime) -> str:
        aware = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        return aware.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


class PostureAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["securemail.posture/v1"] = POSTURE_SCHEMA_VERSION
    scoring_schema_version: Literal["securemail.scoring/v1"] = SCORING_SCHEMA_VERSION
    assessment_state: AssessmentState
    risk_score: int | None = Field(default=None, ge=0, le=100)
    prioritized_findings: list[ScoredEndpointFinding] = Field(default_factory=list, max_length=4096)
    coverage: CoverageMatrix


def scored_from_cluster(
    cluster: EndpointFindingCluster,
    *,
    score: int,
    components: ScoreComponents,
    exposure: ExposureClass,
    asset_criticality: AssetCriticality,
    blast_radius: BlastRadius,
) -> ScoredEndpointFinding:
    return ScoredEndpointFinding(
        finding_id=cluster.finding_id,
        code=cluster.code,
        outcome=cluster.outcome,
        title=cluster.title,
        rationale=cluster.rationale,
        standards=list(cluster.standards),
        remediation_id=cluster.remediation_id,
        severity=cluster.severity,
        evaluation_state=cluster.evaluation_state,
        basis_state=cluster.basis_state,
        policy_profile=cluster.policy_profile,
        policy_pack_version=cluster.policy_pack_version,
        rule_effective_from=cluster.rule_effective_from,
        rule_effective_until=cluster.rule_effective_until,
        policy_evaluation_time=cluster.policy_evaluation_time,
        affected_endpoint=cluster.affected_endpoint,
        recurrence_count=cluster.recurrence_count,
        unique_occurrences=cluster.unique_occurrences,
        contributing_finding_ids=list(cluster.contributing_finding_ids),
        contributing_occurrences=list(cluster.contributing_occurrences),
        evidence_references=list(cluster.evidence_references),
        score=score,
        components=components,
        exposure=exposure,
        asset_criticality=asset_criticality,
        blast_radius=blast_radius,
    )


def prioritize_findings(
    findings: Sequence[ScoredEndpointFinding],
) -> list[ScoredEndpointFinding]:
    return sorted(
        findings,
        key=lambda item: (
            -item.score,
            _OUTCOME_RANK[item.outcome],
            _SEVERITY_ORDER[item.severity],
            item.code,
            item.affected_endpoint,
            item.finding_id,
        ),
    )


def _zero_counts() -> CoverageCounts:
    return CoverageCounts(
        applicable_count=0,
        passed_count=0,
        failed_count=0,
        unknown_count=0,
        not_observable_count=0,
    )


def _increment(counts: CoverageCounts, outcome: PolicyCheckOutcome) -> CoverageCounts:
    passed = counts.passed_count + (1 if outcome is PolicyCheckOutcome.PASS else 0)
    failed = counts.failed_count + (1 if outcome is PolicyCheckOutcome.FAIL else 0)
    unknown = counts.unknown_count + (1 if outcome is PolicyCheckOutcome.UNKNOWN else 0)
    not_observable = counts.not_observable_count + (
        1 if outcome is PolicyCheckOutcome.NOT_OBSERVABLE else 0
    )
    return CoverageCounts(
        applicable_count=counts.applicable_count + 1,
        passed_count=passed,
        failed_count=failed,
        unknown_count=unknown,
        not_observable_count=not_observable,
    )


def aggregate_coverage(checks: Sequence[PolicyCheck]) -> CoverageMatrix:
    overall = _zero_counts()
    by_protocol: dict[str, CoverageCounts] = {}
    by_category: dict[str, CoverageCounts] = {}
    by_cell: dict[str, dict[str, CoverageCounts]] = {}
    for check in checks:
        overall = _increment(overall, check.outcome)
        protocol = check.protocol.value
        category = check.category.value
        by_protocol[protocol] = _increment(by_protocol.get(protocol, _zero_counts()), check.outcome)
        by_category[category] = _increment(by_category.get(category, _zero_counts()), check.outcome)
        row = by_cell.setdefault(protocol, {})
        row[category] = _increment(row.get(category, _zero_counts()), check.outcome)
    return CoverageMatrix(
        overall=overall,
        by_protocol=dict(sorted(by_protocol.items())),
        by_category=dict(sorted(by_category.items())),
        by_protocol_and_category={
            protocol: dict(sorted(categories.items()))
            for protocol, categories in sorted(by_cell.items())
        },
    )


def _assessment_state(coverage: CoverageCounts) -> AssessmentState:
    if coverage.applicable_count == 0:
        return AssessmentState.NONE
    if coverage.unknown_count > 0 or coverage.not_observable_count > 0:
        return AssessmentState.LIMITED
    return AssessmentState.COMPLETE


def _risk_score(state: AssessmentState, findings: Sequence[ScoredEndpointFinding]) -> int | None:
    if findings:
        return max(item.score for item in findings)
    if state is AssessmentState.COMPLETE:
        return 0
    return None


def build_posture(
    findings: Sequence[ScoredEndpointFinding],
    checks: Sequence[PolicyCheck],
) -> PostureAssessment:
    ordered = prioritize_findings(findings)
    coverage = aggregate_coverage(checks)
    state = _assessment_state(coverage.overall)
    return PostureAssessment(
        assessment_state=state,
        risk_score=_risk_score(state, ordered),
        prioritized_findings=ordered,
        coverage=coverage,
    )


def empty_posture_assessment() -> PostureAssessment:
    return build_posture([], [])
