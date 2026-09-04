"""Coverage denominators stay separate from passed checks."""

from __future__ import annotations

from tests.support.findings import check

from securemail.domain.evidence.run import EvidenceState
from securemail.domain.findings.finding import FindingSeverity
from securemail.domain.findings.posture import (
    AssessmentState,
    CheckCategory,
    CoverageProtocol,
    PolicyCheckOutcome,
    ScoredEndpointFinding,
    aggregate_coverage,
    build_posture,
    prioritize_findings,
)
from securemail.domain.findings.scoring import ScoreComponents


def test_coverage_reconciles_and_keeps_unknown_separate() -> None:
    checks = [
        check(
            1,
            code="TLS_NEGOTIATED_TLS10",
            category=CheckCategory.TLS_HANDSHAKE,
            protocol=CoverageProtocol.SMTP,
            endpoint="192.0.2.10:25",
            record_key="C1",
            outcome=PolicyCheckOutcome.PASS,
            evidence_state=EvidenceState.OBSERVED,
        ),
        check(
            2,
            code="TLS_CIPHER_NULL",
            category=CheckCategory.TLS_HANDSHAKE,
            protocol=CoverageProtocol.SMTP,
            endpoint="192.0.2.10:25",
            record_key="C1",
            outcome=PolicyCheckOutcome.FAIL,
            evidence_state=EvidenceState.OBSERVED,
        ),
        check(
            3,
            code="TLS_FORWARD_SECRECY_INDETERMINATE",
            category=CheckCategory.TLS_HANDSHAKE,
            protocol=CoverageProtocol.SMTP,
            endpoint="192.0.2.10:25",
            record_key="C1",
            outcome=PolicyCheckOutcome.UNKNOWN,
            evidence_state=EvidenceState.INDETERMINATE,
        ),
        check(
            4,
            code="CERT_EXPIRED_AT_CAPTURE",
            category=CheckCategory.CERTIFICATE,
            protocol=CoverageProtocol.IMAP,
            endpoint="192.0.2.11:993",
            record_key="C2",
            outcome=PolicyCheckOutcome.NOT_OBSERVABLE,
            evidence_state=EvidenceState.NOT_OBSERVABLE,
        ),
        check(
            5,
            code="CERT_RSA_KEY_LT2048",
            category=CheckCategory.CERTIFICATE,
            protocol=CoverageProtocol.IMAP,
            endpoint="192.0.2.11:993",
            record_key="C2",
            outcome=PolicyCheckOutcome.UNKNOWN,
            evidence_state=EvidenceState.INCOMPLETE,
        ),
    ]
    coverage = aggregate_coverage(checks)
    assert coverage.overall.applicable_count == 5
    assert coverage.overall.passed_count == 1
    assert coverage.overall.failed_count == 1
    assert coverage.overall.unknown_count == 2
    assert coverage.overall.not_observable_count == 1
    assert coverage.overall.passed_count != coverage.overall.applicable_count
    assert coverage.by_protocol["smtp"].unknown_count == 1
    assert coverage.by_protocol["imap"].not_observable_count == 1
    assert coverage.by_category["tls_handshake"].failed_count == 1
    assert coverage.by_category["certificate"].unknown_count == 1
    assert coverage.by_protocol_and_category["imap"]["certificate"].not_observable_count == 1


def test_limited_coverage_without_findings_is_not_zero() -> None:
    checks = [
        check(
            1,
            code="TLS_NEGOTIATED_TLS10",
            category=CheckCategory.TLS_HANDSHAKE,
            protocol=CoverageProtocol.SMTP,
            endpoint="192.0.2.10:25",
            record_key="C1",
            outcome=PolicyCheckOutcome.UNKNOWN,
            evidence_state=EvidenceState.INCOMPLETE,
        ),
        check(
            2,
            code="CERT_IDENTITY_MISMATCH",
            category=CheckCategory.CERTIFICATE,
            protocol=CoverageProtocol.SMTP,
            endpoint="192.0.2.10:25",
            record_key="C1",
            outcome=PolicyCheckOutcome.NOT_OBSERVABLE,
            evidence_state=EvidenceState.NOT_OBSERVABLE,
        ),
    ]
    posture = build_posture([], checks)
    assert posture.assessment_state is AssessmentState.LIMITED
    assert posture.risk_score is None
    assert posture.coverage.overall.unknown_count == 1
    assert posture.coverage.overall.not_observable_count == 1


def test_complete_coverage_without_findings_is_zero() -> None:
    checks = [
        check(
            1,
            code="TLS_NEGOTIATED_TLS10",
            category=CheckCategory.TLS_HANDSHAKE,
            protocol=CoverageProtocol.SMTP,
            endpoint="192.0.2.10:25",
            record_key="C1",
            outcome=PolicyCheckOutcome.PASS,
            evidence_state=EvidenceState.OBSERVED,
        )
    ]
    posture = build_posture([], checks)
    assert posture.assessment_state is AssessmentState.COMPLETE
    assert posture.risk_score == 0


def test_no_checks_is_none() -> None:
    posture = build_posture([], [])
    assert posture.assessment_state is AssessmentState.NONE
    assert posture.risk_score is None


def _scored(
    *,
    finding_id: str,
    code: str,
    score: int,
    severity: FindingSeverity,
    endpoint: str,
) -> ScoredEndpointFinding:
    from datetime import UTC, date, datetime

    from tests.support.findings import PACK

    from securemail.domain.findings.dedup import OccurrenceRef
    from securemail.domain.findings.finding import EvidenceRecordType, FindingOutcome
    from securemail.domain.findings.scoring import AssetCriticality, BlastRadius, ExposureClass

    return ScoredEndpointFinding(
        finding_id=finding_id,
        code=code,
        outcome=FindingOutcome.NEGATIVE,
        title=code,
        rationale="order",
        standards=["RFC 0"],
        remediation_id="rem.synthetic",
        severity=severity,
        evaluation_state=EvidenceState.VERIFIED,
        basis_state=EvidenceState.OBSERVED,
        policy_profile="ietf_current",
        policy_pack_version=PACK,
        rule_effective_from=date(2018, 1, 1),
        policy_evaluation_time=datetime(2026, 9, 4, 12, tzinfo=UTC),
        affected_endpoint=endpoint,
        recurrence_count=1,
        unique_occurrences=1,
        contributing_finding_ids=[finding_id],
        contributing_occurrences=[
            OccurrenceRef(
                finding_id=finding_id,
                record_type=EvidenceRecordType.SESSION,
                record_key="C1",
                session_uid="C1",
            )
        ],
        score=score,
        components=ScoreComponents(
            severity=50 if severity is FindingSeverity.HIGH else 30,
            confidence=16,
            exposure=4,
            recurrence=0,
            asset_criticality=2,
            blast_radius=1,
        ),
        exposure=ExposureClass.UNKNOWN,
        asset_criticality=AssetCriticality.UNKNOWN,
        blast_radius=BlastRadius.UNKNOWN,
    )


def test_priority_orders_by_score_then_code() -> None:
    lower = _scored(
        finding_id="a" * 64,
        code="TLS_CIPHER_CBC",
        score=61,
        severity=FindingSeverity.MEDIUM,
        endpoint="192.0.2.11:25",
    )
    higher = _scored(
        finding_id="b" * 64,
        code="TLS_NEGOTIATED_TLS10",
        score=90,
        severity=FindingSeverity.HIGH,
        endpoint="192.0.2.10:25",
    )
    ordered = prioritize_findings([lower, higher])
    assert [item.code for item in ordered] == ["TLS_NEGOTIATED_TLS10", "TLS_CIPHER_CBC"]
