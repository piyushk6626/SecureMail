"""Builders for Step 8 unit tests and synthetic score requests."""

from __future__ import annotations

from datetime import UTC, date, datetime

from securemail.domain.evidence.run import EvidenceState
from securemail.domain.findings.finding import (
    EvidenceRecordType,
    EvidenceReference,
    Finding,
    FindingOutcome,
    FindingSeverity,
)
from securemail.domain.findings.posture import (
    CheckCategory,
    CoverageProtocol,
    PolicyCheck,
    PolicyCheckOutcome,
)

PACK = "c" * 64
EVAL_TIME = datetime(2026, 9, 4, 12, tzinfo=UTC)


def hex_id(n: int) -> str:
    return f"{n:064x}"


def finding(
    n: int,
    *,
    code: str,
    severity: FindingSeverity,
    basis_state: EvidenceState,
    endpoint: str,
    outcome: FindingOutcome = FindingOutcome.NEGATIVE,
    record_key: str | None = None,
    evaluation_time: datetime | None = None,
) -> Finding:
    key = record_key or f"C{n}"
    evaluation_state = (
        EvidenceState.INDETERMINATE
        if outcome is FindingOutcome.INDETERMINATE
        else EvidenceState.VERIFIED
    )
    return Finding(
        finding_id=hex_id(n),
        code=code,
        outcome=outcome,
        title=code.replace("_", " ").title(),
        rationale="Synthetic Step 8 finding.",
        standards=["RFC 0"],
        remediation_id="rem.synthetic",
        severity=severity,
        evaluation_state=evaluation_state,
        basis_state=basis_state,
        policy_profile="ietf_current",
        policy_pack_version=PACK,
        rule_effective_from=date(2018, 1, 1),
        policy_evaluation_time=evaluation_time or EVAL_TIME,
        affected_endpoint=endpoint,
        evidence_references=[
            EvidenceReference(
                record_type=EvidenceRecordType.SESSION,
                record_key=key,
                field_path="session.protocol",
                evidence_state=basis_state,
            )
        ],
    )


def check(
    n: int,
    *,
    code: str,
    category: CheckCategory,
    protocol: CoverageProtocol,
    endpoint: str,
    record_key: str,
    outcome: PolicyCheckOutcome,
    evidence_state: EvidenceState,
) -> PolicyCheck:
    return PolicyCheck(
        check_id=hex_id(n),
        code=code,
        category=category,
        protocol=protocol,
        affected_endpoint=endpoint,
        record_type=EvidenceRecordType.SESSION
        if category is CheckCategory.MAIL_PROTOCOL
        else EvidenceRecordType.HANDSHAKE
        if category is CheckCategory.TLS_HANDSHAKE
        else EvidenceRecordType.CERTIFICATE
        if category is CheckCategory.CERTIFICATE
        else EvidenceRecordType.FLOW,
        record_key=record_key,
        outcome=outcome,
        evidence_state=evidence_state,
        title=code.replace("_", " ").title(),
    )
