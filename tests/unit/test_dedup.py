"""Session findings sharing a code and endpoint collapse to one endpoint finding."""

from __future__ import annotations

import random

from tests.support.findings import PACK, finding

from securemail.domain.evidence.run import EvidenceState
from securemail.domain.findings.dedup import dedup_findings
from securemail.domain.findings.finding import FindingOutcome, FindingSeverity


def test_same_code_and_endpoint_collapse_to_one() -> None:
    members = [
        finding(
            index,
            code="MAIL_ACCESS_CLEARTEXT",
            severity=FindingSeverity.LOW,
            basis_state=EvidenceState.OBSERVED,
            endpoint="192.0.2.25:143",
            record_key=f"C{index}",
        )
        for index in range(1, 5)
    ]
    clusters = dedup_findings(members)
    assert len(clusters) == 1
    cluster = clusters[0]
    assert cluster.recurrence_count == 4
    assert cluster.unique_occurrences == 4
    assert cluster.contributing_finding_ids == [item.finding_id for item in members]
    assert [item.session_uid for item in cluster.contributing_occurrences] == [
        "C1",
        "C2",
        "C3",
        "C4",
    ]
    assert len(cluster.evidence_references) == 4


def test_different_code_or_endpoint_does_not_collapse() -> None:
    members = [
        finding(
            1,
            code="MAIL_ACCESS_CLEARTEXT",
            severity=FindingSeverity.LOW,
            basis_state=EvidenceState.OBSERVED,
            endpoint="192.0.2.25:143",
        ),
        finding(
            2,
            code="IMAP_LOGIN_WITHOUT_TLS",
            severity=FindingSeverity.LOW,
            basis_state=EvidenceState.OBSERVED,
            endpoint="192.0.2.25:143",
        ),
        finding(
            3,
            code="MAIL_ACCESS_CLEARTEXT",
            severity=FindingSeverity.LOW,
            basis_state=EvidenceState.OBSERVED,
            endpoint="192.0.2.26:143",
        ),
    ]
    clusters = dedup_findings(members)
    assert len(clusters) == 3


def test_mixed_pack_versions_stay_separate() -> None:
    first = finding(
        1,
        code="TLS_CIPHER_CBC",
        severity=FindingSeverity.MEDIUM,
        basis_state=EvidenceState.OBSERVED,
        endpoint="192.0.2.10:25",
    )
    second = first.model_copy(update={"finding_id": "b" * 64, "policy_pack_version": "d" * 64})
    clusters = dedup_findings([first, second])
    assert len(clusters) == 2


def test_negative_outweighs_indeterminate_in_a_group() -> None:
    negative = finding(
        1,
        code="TLS_CIPHER_CBC",
        severity=FindingSeverity.MEDIUM,
        basis_state=EvidenceState.INFERRED,
        endpoint="192.0.2.10:25",
        record_key="Cneg",
    )
    indeterminate = finding(
        2,
        code="TLS_CIPHER_CBC",
        severity=FindingSeverity.INFORMATIONAL,
        basis_state=EvidenceState.VERIFIED,
        endpoint="192.0.2.10:25",
        outcome=FindingOutcome.INDETERMINATE,
        record_key="Cind",
    )
    cluster = dedup_findings([indeterminate, negative])[0]
    assert cluster.outcome is FindingOutcome.NEGATIVE
    assert cluster.severity is FindingSeverity.MEDIUM
    assert cluster.basis_state is EvidenceState.INFERRED
    assert cluster.evaluation_state is EvidenceState.VERIFIED


def test_shuffle_is_byte_equivalent() -> None:
    members = [
        finding(
            index,
            code="MAIL_ACCESS_CLEARTEXT",
            severity=FindingSeverity.LOW,
            basis_state=EvidenceState.OBSERVED,
            endpoint="192.0.2.25:143",
            record_key=f"C{index}",
        )
        for index in range(1, 6)
    ]
    shuffled = list(members)
    random.Random(7).shuffle(shuffled)
    first = [item.model_dump(mode="json") for item in dedup_findings(members)]
    second = [item.model_dump(mode="json") for item in dedup_findings(shuffled)]
    assert first == second
    assert first[0]["policy_pack_version"] == PACK
