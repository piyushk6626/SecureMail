"""Hand-authored Step 8 synthetic finding sets (no PCAP)."""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from tests.support.findings import check, finding  # noqa: E402

from securemail.application.run_analysis import ScoreRequest, score_findings  # noqa: E402
from securemail.domain.evidence.run import EvidenceState  # noqa: E402
from securemail.domain.findings.finding import FindingOutcome, FindingSeverity  # noqa: E402
from securemail.domain.findings.posture import (  # noqa: E402
    CheckCategory,
    CoverageProtocol,
    PolicyCheckOutcome,
)
from securemail.domain.findings.scoring import (  # noqa: E402
    AssetContext,
    AssetCriticality,
    BlastRadius,
    ExposureClass,
)

OUT = Path(__file__).resolve().parents[1] / "synthetic_findings"


def _dump(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(
            payload if isinstance(payload, dict) else payload.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


def mixed_severity() -> ScoreRequest:
    return ScoreRequest(
        findings=[
            finding(
                1,
                code="TLS_NEGOTIATED_TLS10",
                severity=FindingSeverity.HIGH,
                basis_state=EvidenceState.VERIFIED,
                endpoint="192.0.2.10:25",
            ),
            finding(
                2,
                code="TLS_CIPHER_CBC",
                severity=FindingSeverity.HIGH,
                basis_state=EvidenceState.INFERRED,
                endpoint="192.0.2.11:993",
            ),
            finding(
                3,
                code="CERT_EXPIRED_AT_CAPTURE",
                severity=FindingSeverity.MEDIUM,
                basis_state=EvidenceState.OBSERVED,
                endpoint="192.0.2.12:587",
            ),
            finding(
                4,
                code="MAIL_ACCESS_CLEARTEXT",
                severity=FindingSeverity.LOW,
                basis_state=EvidenceState.INFERRED,
                endpoint="192.0.2.13:143",
            ),
            finding(
                5,
                code="TLS_FORWARD_SECRECY_INDETERMINATE",
                severity=FindingSeverity.INFORMATIONAL,
                basis_state=EvidenceState.INDETERMINATE,
                endpoint="192.0.2.14:4433",
                outcome=FindingOutcome.INDETERMINATE,
            ),
        ],
        policy_checks=[
            check(
                11,
                code="TLS_NEGOTIATED_TLS10",
                category=CheckCategory.TLS_HANDSHAKE,
                protocol=CoverageProtocol.SMTP,
                endpoint="192.0.2.10:25",
                record_key="C1",
                outcome=PolicyCheckOutcome.FAIL,
                evidence_state=EvidenceState.VERIFIED,
            ),
            check(
                12,
                code="TLS_NEGOTIATED_SSL3",
                category=CheckCategory.TLS_HANDSHAKE,
                protocol=CoverageProtocol.SMTP,
                endpoint="192.0.2.10:25",
                record_key="C1",
                outcome=PolicyCheckOutcome.PASS,
                evidence_state=EvidenceState.OBSERVED,
            ),
        ],
        asset_context=[
            AssetContext(
                endpoint="192.0.2.10:25",
                exposure=ExposureClass.PUBLIC,
                asset_criticality=AssetCriticality.CRITICAL,
                blast_radius=BlastRadius.ORGANIZATION,
            ),
            AssetContext(
                endpoint="192.0.2.11:993",
                exposure=ExposureClass.ISOLATED,
                asset_criticality=AssetCriticality.LOW,
                blast_radius=BlastRadius.SINGLE_ENDPOINT,
            ),
            AssetContext(
                endpoint="192.0.2.12:587",
                exposure=ExposureClass.PARTNER,
                asset_criticality=AssetCriticality.HIGH,
                blast_radius=BlastRadius.MULTI_ASSET,
            ),
            AssetContext(
                endpoint="192.0.2.13:143",
                exposure=ExposureClass.INTERNAL,
                asset_criticality=AssetCriticality.MEDIUM,
                blast_radius=BlastRadius.SINGLE_ENDPOINT,
            ),
        ],
    )


def many_low_severity_one_endpoint() -> ScoreRequest:
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
    members.append(
        finding(
            5,
            code="IMAP_LOGIN_WITHOUT_TLS",
            severity=FindingSeverity.LOW,
            basis_state=EvidenceState.OBSERVED,
            endpoint="192.0.2.25:143",
            record_key="C5",
        )
    )
    return ScoreRequest(findings=members)


def recurring_sessions() -> ScoreRequest:
    members = [
        finding(
            index,
            code="TLS_CIPHER_CBC",
            severity=FindingSeverity.MEDIUM,
            basis_state=EvidenceState.OBSERVED,
            endpoint="192.0.2.25:465",
            record_key=f"C{index}",
            evaluation_time=datetime(2026, index, 1, 12, tzinfo=UTC),
        )
        for index in range(1, 4)
    ]
    return ScoreRequest(
        findings=members,
        asset_context=[
            AssetContext(
                endpoint="192.0.2.25:465",
                exposure=ExposureClass.PUBLIC,
            )
        ],
    )


def coverage_denominators() -> ScoreRequest:
    endpoint = "192.0.2.10:25"
    return ScoreRequest(
        findings=[],
        policy_checks=[
            check(
                1,
                code="TLS_NEGOTIATED_SSL3",
                category=CheckCategory.TLS_HANDSHAKE,
                protocol=CoverageProtocol.SMTP,
                endpoint=endpoint,
                record_key="C1",
                outcome=PolicyCheckOutcome.PASS,
                evidence_state=EvidenceState.OBSERVED,
            ),
            check(
                2,
                code="TLS_NEGOTIATED_TLS10",
                category=CheckCategory.TLS_HANDSHAKE,
                protocol=CoverageProtocol.SMTP,
                endpoint=endpoint,
                record_key="C1",
                outcome=PolicyCheckOutcome.PASS,
                evidence_state=EvidenceState.OBSERVED,
            ),
            check(
                3,
                code="TLS_CIPHER_NULL",
                category=CheckCategory.TLS_HANDSHAKE,
                protocol=CoverageProtocol.SMTP,
                endpoint=endpoint,
                record_key="C1",
                outcome=PolicyCheckOutcome.FAIL,
                evidence_state=EvidenceState.OBSERVED,
            ),
            check(
                4,
                code="TLS_FORWARD_SECRECY_INDETERMINATE",
                category=CheckCategory.TLS_HANDSHAKE,
                protocol=CoverageProtocol.SMTP,
                endpoint=endpoint,
                record_key="C1",
                outcome=PolicyCheckOutcome.UNKNOWN,
                evidence_state=EvidenceState.INDETERMINATE,
            ),
            check(
                5,
                code="TLS_HANDSHAKE_SIGNATURE_SHA1",
                category=CheckCategory.TLS_HANDSHAKE,
                protocol=CoverageProtocol.SMTP,
                endpoint=endpoint,
                record_key="C1",
                outcome=PolicyCheckOutcome.UNKNOWN,
                evidence_state=EvidenceState.INCOMPLETE,
            ),
            check(
                6,
                code="CERT_EXPIRED_AT_CAPTURE",
                category=CheckCategory.CERTIFICATE,
                protocol=CoverageProtocol.IMAP,
                endpoint="192.0.2.11:993",
                record_key="C2",
                outcome=PolicyCheckOutcome.NOT_OBSERVABLE,
                evidence_state=EvidenceState.NOT_OBSERVABLE,
            ),
            check(
                7,
                code="CERT_IDENTITY_MISMATCH",
                category=CheckCategory.CERTIFICATE,
                protocol=CoverageProtocol.IMAP,
                endpoint="192.0.2.11:993",
                record_key="C2",
                outcome=PolicyCheckOutcome.NOT_OBSERVABLE,
                evidence_state=EvidenceState.NOT_OBSERVABLE,
            ),
            check(
                8,
                code="CERT_RSA_KEY_LT2048",
                category=CheckCategory.CERTIFICATE,
                protocol=CoverageProtocol.IMAP,
                endpoint="192.0.2.11:993",
                record_key="C2",
                outcome=PolicyCheckOutcome.UNKNOWN,
                evidence_state=EvidenceState.CONFLICTING,
            ),
            check(
                9,
                code="MAIL_ACCESS_CLEARTEXT",
                category=CheckCategory.MAIL_PROTOCOL,
                protocol=CoverageProtocol.IMAP,
                endpoint="192.0.2.11:993",
                record_key="C2",
                outcome=PolicyCheckOutcome.PASS,
                evidence_state=EvidenceState.OBSERVED,
            ),
        ],
    )


CASES = {
    "mixed_severity": mixed_severity,
    "many_low_severity_one_endpoint": many_low_severity_one_endpoint,
    "recurring_sessions": recurring_sessions,
    "coverage_denominators": coverage_denominators,
}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    expected_cases: dict[str, object] = {}
    hashes: dict[str, str] = {}
    for name, factory in CASES.items():
        request = factory()
        path = OUT / f"{name}.json"
        _dump(path, request)
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        expected_cases[name] = score_findings(request).model_dump(mode="json")
    _dump(OUT / "expected.json", {"cases": expected_cases})
    provenance = {
        "source": "synthetic",
        "generator": "tests/fixtures/generators/step8_synthetic_findings.py",
        "created_at": "2026-09-04T12:00:00Z",
        "scoring_schema_version": "securemail.scoring/v1",
        "posture_schema_version": "securemail.posture/v1",
        "description": (
            "Hand-assembled finding sets for Step 8 scoring, dedup, ordering, "
            "and coverage denominators. No PCAP."
        ),
        "inputs": hashes,
        "expected_sha256": hashlib.sha256((OUT / "expected.json").read_bytes()).hexdigest(),
    }
    _dump(OUT / "provenance.json", provenance)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
