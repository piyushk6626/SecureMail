"""Build typed Step 11 dashboard reports from the Step 9 golden evidence."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from securemail.adapters.reports.canonical_json import canonicalize, sha256_digest
from securemail.domain.reports.schema import (
    AdvisoryItem,
    AdvisorySection,
    AnalystSection,
    CanonicalReport,
    CaptureLimitations,
    PostureSummary,
    SourceRecord,
    SourceRecordKind,
)

if TYPE_CHECKING:
    from securemail.domain.findings.finding import Finding
    from securemail.domain.findings.posture import PolicyCheck, ScoredEndpointFinding

HERE = Path(__file__).resolve().parent
GOLDEN_REPORT = HERE.parent / "reports" / "golden_report.json"
CATALOG_SCHEMA_VERSION = "securemail.report-catalog/v1"
GENERATED_AT = datetime(2026, 9, 5, 0, 0, tzinfo=UTC)


@dataclass(frozen=True)
class DashboardReportSpec:
    case_id: str
    finding_codes: frozenset[str] | None
    check_codes: frozenset[str] | None
    advisory: AdvisorySection
    analyst_conclusions: AnalystSection


SPECS = (
    DashboardReportSpec(
        case_id="dashboard_critical",
        finding_codes=None,
        check_codes=None,
        advisory=AdvisorySection(
            present=True,
            items=[
                AdvisoryItem(
                    code="ADVISORY_TLS_VERSION_SHIFT",
                    reason=(
                        "TLS 1.0 appears in a cohort otherwise dominated by TLS 1.2 and TLS 1.3."
                    ),
                )
            ],
        ),
        analyst_conclusions=AnalystSection(),
    ),
    DashboardReportSpec(
        case_id="dashboard_attention",
        finding_codes=frozenset(
            {
                "TLS_CIPHER_CBC",
                "MAIL_STARTTLS_PLAINTEXT_FALLBACK",
                "CERT_EXPIRED_AT_CAPTURE",
            }
        ),
        check_codes=frozenset(
            {
                "TLS_CIPHER_CBC",
                "MAIL_STARTTLS_ADVERTISED",
                "TLS_CIPHER_NULL",
            }
        ),
        advisory=AdvisorySection(),
        analyst_conclusions=AnalystSection(
            present=True,
            notes=["Confirm whether the submission endpoint is scheduled for certificate renewal."],
        ),
    ),
    DashboardReportSpec(
        case_id="dashboard_clear",
        finding_codes=frozenset(),
        check_codes=frozenset(
            {
                "TLS_CIPHER_NULL",
                "MAIL_STARTTLS_ADVERTISED",
                "IMPLICIT_TLS_CORRELATED",
            }
        ),
        advisory=AdvisorySection(),
        analyst_conclusions=AnalystSection(
            present=True,
            notes=["Reviewed pass-only policy subset; retain normal monitoring cadence."],
        ),
    ),
)


def _load_base_report() -> CanonicalReport:
    return CanonicalReport.model_validate_json(GOLDEN_REPORT.read_bytes())


def _selected_findings(
    base: CanonicalReport,
    codes: frozenset[str] | None,
) -> tuple[list[Finding], list[ScoredEndpointFinding]]:
    if codes is None:
        return list(base.evidence.findings), list(base.evidence.posture.prioritized_findings)
    findings = [item for item in base.evidence.findings if item.code in codes]
    scored = [item for item in base.evidence.posture.prioritized_findings if item.code in codes]
    return findings, scored


def _selected_checks(
    base: CanonicalReport,
    codes: frozenset[str] | None,
) -> list[PolicyCheck]:
    if codes is None:
        return list(base.evidence.policy_checks)
    return [item for item in base.evidence.policy_checks if item.code in codes]


def build_dashboard_report(
    base: CanonicalReport,
    spec: DashboardReportSpec,
    *,
    generated_at: datetime,
) -> CanonicalReport:
    from securemail.domain.findings.posture import build_posture

    findings, scored = _selected_findings(base, spec.finding_codes)
    checks = _selected_checks(base, spec.check_codes)
    posture = build_posture(scored, checks)
    evidence = base.evidence.model_copy(
        update={"findings": findings, "policy_checks": checks, "posture": posture}
    )
    source_records = [
        SourceRecord(
            kind=record.kind,
            identifier=(
                spec.case_id
                if record.kind is SourceRecordKind.CASE
                else f"{spec.case_id}-run"
                if record.kind is SourceRecordKind.ANALYSIS_RUN
                else record.identifier
            ),
            availability=record.availability,
        )
        for record in base.manifest.source_records
    ]
    manifest = base.manifest.model_copy(
        update={
            "generated_at": generated_at,
            "case_id": spec.case_id,
            "analysis_run_id": f"{spec.case_id}-run",
            "source_records": source_records,
            "posture_summary": PostureSummary(
                assessment_state=posture.assessment_state,
                risk_score=posture.risk_score,
                finding_count=len(posture.prioritized_findings),
                unknown_count=posture.coverage.overall.unknown_count,
                not_observable_count=posture.coverage.overall.not_observable_count,
            ),
        }
    )
    limitations = CaptureLimitations(
        truncated_packets_present=base.limitations.truncated_packets_present,
        incomplete_flow_count=base.limitations.incomplete_flow_count,
        conflicting_flow_count=base.limitations.conflicting_flow_count,
        not_observable_certificate_count=base.limitations.not_observable_certificate_count,
        unknown_check_count=posture.coverage.overall.unknown_count,
        not_observable_check_count=posture.coverage.overall.not_observable_count,
        notes=[
            f"Dashboard fixture {spec.case_id} derived from reports/golden_report.json.",
            "Underlying flow, session, TLS, and certificate evidence is retained.",
        ],
    )
    payload = base.model_copy(
        update={
            "manifest": manifest,
            "evidence": evidence,
            "limitations": limitations,
            "advisory": spec.advisory,
            "analyst_conclusions": spec.analyst_conclusions,
        }
    )
    return CanonicalReport.model_validate(payload.model_dump(mode="json"))


def main() -> None:
    base = _load_base_report()
    reports: list[dict[str, str]] = []
    provenance_reports: list[dict[str, object]] = []
    for index, spec in enumerate(SPECS):
        report = build_dashboard_report(
            base,
            spec,
            generated_at=GENERATED_AT + timedelta(minutes=index),
        )
        filename = f"{spec.case_id}.report.json"
        payload = report.model_dump(mode="json")
        (HERE / filename).write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        reports.append({"case_id": spec.case_id, "report": filename})
        provenance_reports.append(
            {
                "case_id": spec.case_id,
                "canonical_json_sha256": sha256_digest(canonicalize(payload)),
                "risk_score": report.evidence.posture.risk_score,
                "finding_severities": sorted(
                    {item.severity.value for item in report.evidence.posture.prioritized_findings}
                ),
                "advisory_present": report.advisory.present,
                "analyst_conclusions_present": report.analyst_conclusions.present,
            }
        )

    catalog = {"schema_version": CATALOG_SCHEMA_VERSION, "reports": reports}
    (HERE / "catalog.json").write_text(
        json.dumps(catalog, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    provenance = {
        "source": "typed assembly from existing canonical report and earlier evidence",
        "generator": "tests/fixtures/dashboard/assemble.py",
        "created_at": "2026-09-05T00:00:00Z",
        "source_report": "tests/fixtures/reports/golden_report.json",
        "report_schema_version": "securemail.report/v1",
        "reports": provenance_reports,
        "notes": [
            "Reports retain typed flow, session, TLS, certificate, and evidence references.",
            "Subsets vary posture and severity for deterministic dashboard filtering tests.",
        ],
    }
    (HERE / "provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
