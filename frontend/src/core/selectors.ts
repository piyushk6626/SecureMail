import type {
  CanonicalReport,
  EvidenceState,
  FindingSeverity,
} from "./model";
import { severity_order } from "./model";
import type {
  CoverageCounts,
  ScoredEndpointFinding,
} from "../types/canonical_report.generated";

export interface FindingFilters {
  search: string;
  severities: FindingSeverity[];
  protocols: string[];
  evidence_states: EvidenceState[];
}

export interface FindingRow extends ScoredEndpointFinding {
  protocol: string;
}

export function select_findings(report: CanonicalReport): FindingRow[] {
  const checks = report.evidence.policy_checks ?? [];
  return (report.evidence.posture.prioritized_findings ?? []).map((finding) => {
    const reference_keys = new Set(finding.evidence_references?.map((item) => item.record_key));
    const protocol =
      checks.find(
        (check) =>
          reference_keys.has(check.record_key) ||
          check.affected_endpoint === finding.affected_endpoint,
      )?.protocol ?? "unclassified";
    return { ...finding, protocol };
  });
}

export function filter_findings(input: {
  rows: FindingRow[];
  filters: FindingFilters;
}): FindingRow[] {
  const normalized_search = input.filters.search.trim().toLocaleLowerCase();
  return input.rows
    .filter((row) => {
      if (
        input.filters.severities.length > 0 &&
        !input.filters.severities.includes(row.severity)
      )
        return false;
      if (input.filters.protocols.length > 0 && !input.filters.protocols.includes(row.protocol))
        return false;
      if (
        input.filters.evidence_states.length > 0 &&
        !input.filters.evidence_states.includes(row.basis_state)
      )
        return false;
      if (!normalized_search) return true;
      return [row.title, row.code, row.affected_endpoint, row.rationale, row.protocol]
        .join(" ")
        .toLocaleLowerCase()
        .includes(normalized_search);
    })
    .sort(
      (left, right) =>
        right.score - left.score ||
        severity_order[right.severity] - severity_order[left.severity] ||
        left.title.localeCompare(right.title),
    );
}

export function select_severity_counts(
  report: CanonicalReport,
): Record<FindingSeverity, number> {
  const initial: Record<FindingSeverity, number> = {
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  };
  return select_findings(report).reduce((counts, finding) => {
    counts[finding.severity] += 1;
    return counts;
  }, initial);
}

export function select_coverage(report: CanonicalReport): CoverageCounts {
  return report.evidence.posture.coverage.overall;
}

export function select_protocols(report: CanonicalReport): string[] {
  return Array.from(new Set(select_findings(report).map((finding) => finding.protocol))).sort();
}

export function coverage_percent(input: CoverageCounts): number | null {
  if (input.applicable_count === 0) return null;
  return Math.round((input.passed_count / input.applicable_count) * 100);
}

export function select_protocol_counts(report: CanonicalReport): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const session of report.evidence.sessions ?? []) {
    const protocol = session.protocol ?? "unclassified";
    counts[protocol] = (counts[protocol] ?? 0) + 1;
  }
  return counts;
}

export function select_tls_versions(report: CanonicalReport): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const handshake of report.evidence.handshakes ?? []) {
    const version = handshake.version.selected ?? "not_observable";
    counts[version] = (counts[version] ?? 0) + 1;
  }
  return counts;
}

export function select_starttls_states(report: CanonicalReport): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const session of report.evidence.sessions ?? []) {
    const state = session.explicit_upgrade?.state ?? "none";
    counts[state] = (counts[state] ?? 0) + 1;
  }
  return counts;
}

export function select_certificate_posture(report: CanonicalReport): {
  observed: number;
  valid_at_capture: number;
  expired_at_capture: number;
  identity_match: number;
  identity_mismatch: number;
  not_observable_handshakes: number;
} {
  const certificates = report.evidence.certificates ?? [];
  const handshakes = report.evidence.handshakes ?? [];
  return {
    observed: certificates.length,
    valid_at_capture: certificates.filter((item) => item.valid_at_capture_time === true).length,
    expired_at_capture: certificates.filter((item) => item.valid_at_capture_time === false).length,
    identity_match: certificates.filter((item) => item.validation?.identity_match === true).length,
    identity_mismatch: certificates.filter((item) => item.validation?.identity_match === false)
      .length,
    not_observable_handshakes: handshakes.filter(
      (item) => item.server_certificate_state === "not_observable",
    ).length,
  };
}
