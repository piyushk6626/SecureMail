import type {
  CanonicalReport,
  EvidenceState,
  FindingSeverity,
} from "./model";
import { severity_order } from "./model";
import type {
  CertificateEvidence,
  CoverageCounts,
  EmailSession,
  FindingOutcome,
  Flow,
  PolicyCheck,
  ScoredEndpointFinding,
  TlsHandshake,
} from "../types/canonical_report.generated";

export const coverage_protocols = ["smtp", "imap", "pop3", "unclassified"] as const;
export const coverage_categories = [
  "transport",
  "mail_protocol",
  "tls_handshake",
  "certificate",
] as const;

export type CoverageProtocolName = (typeof coverage_protocols)[number];
export type CoverageCategoryName = (typeof coverage_categories)[number];
export type FindingGroupMode = "endpoint" | "remediation" | "code" | "protocol";
export type AnalystFocus = "standard" | "incident" | "mail_owner" | "protocol" | "pki" | "historical";
export type SecurityDomain =
  | "Cleartext and credential exposure"
  | "STARTTLS / STLS upgrade integrity"
  | "TLS protocol version"
  | "Cipher suite strength"
  | "Key exchange and forward secrecy"
  | "Handshake signatures"
  | "Certificates"
  | "Other deterministic conclusions";

export interface FindingFilters {
  search: string;
  severities: FindingSeverity[];
  protocols: string[];
  evidence_states: EvidenceState[];
}

export interface FindingRow extends ScoredEndpointFinding {
  protocol: string;
  domain: SecurityDomain;
  remediation_family: string;
}

export interface CoverageCell {
  protocol: CoverageProtocolName;
  category: CoverageCategoryName;
  counts: CoverageCounts;
}

export interface EndpointGroup {
  endpoint: string;
  protocol: string;
  service_role: string;
  session_count: number;
  tls_session_count: number;
  cleartext_session_count: number;
  unresolved_check_count: number;
  findings: FindingRow[];
}

export interface CertificateChain {
  uid: string;
  certificates: CertificateEvidence[];
  handshake: TlsHandshake | null;
}

const zero_coverage: CoverageCounts = {
  applicable_count: 0,
  passed_count: 0,
  failed_count: 0,
  unknown_count: 0,
  not_observable_count: 0,
};

const credential_codes = new Set([
  "IMAP_LOGIN_WITHOUT_TLS",
  "POP3_PASS_WITHOUT_TLS",
  "MAIL_SUBMISSION_CLEARTEXT",
  "MAIL_ACCESS_CLEARTEXT",
]);
const upgrade_codes = new Set([
  "UPGRADE_ACCEPTED_WITHOUT_TLS_TRANSITION",
  "UPGRADE_PLAINTEXT_FALLBACK",
  "MAIL_STARTTLS_PLAINTEXT_FALLBACK",
]);

/**
 * The policy-pack taxonomy is deliberately explicit at this presentation
 * boundary.  New rule IDs fall back to Other deterministic conclusions until
 * this table and its selector test intentionally classify them.
 */
const known_rule_domains: Record<string, SecurityDomain> = {
  IMAP_LOGIN_WITHOUT_TLS: "Cleartext and credential exposure",
  POP3_PASS_WITHOUT_TLS: "Cleartext and credential exposure",
  MAIL_SUBMISSION_CLEARTEXT: "Cleartext and credential exposure",
  MAIL_ACCESS_CLEARTEXT: "Cleartext and credential exposure",
  UPGRADE_ACCEPTED_WITHOUT_TLS_TRANSITION: "STARTTLS / STLS upgrade integrity",
  UPGRADE_PLAINTEXT_FALLBACK: "STARTTLS / STLS upgrade integrity",
  MAIL_STARTTLS_PLAINTEXT_FALLBACK: "STARTTLS / STLS upgrade integrity",
  TLS_NEGOTIATED_SSL3: "TLS protocol version",
  TLS_NEGOTIATED_TLS10: "TLS protocol version",
  TLS_NEGOTIATED_TLS10_DISCOURAGED: "TLS protocol version",
  TLS_NEGOTIATED_TLS11: "TLS protocol version",
  TLS_NEGOTIATED_TLS11_DISCOURAGED: "TLS protocol version",
  TLS_CIPHER_NULL: "Cipher suite strength",
  TLS_CIPHER_EXPORT: "Cipher suite strength",
  TLS_CIPHER_RC4: "Cipher suite strength",
  TLS_CIPHER_3DES: "Cipher suite strength",
  TLS_CIPHER_CBC: "Cipher suite strength",
  NIST_TLS_SUITE_NOT_APPROVED: "Cipher suite strength",
  TLS12_STATIC_RSA_NEGOTIATED: "Key exchange and forward secrecy",
  TLS12_STATIC_RSA_DISCOURAGED: "Key exchange and forward secrecy",
  TLS12_STATIC_DH_NEGOTIATED: "Key exchange and forward secrecy",
  TLS12_DHE_NEGOTIATED: "Key exchange and forward secrecy",
  TLS12_STATIC_ECDH_NEGOTIATED: "Key exchange and forward secrecy",
  TLS12_DHE_PARAMETERS_LT2048: "Key exchange and forward secrecy",
  TLS_FORWARD_SECRECY_ABSENT: "Key exchange and forward secrecy",
  TLS_FORWARD_SECRECY_INDETERMINATE: "Key exchange and forward secrecy",
  TLS_HANDSHAKE_SIGNATURE_MD5: "Handshake signatures",
  TLS_HANDSHAKE_SIGNATURE_SHA1: "Handshake signatures",
  CERT_RSA_KEY_LT2048: "Certificates",
  CERT_PUBLIC_KEY_STRENGTH_LT112: "Certificates",
  CERT_SIGNATURE_MD5: "Certificates",
  CERT_SIGNATURE_SHA1: "Certificates",
  CERT_EXPIRED_AT_CAPTURE: "Certificates",
  CERT_PATH_INVALID_AT_CAPTURE: "Certificates",
  CERT_IDENTITY_MISMATCH: "Certificates",
  CERT_BECAME_INVALID_AFTER_CAPTURE: "Certificates",
};

export const policy_rule_domains: Readonly<Record<string, SecurityDomain>> = known_rule_domains;

function clone_counts(counts: CoverageCounts | undefined): CoverageCounts {
  if (!counts) return { ...zero_coverage };
  return {
    applicable_count: counts.applicable_count,
    passed_count: counts.passed_count,
    failed_count: counts.failed_count,
    unknown_count: counts.unknown_count,
    not_observable_count: counts.not_observable_count,
  };
}

function session_for_uid(report: CanonicalReport, uid: string): EmailSession | null {
  return report.evidence.sessions?.find((item) => item.uid === uid) ?? null;
}

function flow_for_uid(report: CanonicalReport, uid: string): Flow | null {
  return report.evidence.flows?.find((item) => item.uid === uid) ?? null;
}

function handshake_for_uid(report: CanonicalReport, uid: string): TlsHandshake | null {
  return report.evidence.handshakes?.find((item) => item.uid === uid) ?? null;
}

function uid_from_finding(finding: ScoredEndpointFinding): string | null {
  const occurrence_uid = finding.contributing_occurrences.find((item) => item.session_uid)?.session_uid;
  if (occurrence_uid) return occurrence_uid;
  const reference = finding.evidence_references?.find((item) => !item.record_key.includes(":"));
  return reference?.record_key ?? null;
}

function protocol_for_finding(report: CanonicalReport, finding: ScoredEndpointFinding): string {
  const reference_keys = new Set(finding.evidence_references?.map((item) => item.record_key));
  const matching_check = (report.evidence.policy_checks ?? []).find(
    (check) =>
      reference_keys.has(check.record_key) ||
      check.affected_endpoint === finding.affected_endpoint,
  );
  if (matching_check) return matching_check.protocol;
  const uid = uid_from_finding(finding);
  return uid ? session_for_uid(report, uid)?.protocol ?? "unclassified" : "unclassified";
}

export function finding_domain(code: string): SecurityDomain {
  const known = known_rule_domains[code];
  if (known) return known;
  if (credential_codes.has(code)) return "Cleartext and credential exposure";
  if (upgrade_codes.has(code)) return "STARTTLS / STLS upgrade integrity";
  if (code.startsWith("TLS_NEGOTIATED_")) return "TLS protocol version";
  if (code.startsWith("TLS_CIPHER_") || code === "NIST_TLS_SUITE_NOT_APPROVED")
    return "Cipher suite strength";
  if (code.startsWith("TLS_HANDSHAKE_SIGNATURE_")) return "Handshake signatures";
  if (code.startsWith("CERT_")) return "Certificates";
  if (code.startsWith("TLS12_") || code.startsWith("TLS_FORWARD_SECRECY_"))
    return "Key exchange and forward secrecy";
  return "Other deterministic conclusions";
}

export function remediation_family(remediation_id: string): string {
  const prefix = remediation_id.split(".")[0] ?? "other";
  if (prefix === "tls") return "TLS configuration";
  if (prefix === "pki") return "PKI and certificates";
  if (prefix === "mail") return "Mail transport";
  if (prefix === "imap") return "IMAP authentication";
  if (prefix === "pop3") return "POP3 authentication";
  return "Other remediation";
}

export function select_findings(report: CanonicalReport): FindingRow[] {
  return (report.evidence.posture.prioritized_findings ?? []).map((finding) => ({
    ...finding,
    protocol: protocol_for_finding(report, finding),
    domain: finding_domain(finding.code),
    remediation_family: remediation_family(finding.remediation_id),
  }));
}

export function compare_findings(left: FindingRow, right: FindingRow): number {
  const outcome_order: Record<FindingOutcome, number> = { negative: 2, indeterminate: 1 };
  return (
    right.score - left.score ||
    outcome_order[right.outcome] - outcome_order[left.outcome] ||
    severity_order[right.severity] - severity_order[left.severity] ||
    left.code.localeCompare(right.code) ||
    left.affected_endpoint.localeCompare(right.affected_endpoint)
  );
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
      return [
        row.title,
        row.code,
        row.affected_endpoint,
        row.rationale,
        row.protocol,
        row.domain,
        row.remediation_id,
      ]
        .join(" ")
        .toLocaleLowerCase()
        .includes(normalized_search);
    })
    .sort(compare_findings);
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

export function select_coverage_cells(report: CanonicalReport): CoverageCell[] {
  const matrix = report.evidence.posture.coverage.by_protocol_and_category ?? {};
  return coverage_protocols.flatMap((protocol) =>
    coverage_categories.map((category) => ({
      protocol,
      category,
      counts: clone_counts(matrix[protocol]?.[category]),
    })),
  );
}

export function select_policy_checks(
  report: CanonicalReport,
  filter?: Partial<Pick<CoverageCell, "protocol" | "category">>,
): PolicyCheck[] {
  return (report.evidence.policy_checks ?? []).filter(
    (check) =>
      (filter?.protocol === undefined || check.protocol === filter.protocol) &&
      (filter?.category === undefined || check.category === filter.category),
  );
}

export function coverage_percent(input: CoverageCounts): number | null {
  if (input.applicable_count === 0) return null;
  return Math.round((input.passed_count / input.applicable_count) * 100);
}

export function select_protocols(report: CanonicalReport): string[] {
  return Array.from(new Set(select_findings(report).map((finding) => finding.protocol))).sort();
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
    expired_at_capture: certificates.filter((item) => item.valid_at_capture_time === false)
      .length,
    identity_match: certificates.filter((item) => item.validation?.identity_match === true)
      .length,
    identity_mismatch: certificates.filter((item) => item.validation?.identity_match === false)
      .length,
    not_observable_handshakes: handshakes.filter(
      (item) => item.server_certificate_state === "not_observable",
    ).length,
  };
}

export function session_tls_established(report: CanonicalReport, session: EmailSession): boolean {
  if (session.explicit_upgrade?.state === "tls_established") return true;
  return handshake_for_uid(report, session.uid)?.established === true;
}

export function service_role(report: CanonicalReport, uid: string): string {
  const session = session_for_uid(report, uid);
  const flow = flow_for_uid(report, uid);
  if (!session?.protocol || !flow) return "unclassified";
  const port = flow.resp.port;
  if (session.protocol === "smtp" && port === 25) return "smtp_relay";
  if (session.protocol === "smtp" && (port === 465 || port === 587)) return "smtp_submission";
  if (session.protocol === "imap" && (port === 143 || port === 993)) return "imap_access";
  if (session.protocol === "pop3" && (port === 110 || port === 995)) return "pop3_access";
  return "unclassified";
}

export function select_endpoint_groups(report: CanonicalReport): EndpointGroup[] {
  const checks = report.evidence.policy_checks ?? [];
  const groups = new Map<string, EndpointGroup>();
  for (const finding of [...select_findings(report)].sort(compare_findings)) {
    const current = groups.get(finding.affected_endpoint);
    const uid = uid_from_finding(finding);
    const session = uid ? session_for_uid(report, uid) : null;
    if (current) {
      current.findings.push(finding);
      continue;
    }
    const endpoint_checks = checks.filter((check) => check.affected_endpoint === finding.affected_endpoint);
    const endpoint_sessions = (report.evidence.sessions ?? []).filter((candidate) => {
      const candidate_flow = flow_for_uid(report, candidate.uid);
      return candidate_flow ? `${candidate_flow.resp.host}:${candidate_flow.resp.port}` === finding.affected_endpoint : false;
    });
    const sessions = endpoint_sessions.length > 0 ? endpoint_sessions : session ? [session] : [];
    const tls_session_count = sessions.filter((candidate) => session_tls_established(report, candidate)).length;
    groups.set(finding.affected_endpoint, {
      endpoint: finding.affected_endpoint,
      protocol: finding.protocol,
      service_role: uid ? service_role(report, uid) : "unclassified",
      session_count: sessions.length,
      tls_session_count,
      cleartext_session_count: Math.max(0, sessions.length - tls_session_count),
      unresolved_check_count: endpoint_checks.filter(
        (check) => check.outcome === "unknown" || check.outcome === "not_observable",
      ).length,
      findings: [finding],
    });
  }
  return [...groups.values()].sort((left, right) => {
    const left_finding = left.findings[0];
    const right_finding = right.findings[0];
    const finding_comparison =
      left_finding && right_finding ? compare_findings(left_finding, right_finding) : 0;
    return finding_comparison || left.endpoint.localeCompare(right.endpoint);
  });
}

export function group_findings(rows: FindingRow[], mode: FindingGroupMode): Map<string, FindingRow[]> {
  const groups = new Map<string, FindingRow[]>();
  for (const row of [...rows].sort(compare_findings)) {
    const key =
      mode === "endpoint"
        ? row.affected_endpoint
        : mode === "remediation"
          ? row.remediation_family
          : mode === "code"
            ? row.code
            : row.protocol;
    groups.set(key, [...(groups.get(key) ?? []), row]);
  }
  return new Map([...groups.entries()].sort(([left], [right]) => left.localeCompare(right)));
}

export function select_certificate_chains(report: CanonicalReport): CertificateChain[] {
  const by_uid = new Map<string, CertificateEvidence[]>();
  for (const certificate of report.evidence.certificates ?? []) {
    by_uid.set(certificate.uid, [...(by_uid.get(certificate.uid) ?? []), certificate]);
  }
  return [...by_uid.entries()]
    .map(([uid, certificates]) => ({
      uid,
      certificates: [...certificates].sort((left, right) => left.chain_index - right.chain_index),
      handshake: handshake_for_uid(report, uid),
    }))
    .sort((left, right) => left.uid.localeCompare(right.uid));
}

export function focus_matches(finding: FindingRow, focus: AnalystFocus): boolean {
  if (focus === "incident")
    return finding.severity === "high" ||
      finding.domain === "Cleartext and credential exposure" ||
      finding.domain === "TLS protocol version" ||
      finding.domain === "STARTTLS / STLS upgrade integrity";
  if (focus === "pki") return finding.domain === "Certificates";
  return true;
}

export function record_uid_from_reference(record_key: string): string {
  return record_key.split(":")[0] ?? record_key;
}
