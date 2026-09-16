import { describe, expect, it } from "vitest";
import { make_report } from "../test/report_fixture";
import {
  coverage_percent,
  filter_findings,
  group_findings,
  policy_rule_domains,
  select_coverage,
  select_coverage_cells,
  select_attention_metrics,
  select_evidence_bands,
  select_findings,
} from "./selectors";

function deep_freeze<T>(value: T): T {
  if (typeof value !== "object" || value === null) return value;
  for (const child of Object.values(value)) deep_freeze(child);
  return Object.freeze(value);
}

describe("report selectors", () => {
  it("joins findings to protocol checks and filters by evidence state", () => {
    const rows = select_findings(make_report());
    expect(rows[0]?.protocol).toBe("smtp");
    expect(
      filter_findings({
        rows,
        filters: {
          search: "old tls",
          severities: ["high"],
          protocols: ["smtp"],
          evidence_states: ["verified"],
        },
      }),
    ).toHaveLength(1);
  });

  it("does not count unknown or not-observable checks as passed", () => {
    const coverage = select_coverage(make_report());
    expect(coverage_percent(coverage)).toBe(33);
    expect(coverage.passed_count).toBe(1);
    expect(coverage.not_observable_count).toBe(1);
  });

  it("zero-fills all sixteen coverage cells without turning omitted checks into passes", () => {
    const cells = select_coverage_cells(make_report());
    expect(cells).toHaveLength(16);
    expect(cells.find((cell) => cell.protocol === "smtp" && cell.category === "transport")?.counts).toEqual({
      applicable_count: 0,
      passed_count: 0,
      failed_count: 0,
      unknown_count: 0,
      not_observable_count: 0,
    });
  });

  it("keeps every intentional policy-rule domain mapping and preserves canonical inputs", () => {
    expect(Object.keys(policy_rule_domains)).toEqual(expect.arrayContaining([
      "IMAP_LOGIN_WITHOUT_TLS",
      "TLS_NEGOTIATED_TLS10",
      "TLS_CIPHER_RC4",
      "TLS12_STATIC_RSA_NEGOTIATED",
      "TLS_HANDSHAKE_SIGNATURE_SHA1",
      "CERT_IDENTITY_MISMATCH",
    ]));
    const report = make_report();
    const original = structuredClone(report);
    deep_freeze(report);
    const rows = select_findings(report);
    for (const mode of ["endpoint", "remediation", "code", "protocol"] as const) {
      const ids = [...group_findings(rows, mode).values()].flat().map((finding) => finding.finding_id);
      expect(ids).toEqual(rows.map((finding) => finding.finding_id));
    }
    expect(report).toEqual(original);
  });

  it("projects all four attention ratios from published coverage and same-UID evidence", () => {
    const report = make_report();
    report.evidence.sessions = [{
      uid: "tls-1", protocol: "smtp", payload_evidence: "smtp", port_hint: "smtp",
      evidence_state: "observed", explicit_upgrade: { state: "tls_established", evidence_state: "verified" },
    }, {
      uid: "session-2", protocol: "imap", payload_evidence: "imap", port_hint: "imap",
      evidence_state: "observed", explicit_upgrade: null,
    }];
    const metrics = select_attention_metrics(report);
    expect(metrics.map(({ numerator, denominator }) => [numerator, denominator])).toEqual([
      [1, 3], [1, 3], [1, 2], [1, 1],
    ]);
    report.evidence.posture.coverage.overall.applicable_count = 0;
    expect(select_attention_metrics(report)[0]).toMatchObject({ numerator: 1, denominator: 0 });
  });

  it("keeps report order, exact reference joins, composite certificate keys, and immutable inputs", () => {
    const report = make_report();
    const certificate = report.evidence.certificates?.[0];
    if (!certificate) throw new Error("fixture requires a certificate");
    report.evidence.policy_checks?.push({
      check_id: "c".repeat(64), code: "CERT_TEST", category: "certificate", protocol: "smtp",
      affected_endpoint: "192.0.2.2:25", record_type: "certificate",
      record_key: `tls-1:server:0:${certificate.der_sha256}`, outcome: "pass", evidence_state: "verified", title: "Certificate test",
    });
    report.evidence.posture.prioritized_findings?.[0]?.evidence_references?.push({
      record_type: "certificate", record_key: `tls-1:server:0:${certificate.der_sha256}`,
      field_path: "validation.identity_match", evidence_state: "verified",
    });
    const original = structuredClone(report);
    deep_freeze(report);
    const bands = select_evidence_bands(report);
    expect(bands.map((band) => band.label)).toEqual(["Flows", "Mail sessions", "TLS handshakes", "Certificates"]);
    const cert = bands[3]?.cells[0];
    expect(cert).toMatchObject({ key: `tls-1:server:0:${certificate.der_sha256}`, tone: "danger", marker: "HIGH" });
    expect(cert?.checks).toHaveLength(1);
    expect(cert?.findings).toHaveLength(1);
    expect(report).toEqual(original);
  });

  it("keeps unresolved checks out of pass styling and preserves a failure as the worst result", () => {
    const report = make_report();
    const check = report.evidence.policy_checks?.[0];
    if (!check) throw new Error("fixture requires a policy check");
    report.evidence.posture.prioritized_findings = [];
    check.outcome = "unknown";
    const unknown = select_evidence_bands(report).find((band) => band.type === "handshake")?.cells[0];
    expect(unknown).toMatchObject({ tone: "unknown", marker: "UNKNOWN" });
    check.outcome = "fail";
    check.evidence_state = "incomplete";
    const failed = select_evidence_bands(report).find((band) => band.type === "handshake")?.cells[0];
    expect(failed).toMatchObject({ tone: "danger", marker: "FAILED CHECK", unresolved_states: ["incomplete"] });
  });
});
