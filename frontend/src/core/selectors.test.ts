import { describe, expect, it } from "vitest";
import { make_report } from "../test/report_fixture";
import {
  coverage_percent,
  filter_findings,
  group_findings,
  policy_rule_domains,
  select_coverage,
  select_coverage_cells,
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
});
