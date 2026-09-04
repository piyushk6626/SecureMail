import { describe, expect, it } from "vitest";
import { make_report } from "../test/report_fixture";
import {
  coverage_percent,
  filter_findings,
  select_coverage,
  select_findings,
} from "./selectors";

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
});
