import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { make_report } from "../test/report_fixture";
import { CoverageMatrix } from "./coverage_matrix";

describe("CoverageMatrix", () => {
  it("renders the complete matrix and filters the canonical policy-check ledger", () => {
    const report = make_report();
    report.evidence.posture.coverage.by_protocol_and_category = {
      smtp: {
        tls_handshake: {
          applicable_count: 3,
          passed_count: 1,
          failed_count: 1,
          unknown_count: 0,
          not_observable_count: 1,
        },
      },
    };
    render(<CoverageMatrix report={report} />);
    expect(screen.getAllByRole("button", { name: /: .* passed, .* failed,/ })).toHaveLength(16);
    expect(screen.getByRole("img", { name: /Coverage donut: Passed 1, Failed 1/ })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /smtp tls_handshake: 1 passed, 1 failed/ }));
    expect(screen.getByTestId("coverage-ledger")).toHaveTextContent("Old TLS");
    expect(screen.getByTestId("coverage-ledger")).toHaveTextContent("handshake");
  });
});
