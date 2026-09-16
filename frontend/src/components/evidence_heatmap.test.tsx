import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { make_report } from "../test/report_fixture";
import { EvidenceHeatmap } from "./evidence_heatmap";

describe("EvidenceHeatmap", () => {
  it("selects a canonical record, exposes exact links, and opens the existing finding callback", () => {
    const report = make_report();
    const on_open_finding = vi.fn();
    render(<EvidenceHeatmap on_open_finding={on_open_finding} report={report} />);
    const square = document.querySelector<HTMLButtonElement>("#evidence-cell-handshake\\:tls-1");
    if (!square) throw new Error("handshake square missing");
    fireEvent.click(square);
    expect(screen.getByRole("region", { name: "Selected evidence record" })).toHaveTextContent("tls-1");
    expect(screen.getByRole("region", { name: "Selected evidence record" })).toHaveTextContent("Old TLS");
    fireEvent.click(screen.getByRole("button", { name: "Open finding" }));
    expect(on_open_finding).toHaveBeenCalledWith("1".repeat(64));
  });

  it("combines record types into one grouped matrix and explicitly renders more cells per group", () => {
    const report = make_report();
    const first = report.evidence.flows?.[0];
    if (!first) throw new Error("fixture requires a flow");
    report.evidence.flows = Array.from({ length: 106 }, (_, index) => ({ ...first, uid: `flow-${index}` }));
    const { container } = render(<EvidenceHeatmap on_open_finding={() => undefined} report={report} />);
    expect(container.querySelectorAll(".heatmap-groups")).toHaveLength(1);
    expect(container.querySelectorAll(".heatmap-group")).toHaveLength(4);
    expect(container.querySelectorAll(".heatmap-band-scroll")).toHaveLength(0);
    expect(screen.getAllByText("Flows")).toHaveLength(2);
    expect(screen.getAllByText("Mail sessions")).toHaveLength(2);
    expect(screen.getByRole("grid", { name: "Evidence records" })).toHaveTextContent("104/106");
    expect(screen.getByRole("group", { name: "Evidence grid legend" })).toHaveTextContent("Low / informational");
    expect(screen.getByRole("group", { name: "Evidence grid legend" })).toHaveTextContent("High / failed");
    const first_square = container.querySelector<HTMLButtonElement>("#evidence-cell-flow\\:flow-0");
    if (!first_square) throw new Error("first square missing");
    fireEvent.keyDown(first_square, { key: "ArrowRight" });
    expect(container.querySelector<HTMLButtonElement>("#evidence-cell-flow\\:flow-1")).toHaveAttribute("tabindex", "0");
    fireEvent.click(screen.getByRole("button", { name: "Show 2 more" }));
    const matrix = screen.getByRole("grid", { name: "Evidence records" });
    expect(matrix).toHaveTextContent("106/106");
    expect(screen.queryByRole("button", { name: /show .* more/i })).not.toBeInTheDocument();
  });
});
