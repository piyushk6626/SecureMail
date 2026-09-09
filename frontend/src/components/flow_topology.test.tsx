import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { make_report } from "../test/report_fixture";
import { FlowTopology } from "./flow_topology";

describe("FlowTopology", () => {
  it("highlights the graph path for the hovered list entry", () => {
    const report = make_report();
    const first_flow = report.evidence.flows?.[0];
    if (!first_flow) throw new Error("fixture requires one flow");
    report.evidence.flows = [
      first_flow,
      {
        ...first_flow,
        uid: "flow-2",
        orig: { host: "198.51.100.10", port: 49152 },
        resp: { host: "203.0.113.25", port: 993 },
      },
    ];

    render(<FlowTopology report={report} />);
    const second_flow = screen.getByRole("button", { name: /Flow 2:/ });
    fireEvent.pointerEnter(second_flow);

    expect(second_flow).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("img", { name: /198\.51\.100\.10:49152.*203\.0\.113\.25:993/ })).toBeInTheDocument();
  });
});
