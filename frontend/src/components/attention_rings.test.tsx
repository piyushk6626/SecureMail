import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { make_report } from "../test/report_fixture";
import { AttentionRings } from "./attention_rings";

describe("AttentionRings", () => {
  it("renders inverse-filled rings with four exact-value metric chips", () => {
    render(<AttentionRings report={make_report()} />);

    expect(screen.getByRole("img", { name: /inverse-filled rings begin at twelve o’clock/i })).toBeInTheDocument();
    expect(document.querySelectorAll(".attention-metric-chip")).toHaveLength(4);
    const inverse_ring = document.querySelector(".attention-ring[data-inverted-share='0.6667']");
    expect(inverse_ring).toHaveClass("attention-ring-inverse");
    expect(inverse_ring).toHaveAttribute("stroke-dashoffset", "0");
    expect(document.querySelector("[data-attention-share='0.3333']")).toBeInTheDocument();
    expect(screen.getAllByText("1 / 3")).toHaveLength(2);
  });
});
