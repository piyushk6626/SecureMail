import { describe, expect, it } from "vitest";
import { render_forensic_text, render_forensic_value } from "./forensic_text";

describe("render_forensic_text", () => {
  it("makes control and bidi characters visible", () => {
    expect(render_forensic_text("mail\u0000\u0007\u202e.example")).toBe(
      "mail⟦U+0000 NULL⟧⟦U+0007 BELL⟧⟦U+202E RIGHT-TO-LEFT OVERRIDE⟧.example",
    );
  });

  it("keeps hostile markup as inert text", () => {
    expect(render_forensic_value("<script>alert(1)</script>")).toBe(
      "<script>alert(1)</script>",
    );
  });
});
