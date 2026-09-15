import { describe, expect, it } from "vitest";
import { evidence_state_tone, outcome_tone } from "./ui";

describe("ledger state mapping", () => {
  it("keeps not observable distinct from warning and policy pass", () => {
    expect(evidence_state_tone("not_observable")).toBe("not_observable");
    expect(outcome_tone("not_observable")).toBe("not_observable");
    expect(outcome_tone("pass")).toBe("success");
    expect(evidence_state_tone("incomplete")).toBe("unknown");
  });
});
