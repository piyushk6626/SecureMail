import { describe, expect, it } from "vitest";
import { make_report } from "../test/report_fixture";
import { resolve_evidence_reference } from "./evidence_resolver";

describe("resolve_evidence_reference", () => {
  it("resolves a nested handshake field and frame", () => {
    const resolved = resolve_evidence_reference({
      report: make_report(),
      reference: {
        record_type: "handshake",
        record_key: "tls-1",
        field_path: "version.selected",
        frame_number: 6,
        evidence_state: "verified",
      },
    });
    expect(resolved.status).toBe("resolved");
    expect(resolved.field_value).toBe("TLSv10");
    expect(resolved.frame_context).toContain("server_hello");
  });

  it("resolves composite certificate keys", () => {
    const report = make_report();
    const certificate = report.evidence.certificates?.at(0);
    if (certificate === undefined) {
      throw new Error("fixture is missing a certificate");
    }
    const resolved = resolve_evidence_reference({
      report,
      reference: {
        record_type: "certificate",
        record_key: `${certificate.uid}:${certificate.role}:${String(certificate.chain_index)}:${certificate.der_sha256}`,
        field_path: "role",
        frame_number: 8,
        evidence_state: "observed",
      },
    });
    expect(resolved.status).toBe("resolved");
    expect(resolved.field_value).toBe("server");
    expect(resolved.frame_context).toContain("Certificate source frame 8");
  });

  it("reports dangling records without throwing", () => {
    const resolved = resolve_evidence_reference({
      report: make_report(),
      reference: {
        record_type: "certificate",
        record_key: "missing:server:0:hash",
        field_path: "subject",
        frame_number: null,
        evidence_state: "not_observable",
      },
    });
    expect(resolved.status).toBe("dangling_record");
    expect(resolved.record).toBeNull();
  });
});
