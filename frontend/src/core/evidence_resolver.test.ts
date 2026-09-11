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

  it("resolves qualified paths and every supported derived display fact", () => {
    const report = make_report();
    const flow = report.evidence.flows?.[0];
    const handshake = report.evidence.handshakes?.[0];
    if (!flow || !handshake) throw new Error("fixture requires flow and handshake evidence");
    flow.uid = "tls-1";
    handshake.version.selected = "TLSv12";
    handshake.key_exchange.mechanism = "ECDHE";
    report.evidence.sessions = [{
      uid: "tls-1",
      protocol: "smtp",
      payload_evidence: "smtp",
      port_hint: "smtp",
      evidence_state: "observed",
      explicit_upgrade: { state: "tls_established", evidence_state: "observed", evidence_frames: [4] },
      implicit_tls: null,
      events: [{ kind: "request", command: "login", direction: "orig", frame_number: 4 }],
    }];
    const values = [
      ["handshake", "handshake.version.selected", "TLSv12"],
      ["session", "derived.service_role", "smtp_relay"],
      ["session", "derived.observed_commands", ["LOGIN"]],
      ["session", "derived.transport_tls_established", true],
      ["handshake", "derived.forward_secrecy.outcome", "present"],
    ] as const;
    for (const [record_type, field_path, expected] of values) {
      const resolved = resolve_evidence_reference({
        report,
        reference: {
          record_type,
          record_key: "tls-1",
          field_path,
          frame_number: null,
          evidence_state: "observed",
        },
      });
      expect(resolved.status).toBe("resolved");
      expect(resolved.field_value).toEqual(expected);
      expect(resolved.frame_context).toBeNull();
      expect(resolved.direct_frame).toBe(false);
    }
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

  it("keeps unknown fields explicit rather than fabricating a value", () => {
    const resolved = resolve_evidence_reference({
      report: make_report(),
      reference: {
        record_type: "handshake",
        record_key: "tls-1",
        field_path: "handshake.not_a_real_field",
        frame_number: null,
        evidence_state: "indeterminate",
      },
    });
    expect(resolved.status).toBe("dangling_field");
    expect(resolved.field_value).toBeUndefined();
  });
});
