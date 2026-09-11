import type {
  CanonicalReport,
  CertificateEvidence,
  EmailSession,
  EvidenceReference,
  Flow,
  TlsHandshake,
} from "../types/canonical_report.generated";
import { is_record } from "./model";
import { service_role, session_tls_established } from "./selectors";

export type EvidenceRecord = Flow | EmailSession | TlsHandshake | CertificateEvidence;

export interface ResolvedEvidence {
  reference: EvidenceReference;
  record: EvidenceRecord | null;
  field_value: unknown;
  frame_context: string | null;
  status: "resolved" | "dangling_record" | "dangling_field";
  direct_frame: boolean;
}

function certificate_keys(certificate: CertificateEvidence): string[] {
  return [
    certificate.uid,
    `${certificate.uid}:${certificate.role}:${certificate.chain_index}:${certificate.der_sha256}`,
  ];
}

function find_record(input: {
  report: CanonicalReport;
  reference: EvidenceReference;
}): EvidenceRecord | null {
  const evidence = input.report.evidence;
  if (input.reference.record_type === "flow")
    return evidence.flows?.find((item) => item.uid === input.reference.record_key) ?? null;
  if (input.reference.record_type === "session")
    return evidence.sessions?.find((item) => item.uid === input.reference.record_key) ?? null;
  if (input.reference.record_type === "handshake")
    return evidence.handshakes?.find((item) => item.uid === input.reference.record_key) ?? null;
  return (
    evidence.certificates?.find((item) =>
      certificate_keys(item).includes(input.reference.record_key),
    ) ?? null
  );
}

function relative_field_path(reference: EvidenceReference): string {
  const prefix = `${reference.record_type}.`;
  return reference.field_path.startsWith(prefix)
    ? reference.field_path.slice(prefix.length)
    : reference.field_path;
}

function resolve_field(record: EvidenceRecord, field_path: string): unknown {
  let value: unknown = record;
  for (const segment of field_path.split(".")) {
    if (!is_record(value) || !(segment in value)) return undefined;
    value = value[segment];
  }
  return value;
}

function forward_secrecy(handshake: TlsHandshake): "present" | "absent" | "indeterminate" {
  const version = handshake.version.selected;
  const mechanism = handshake.key_exchange.mechanism?.toUpperCase();
  if (!version || !mechanism || handshake.visibility !== "full") return "indeterminate";
  if (version === "TLSv13") {
    if (mechanism.includes("PSK") && !mechanism.includes("DHE")) return "indeterminate";
    return mechanism.includes("DHE") ? "present" : "indeterminate";
  }
  if (version === "TLSv12") {
    if (mechanism === "ECDHE" || mechanism === "DHE" || mechanism === "(EC)DHE") return "present";
    if (mechanism === "RSA" || mechanism === "DH" || mechanism === "ECDH") return "absent";
  }
  return "indeterminate";
}

function resolve_derived(input: {
  report: CanonicalReport;
  record: EvidenceRecord;
  reference: EvidenceReference;
}): unknown {
  const path = input.reference.field_path;
  if (!path.startsWith("derived.")) return undefined;
  const uid = input.record.uid;
  if (path === "derived.service_role") return service_role(input.report, uid);
  if (path === "derived.observed_commands" && "events" in input.record)
    return input.record.events
      .flatMap((event) => (event.command ? [event.command.toUpperCase()] : []));
  if (path === "derived.transport_tls_established") {
    const session = input.report.evidence.sessions?.find((item) => item.uid === uid);
    return session ? session_tls_established(input.report, session) : false;
  }
  if (path === "derived.forward_secrecy.outcome" && "key_exchange" in input.record)
    return forward_secrecy(input.record);
  return undefined;
}

function resolve_frame_context(record: EvidenceRecord, frame_number: number | null): string | null {
  if (frame_number === null) return null;
  if ("events" in record) {
    const event = record.events.find((item) => item.frame_number === frame_number);
    return event ? `Protocol ${event.kind}, ${event.direction} direction` : `Frame ${frame_number}`;
  }
  if ("messages" in record) {
    const message = record.messages.find((item) => item.frame_number === frame_number);
    return message ? `TLS ${message.kind}, ${message.direction} direction` : `Frame ${frame_number}`;
  }
  if ("source_frames" in record && record.source_frames.includes(frame_number))
    return `Certificate source frame ${frame_number}`;
  return `Frame ${frame_number}`;
}

export function resolve_evidence_reference(input: {
  report: CanonicalReport;
  reference: EvidenceReference;
}): ResolvedEvidence {
  const record = find_record(input);
  const frame_number = input.reference.frame_number ?? null;
  if (!record)
    return {
      reference: input.reference,
      record: null,
      field_value: undefined,
      frame_context: frame_number === null ? null : `Frame ${frame_number} (record unavailable)`,
      status: "dangling_record",
      direct_frame: frame_number !== null,
    };

  const derived = resolve_derived({ ...input, record });
  const field_value = input.reference.field_path.startsWith("derived.")
    ? derived
    : resolve_field(record, relative_field_path(input.reference));
  return {
    reference: input.reference,
    record,
    field_value,
    frame_context: resolve_frame_context(record, frame_number),
    status: field_value === undefined ? "dangling_field" : "resolved",
    direct_frame: frame_number !== null,
  };
}
