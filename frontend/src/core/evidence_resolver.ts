import type {
  CanonicalReport,
  CertificateEvidence,
  EmailSession,
  EvidenceReference,
  Flow,
  TlsHandshake,
} from "../types/canonical_report.generated";
import { is_record } from "./model";

export type EvidenceRecord = Flow | EmailSession | TlsHandshake | CertificateEvidence;

export interface ResolvedEvidence {
  reference: EvidenceReference;
  record: EvidenceRecord | null;
  field_value: unknown;
  frame_context: string | null;
  status: "resolved" | "dangling_record" | "dangling_field";
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

function resolve_field(record: EvidenceRecord, field_path: string): unknown {
  let value: unknown = record;
  for (const segment of field_path.split(".")) {
    if (!is_record(value) || !(segment in value)) return undefined;
    value = value[segment];
  }
  return value;
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
  if (!record)
    return {
      reference: input.reference,
      record: null,
      field_value: undefined,
      frame_context: input.reference.frame_number
        ? `Frame ${input.reference.frame_number} (record unavailable)`
        : null,
      status: "dangling_record",
    };

  const field_value = resolve_field(record, input.reference.field_path);
  return {
    reference: input.reference,
    record,
    field_value,
    frame_context: resolve_frame_context(record, input.reference.frame_number ?? null),
    status: field_value === undefined ? "dangling_field" : "resolved",
  };
}
