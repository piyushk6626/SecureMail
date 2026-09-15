import type { CertificateChain as CertificateChainModel } from "../core/selectors";
import { render_forensic_text } from "../core/forensic_text";
import { Badge, Card, evidence_state_tone } from "./ui";

function bool_label(value: boolean | null | undefined): string {
  if (value === true) return "valid";
  if (value === false) return "invalid";
  return "not assessed";
}

function bool_tone(value: boolean | null | undefined): "success" | "danger" | "unknown" {
  if (value === true) return "success";
  if (value === false) return "danger";
  return "unknown";
}

export function CertificateChain({ chain }: { chain: CertificateChainModel }) {
  const leaf = chain.certificates.find((certificate) => certificate.chain_index === 0 && certificate.role === "server") ?? chain.certificates[0];
  const validation = leaf?.validation;
  if (chain.handshake?.server_certificate_state === "not_observable" && chain.certificates.length === 0) {
    return <Card className="certificate-unobservable p-5"><p className="section-label">Certificate evidence</p><h3 className="mt-1 font-semibold">Certificate not observable</h3><p className="mt-2 text-sm leading-6 text-[var(--muted)]">Not observable (typical for TLS 1.3 without authorized secrets). This is a visibility limit, not a certificate pass.</p></Card>;
  }
  if (!leaf) return null;
  return (
    <Card className="certificate-chain p-5">
      <div className="flex flex-wrap items-start justify-between gap-3"><div><p className="section-label">Presented certificate chain</p><h3 className="mt-1 font-semibold">Handshake {render_forensic_text(chain.uid)}</h3></div><Badge tone={evidence_state_tone(chain.handshake?.server_certificate_state ?? leaf.evidence_state)}>{chain.handshake?.server_certificate_state ?? leaf.evidence_state}</Badge></div>
      <ol className="certificate-nodes">{chain.certificates.map((certificate) => <li key={`${certificate.der_sha256}-${certificate.chain_index}`}><span>{certificate.chain_index === 0 ? "Leaf" : `Issuer ${certificate.chain_index}`}</span><b className="forensic-text">{render_forensic_text(certificate.subject ?? certificate.der_sha256)}</b><small className="forensic-text">{certificate.public_key_algorithm ?? "key not observed"} {certificate.public_key_size ? `${certificate.public_key_size} bits` : ""}</small></li>)}</ol>
      <div className="certificate-validation-grid"><div><p>Path at capture</p><Badge tone={bool_tone(validation?.path_valid_at_capture_time)}>{bool_label(validation?.path_valid_at_capture_time)}</Badge><Reasons values={validation?.path_invalid_reasons_at_capture_time} /></div><div><p>Identity (SAN only)</p><Badge tone={bool_tone(validation?.identity_match)}>{bool_label(validation?.identity_match)}</Badge><Reasons values={validation?.identity_mismatch_reasons ?? validation?.indeterminate_reasons} /></div><div><p>Time</p><b>{leaf.valid_at_capture_time === false ? "invalid at capture" : leaf.valid_at_capture_time === true ? "valid at capture" : "not assessed"}</b><small>{leaf.valid_at_analysis_time === false ? "invalid at analysis" : leaf.valid_at_analysis_time === true ? "valid at analysis" : "analysis time unavailable"}</small></div><div><p>Revocation</p><Badge tone={validation?.revocation_status === "unknown" ? "unknown" : "neutral"}>{validation?.revocation_status ?? "unknown"}</Badge><small>Offline default is unknown.</small></div></div>
      <dl className="certificate-facts"><Detail label="Issuer" value={leaf.issuer ?? "not observed"} /><Detail label="Reference identity" value={validation?.reference_identity ?? "unavailable"} /><Detail label="Certificate signature" value={leaf.signature_algorithm ?? "not observed"} /><Detail label="CertificateVerify" value={chain.handshake?.certificate_verify_signature.algorithm ?? "not observable"} /></dl>
    </Card>
  );
}

function Reasons({ values }: { values?: readonly string[] | null | undefined }) {
  return values && values.length > 0 ? <small className="forensic-text">{values.map(render_forensic_text).join(", ")}</small> : <small>No reason recorded.</small>;
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd className="forensic-text">{render_forensic_text(value)}</dd></div>;
}
