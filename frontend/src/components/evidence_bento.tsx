import { Activity, Fingerprint, Mail, Network, ShieldCheck } from "lucide-react";
import type { CSSProperties, ReactNode } from "react";
import type { CanonicalReport } from "../core/model";

export function EvidenceBento({ report }: { report: CanonicalReport }) {
  const flows = report.evidence.flows ?? [];
  const sessions = report.evidence.sessions ?? [];
  const handshakes = report.evidence.handshakes ?? [];
  const certificates = report.evidence.certificates ?? [];
  const packet_count = report.evidence.capture_preflight.packet_count;
  const observed_bytes = flows.reduce((total, flow) => total + flow.orig_bytes + flow.resp_bytes, 0);
  const complete_flows = flows.filter((flow) => flow.reconstruction_quality === "complete").length;
  const incomplete_flows = report.limitations.incomplete_flow_count;
  const conflicting_flows = report.limitations.conflicting_flow_count;
  const identified_sessions = sessions.filter((session) => session.protocol !== null && session.protocol !== undefined).length;
  const protocols = new Set(sessions.map((session) => session.protocol).filter(Boolean)).size;
  const secure_upgrades = sessions.filter((session) => session.explicit_upgrade?.state === "tls_established").length;
  const established_tls = handshakes.filter((handshake) => handshake.established).length;
  const full_tls = handshakes.filter((handshake) => handshake.visibility === "full").length;
  const healthy_certificates = certificates.filter(
    (certificate) =>
      certificate.syntax_valid &&
      certificate.valid_at_capture_time !== false &&
      certificate.validation?.identity_match !== false &&
      certificate.validation?.path_valid_at_capture_time !== false,
  ).length;
  const identity_mismatches = certificates.filter(
    (certificate) => certificate.validation?.identity_match === false,
  ).length;

  return (
    <section aria-label="Evidence overview" className="evidence-bento">
      <EvidenceCard className="evidence-bento-volume" icon={<Activity size={18} />} title="Network volume">
        <MetricLead label="packets parsed" value={packet_count.toLocaleString()} />
        <div className="evidence-card-pair">
          <MetricSmall label="Flows" value={flows.length} />
          <MetricSmall label="Observed bytes" value={format_bytes(observed_bytes)} />
        </div>
      </EvidenceCard>

      <EvidenceCard className="evidence-bento-mail" icon={<Mail size={18} />} title="Mail parsing">
        <MetricLead label="sessions identified" value={identified_sessions.toLocaleString()} />
        <Progress label="Protocol resolution" value={ratio(identified_sessions, sessions.length)} />
        <div className="evidence-card-pair">
          <MetricSmall label="Protocols" value={protocols} />
          <MetricSmall label="TLS upgrades" value={secure_upgrades} />
        </div>
      </EvidenceCard>

      <EvidenceCard className="evidence-bento-tls" icon={<ShieldCheck size={18} />} title="TLS visibility">
        <MetricLead label="handshakes observed" value={handshakes.length.toLocaleString()} />
        <Progress label="Full handshake visibility" value={ratio(full_tls, handshakes.length)} />
        <div className="evidence-card-pair">
          <MetricSmall label="Established" value={established_tls} />
          <MetricSmall label="Full evidence" value={full_tls} />
        </div>
      </EvidenceCard>

      <EvidenceCard className="evidence-bento-integrity evidence-bento-wide" icon={<Network size={18} />} title="Flow integrity">
        <Progress label="Completely reconstructed" value={ratio(complete_flows, flows.length)} />
        <div className="evidence-card-triple">
          <MetricSmall label="Complete" value={complete_flows} />
          <MetricSmall label="Incomplete" value={incomplete_flows} />
          <MetricSmall label="Conflicting" value={conflicting_flows} />
        </div>
      </EvidenceCard>

      <EvidenceCard className="evidence-bento-certificates" icon={<Fingerprint size={18} />} title="Certificate identity">
        <MetricLead
          label={certificates.length === 0 ? "health not observable" : "certificates clear"}
          suffix={certificates.length === 0 ? undefined : "%"}
          value={certificates.length === 0 ? "—" : String(ratio(healthy_certificates, certificates.length))}
        />
        <div className="evidence-quality-strip" aria-hidden="true">
          {Array.from({ length: 12 }, (_, index) => (
            <span className={index < Math.round((ratio(healthy_certificates, certificates.length) / 100) * 12) ? "filled" : ""} key={index} />
          ))}
        </div>
        <div className="evidence-card-pair">
          <MetricSmall label="Identity mismatch" value={identity_mismatches} />
          <MetricSmall label="Not observable" value={report.limitations.not_observable_certificate_count} />
        </div>
      </EvidenceCard>
    </section>
  );
}

function EvidenceCard({ children, className, icon, title }: { children: ReactNode; className: string; icon: ReactNode; title: string }) {
  return (
    <article className={`evidence-bento-card ${className}`}>
      <div className="evidence-card-header"><span>{icon}</span><h3>{title}</h3></div>
      <div className="evidence-card-body">{children}</div>
    </article>
  );
}

function MetricLead({ label, suffix, value }: { label: string; suffix?: string | undefined; value: string }) {
  return <div className="evidence-metric-lead"><p><b>{value}</b>{suffix ? <span>{suffix}</span> : null}</p><small>{label}</small></div>;
}

function MetricSmall({ label, value }: { label: string; value: number | string }) {
  return <div className="evidence-metric-small"><b>{typeof value === "number" ? value.toLocaleString() : value}</b><span>{label}</span></div>;
}

function Progress({ label, value }: { label: string; value: number }) {
  return (
    <div className="evidence-progress">
      <div><span>{label}</span><b>{value}%</b></div>
      <div aria-label={`${label}: ${value}%`} aria-valuemax={100} aria-valuemin={0} aria-valuenow={value} className="evidence-progress-track" role="progressbar">
        <span style={{ "--progress": `${value}%` } as CSSProperties} />
      </div>
    </div>
  );
}

function ratio(value: number, total: number): number {
  if (total <= 0) return 0;
  return Math.round((Math.max(0, value) / total) * 100);
}

function format_bytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}
