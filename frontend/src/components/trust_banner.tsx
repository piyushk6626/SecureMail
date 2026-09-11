import { AlertTriangle, CheckCircle2, Clipboard, EyeOff, FileWarning, ShieldQuestion } from "lucide-react";
import type { ReactNode } from "react";
import type { CanonicalReport } from "../core/model";
import { render_forensic_text } from "../core/forensic_text";
import { select_coverage } from "../core/selectors";
import { Badge, Button, Card } from "./ui";

function short_hash(value: string): string {
  return `${value.slice(0, 12)}…${value.slice(-8)}`;
}

function assessment_tone(state: string): "info" | "warning" | "unknown" {
  if (state === "limited") return "warning";
  if (state === "none") return "unknown";
  return "info";
}

export function TrustBanner({
  report,
  acknowledged,
  on_acknowledge,
  original_filename,
}: {
  report: CanonicalReport;
  acknowledged: boolean;
  on_acknowledge: () => void;
  original_filename?: string | null | undefined;
}) {
  const posture = report.evidence.posture;
  const coverage = select_coverage(report);
  const limitations = report.limitations;
  const stage_errors = report.stage_errors ?? [];
  const has_limits =
    posture.assessment_state !== "complete" ||
    limitations.truncated_packets_present ||
    limitations.incomplete_flow_count > 0 ||
    limitations.conflicting_flow_count > 0 ||
    limitations.not_observable_certificate_count > 0 ||
    limitations.unknown_check_count > 0 ||
    limitations.not_observable_check_count > 0 ||
    stage_errors.length > 0 ||
    (limitations.notes?.length ?? 0) > 0;
  const is_open = has_limits && !acknowledged;

  async function copy_capture_hash(): Promise<void> {
    await navigator.clipboard.writeText(report.manifest.source_capture_sha256).catch(() => undefined);
  }

  return (
    <section aria-label="Assessment trust" className={`trust-banner ${is_open ? "trust-banner-open" : ""}`}>
      <Card className="overflow-hidden">
        <div className="trust-banner-main">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={assessment_tone(posture.assessment_state)}>{posture.assessment_state} assessment</Badge>
              {posture.risk_score === null || posture.risk_score === undefined ? (
                <Badge tone="unknown">Not proven</Badge>
              ) : (
                <Badge tone={posture.risk_score >= 80 ? "danger" : posture.risk_score >= 50 ? "warning" : "info"}>
                  Priority {posture.risk_score}
                </Badge>
              )}
              {has_limits ? <Badge tone="unknown">Visibility limits present</Badge> : null}
            </div>
            <h2 className="mt-3 text-xl font-semibold">Assessment trust</h2>
            <p className="mt-1 text-sm leading-6 text-[var(--muted)]">
              Highest endpoint priority (0–100): {posture.risk_score ?? "Not proven"}. {coverage.applicable_count} applicable: {coverage.passed_count} passed, {coverage.failed_count} failed, {coverage.unknown_count} unknown, {coverage.not_observable_count} not observable.
            </p>
          </div>
          <div className="trust-banner-score" aria-label="Highest endpoint priority">
            <span>{posture.risk_score ?? "—"}</span>
            <small>endpoint priority</small>
          </div>
        </div>

        <div className="trust-provenance">
          <div><span>Capture SHA-256</span><b className="forensic-text">{short_hash(report.manifest.source_capture_sha256)}</b><button aria-label="Copy capture SHA-256" onClick={() => void copy_capture_hash()} type="button"><Clipboard size={13} /></button></div>
          <div><span>Policy</span><b className="forensic-text">{render_forensic_text(report.manifest.policy_profile)}</b></div>
          <div><span>Pack</span><b className="forensic-text">{short_hash(report.manifest.policy_pack_version)}</b></div>
          <div><span>Analyzer</span><b className="forensic-text">{short_hash(report.manifest.analyzer_bundle_digest)}</b></div>
          <div><span>Capture file</span><b className="forensic-text">{original_filename ? render_forensic_text(original_filename) : "Not retained in report"}</b></div>
        </div>

        <details className="trust-full-provenance">
          <summary>Full run provenance</summary>
          <dl>
            <Provenance label="Generated" value={report.manifest.generated_at} />
            <Provenance label="Case ID" value={report.manifest.case_id ?? "not retained"} />
            <Provenance label="Analysis run" value={report.manifest.analysis_run_id ?? "not retained"} />
            <Provenance label="Capture ID" value={report.manifest.capture_id ?? "not retained"} />
            <Provenance label="Configuration digest" value={report.manifest.configuration_digest} />
            <Provenance label="Trust store" value={report.manifest.trust_store_digest ?? "not available"} />
            <Provenance label="Renderer" value={`${report.manifest.renderer.html_renderer} / ${report.manifest.renderer.pdf_renderer}`} />
            <Provenance label="Signature" value={report.manifest.signature.availability ?? "unavailable"} />
          </dl>
        </details>

        {is_open ? (
          <div className="trust-limitations" data-testid="trust-limitations">
            <div className="flex items-start gap-3">
              <AlertTriangle className="mt-0.5 shrink-0 text-amber-400" size={18} />
              <div className="min-w-0">
                <h3 className="font-semibold">Limitations can change the conclusion</h3>
                <p className="mt-1 text-sm leading-6 text-[var(--muted)]">Missing, conflicting, encrypted, or incomplete evidence is unresolved scope—not a passing result.</p>
              </div>
            </div>
            <div className="trust-limit-grid">
              <Limit icon={<FileWarning size={15} />} label="Truncated capture" value={limitations.truncated_packets_present ? "present" : "none observed"} />
              <Limit icon={<ShieldQuestion size={15} />} label="Incomplete / conflicting flows" value={`${limitations.incomplete_flow_count} / ${limitations.conflicting_flow_count}`} />
              <Limit icon={<EyeOff size={15} />} label="Certificates not observable" value={limitations.not_observable_certificate_count} />
              <Limit icon={<EyeOff size={15} />} label="Unknown / not observable checks" value={`${limitations.unknown_check_count} / ${limitations.not_observable_check_count}`} />
            </div>
            {(limitations.notes ?? []).map((note, index) => <p className="forensic-text trust-note" key={index}>{render_forensic_text(note)}</p>)}
            {stage_errors.map((error, index) => <p className="forensic-text trust-note" key={`${error.stage}-${index}`}>{render_forensic_text(`${error.stage}: ${error.message} (${error.evidence_state})`)}</p>)}
            <Button className="mt-4" onClick={on_acknowledge} variant="secondary">Acknowledge limits and continue</Button>
          </div>
        ) : has_limits ? (
          <div className="trust-acknowledged"><CheckCircle2 size={15} /> Limitations acknowledged for this report. They remain unresolved evidence boundaries.</div>
        ) : null}
      </Card>
    </section>
  );
}

function Limit({ icon, label, value }: { icon: ReactNode; label: string; value: string | number }) {
  return <div className="trust-limit"><span>{icon}</span><p>{label}</p><b className="forensic-text">{value}</b></div>;
}

function Provenance({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd className="forensic-text">{render_forensic_text(value)}</dd></div>;
}
