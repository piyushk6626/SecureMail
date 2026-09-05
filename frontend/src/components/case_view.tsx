import { Download, FileText } from "lucide-react";
import { motion, useReducedMotion } from "motion/react";
import { analysis_html_url, analysis_pdf_url, case_html_url, case_pdf_url } from "../core/api";
import type { CanonicalReport } from "../core/model";
import { render_forensic_text } from "../core/forensic_text";
import {
  coverage_percent,
  select_certificate_posture,
  select_coverage,
  select_protocol_counts,
  select_starttls_states,
  select_tls_versions,
} from "../core/selectors";
import { CoverageChart, InventoryChart, SeverityChart } from "./charts";
import { FindingsTable } from "./findings_table";
import { Badge, Card } from "./ui";

export function CaseView({
  report,
  run_id,
}: {
  report: CanonicalReport;
  run_id: string | null;
}) {
  const reduced_motion = useReducedMotion();
  const coverage = select_coverage(report);
  const coverage_value = coverage_percent(coverage);
  const advisory_items = report.advisory?.items ?? [];
  const analyst_notes = report.analyst_conclusions?.notes ?? [];
  const case_id = report.manifest.case_id ?? "Uploaded capture";
  const html_href = run_id ? analysis_html_url(run_id) : case_html_url(case_id);
  const pdf_href = run_id ? analysis_pdf_url(run_id) : case_pdf_url(case_id);
  const fact_count =
    (report.evidence.flows?.length ?? 0) +
    (report.evidence.sessions?.length ?? 0) +
    (report.evidence.handshakes?.length ?? 0) +
    (report.evidence.certificates?.length ?? 0);
  const certificates = select_certificate_posture(report);
  return (
    <motion.div
      animate={{ opacity: 1, y: 0 }}
      initial={reduced_motion ? false : { opacity: 0, y: 8 }}
      transition={{ duration: 0.24 }}
    >
      <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone="info">Case view</Badge>
            <Badge tone={report.evidence.posture.assessment_state === "complete" ? "success" : "unknown"}>
              {report.evidence.posture.assessment_state}
            </Badge>
            <span className="text-xs text-[var(--muted)]">
              {new Date(report.manifest.generated_at).toLocaleString()}
            </span>
          </div>
          <h1 className="forensic-text mt-3 break-all text-2xl font-semibold tracking-tight">
            {render_forensic_text(case_id)}
          </h1>
        </div>
        <div className="flex flex-wrap gap-2">
          <a
            className="inline-flex min-h-9 items-center justify-center gap-2 rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 text-sm font-medium text-[var(--text)] hover:bg-[var(--surface-raised)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-400"
            href={html_href}
          >
            <FileText size={15} /> Download HTML
          </a>
          <a
            className="inline-flex min-h-9 items-center justify-center gap-2 rounded-lg bg-cyan-600 px-3 text-sm font-medium text-white hover:bg-cyan-500 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-400"
            href={pdf_href}
          >
            <Download size={15} /> Download PDF
          </a>
        </div>
      </div>
      <section aria-label="Posture KPIs" className="mb-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi label="Risk score" suffix="/100" tone="danger" value={report.evidence.posture.risk_score ?? "—"} />
        <Kpi label="Findings" tone="warning" value={report.manifest.posture_summary.finding_count} />
        <Kpi
          label="Coverage passed"
          suffix={coverage_value === null ? "" : "%"}
          tone="success"
          value={coverage_value ?? "—"}
        />
        <Kpi
          label="Unknown / obscured"
          tone="unknown"
          value={coverage.unknown_count + coverage.not_observable_count}
        />
      </section>
      <div className="mb-6 grid gap-4 xl:grid-cols-2">
        <SeverityChart report={report} />
        <CoverageChart report={report} />
      </div>
      <div className="mb-6 grid gap-4 lg:grid-cols-3">
        <InventoryChart
          counts={select_protocol_counts(report)}
          label="Protocol inventory"
          test_id="protocol-chart"
          title="Protocol inventory"
        />
        <InventoryChart
          counts={select_tls_versions(report)}
          label="TLS versions"
          test_id="tls-chart"
          title="TLS versions"
        />
        <InventoryChart
          counts={select_starttls_states(report)}
          label="STARTTLS states"
          test_id="starttls-chart"
          title="STARTTLS state"
        />
      </div>
      <section aria-labelledby="limitations-title" className="mb-6">
        <Card className="border-amber-500/25 p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="section-label">Visibility constraints</p>
              <h2 className="mt-1 font-semibold" id="limitations-title">
                Limitations are not passes
              </h2>
            </div>
            <Badge tone="warning">
              {report.limitations.unknown_check_count + report.limitations.not_observable_check_count}{" "}
              unresolved checks
            </Badge>
          </div>
          <div className="mt-4 grid gap-3 text-sm sm:grid-cols-3">
            <Limit label="Incomplete flows" value={report.limitations.incomplete_flow_count} />
            <Limit label="Conflicting flows" value={report.limitations.conflicting_flow_count} />
            <Limit
              label="Certificates not observable"
              value={report.limitations.not_observable_certificate_count}
            />
          </div>
          {(report.limitations.notes ?? []).map((note, index) => (
            <p className="forensic-text mt-3 text-xs leading-5 text-[var(--muted)]" key={index}>
              {render_forensic_text(note)}
            </p>
          ))}
        </Card>
      </section>
      <section aria-label="Observed Facts" className="mb-6" data-region="observed-facts">
        <RegionHeading
          count={fact_count}
          description="Analyzer-derived records and frame-linked protocol observations."
          label="Observed Facts"
        />
        <Card className="p-5">
          <div className="grid gap-3 sm:grid-cols-4">
            <Limit label="Flows" value={report.evidence.flows?.length ?? 0} />
            <Limit label="Sessions" value={report.evidence.sessions?.length ?? 0} />
            <Limit label="TLS handshakes" value={report.evidence.handshakes?.length ?? 0} />
            <Limit label="Certificates" value={report.evidence.certificates?.length ?? 0} />
          </div>
          <div className="mt-4 grid gap-3 sm:grid-cols-3">
            <Limit label="Valid at capture" value={certificates.valid_at_capture} />
            <Limit label="Expired at capture" value={certificates.expired_at_capture} />
            <Limit label="Identity mismatch" value={certificates.identity_mismatch} />
          </div>
          <div className="mt-4 space-y-2">
            {(report.evidence.sessions ?? []).flatMap((session) =>
              (session.events ?? []).map((event, index) =>
                event.text ? (
                  <div className="rounded-lg bg-[var(--surface-raised)] p-3 text-xs" key={`${session.uid}-${index}`}>
                    <span className="mr-2 font-mono text-[var(--muted)]">
                      frame {event.frame_number ?? "—"}
                    </span>
                    <bdi className="forensic-text" dir="ltr">
                      {render_forensic_text(event.text)}
                    </bdi>
                  </div>
                ) : (
                  []
                ),
              ),
            )}
          </div>
        </Card>
      </section>
      <section aria-label="Deterministic Conclusions" className="mb-6" data-region="deterministic-conclusions">
        <FindingsTable report={report} />
      </section>
      <div className="grid gap-6 xl:grid-cols-2">
        <section aria-label="Advisory / ML" data-region="advisory-ml">
          <RegionHeading
            count={advisory_items.length}
            description="Shadow-mode signals that never alter deterministic findings."
            label="Advisory / ML"
          />
          <Card className="min-h-36 p-5">
            {report.advisory?.present && advisory_items.length > 0 ? (
              advisory_items.map((item, index) => (
                <div className="border-b border-[var(--border)] py-3 first:pt-0 last:border-0 last:pb-0" key={`${item.code}-${index}`}>
                  <p className="font-medium">{render_forensic_text(item.code)}</p>
                  <p className="forensic-text mt-1 text-sm text-[var(--muted)]">
                    {render_forensic_text(item.reason)}
                  </p>
                </div>
              ))
            ) : (
              <p className="text-sm text-[var(--muted)]">No advisory analysis is present for this report.</p>
            )}
          </Card>
        </section>
        <section aria-label="Analyst Notes" data-region="analyst-notes">
          <RegionHeading
            count={analyst_notes.length}
            description="Read-only conclusions retained in the canonical report."
            label="Analyst Notes"
          />
          <Card className="min-h-36 p-5">
            {report.analyst_conclusions?.present && analyst_notes.length > 0 ? (
              <ul className="list-disc space-y-2 pl-5 text-sm">
                {analyst_notes.map((note, index) => (
                  <li className="forensic-text" key={index}>
                    {render_forensic_text(note)}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-[var(--muted)]">No analyst notes were published with this report.</p>
            )}
          </Card>
        </section>
      </div>
    </motion.div>
  );
}

function Kpi({
  label,
  value,
  suffix = "",
  tone,
}: {
  label: string;
  value: string | number;
  suffix?: string;
  tone: "danger" | "warning" | "success" | "unknown";
}) {
  const reduced_motion = useReducedMotion();
  const colors = {
    danger: "text-red-400",
    warning: "text-amber-400",
    success: "text-emerald-400",
    unknown: "text-violet-300",
  };
  return (
    <Card className="p-4">
      <p className="text-[11px] uppercase tracking-wider text-[var(--muted)]">{label}</p>
      <motion.p
        animate={{ opacity: 1 }}
        className={`mt-2 font-mono text-2xl font-semibold ${colors[tone]}`}
        initial={reduced_motion ? false : { opacity: 0 }}
      >
        {value}
        <span className="ml-1 text-xs text-[var(--muted)]">{suffix}</span>
      </motion.p>
    </Card>
  );
}

function Limit({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg bg-[var(--surface-raised)] p-3">
      <p className="text-xs text-[var(--muted)]">{label}</p>
      <p className="mt-1 font-mono text-lg font-semibold">{value}</p>
    </div>
  );
}

function RegionHeading({
  count,
  label,
  description,
}: {
  count: number;
  label: string;
  description: string;
}) {
  return (
    <div className="mb-3 flex items-end justify-between gap-4">
      <div>
        <p className="section-label">{label}</p>
        <p className="mt-1 text-sm text-[var(--muted)]">{description}</p>
      </div>
      <Badge>{count}</Badge>
    </div>
  );
}
