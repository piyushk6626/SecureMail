import {
  ChevronRight,
  Download,
  EyeOff,
  FileText,
  LockKeyhole,
  Radio,
} from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { useState } from "react";
import { analysis_html_url, analysis_pdf_url, case_html_url, case_pdf_url } from "../core/api";
import { render_forensic_text } from "../core/forensic_text";
import type { CanonicalReport } from "../core/model";
import {
  select_coverage,
  select_findings,
  type FindingRow,
} from "../core/selectors";
import { AnalystRings } from "./analyst_rings";
import { CoverageChart, SeverityChart, TransportProfileCard } from "./charts";
import { EvidenceBento } from "./evidence_bento";
import { EvidenceHeatmap } from "./evidence_heatmap";
import { FindingsTable } from "./findings_table";
import { FlowTopology } from "./flow_topology";
import { Badge, Card } from "./ui";

type CasePage = "overview" | "findings" | "evidence" | "context";

const case_pages: { id: CasePage; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "findings", label: "Findings" },
  { id: "evidence", label: "Evidence" },
  { id: "context", label: "Analysis context" },
];

export function CaseView({ report, run_id }: { report: CanonicalReport; run_id: string | null }) {
  const reduced_motion = useReducedMotion();
  const [active_page, set_active_page] = useState<CasePage>("overview");
  const findings = [...select_findings(report)].sort((left, right) => right.score - left.score);
  const advisory_items = report.advisory?.items ?? [];
  const analyst_notes = report.analyst_conclusions?.notes ?? [];
  const case_id = report.manifest.case_id ?? "Uploaded capture";
  const html_href = run_id ? analysis_html_url(run_id) : case_html_url(case_id);
  const pdf_href = run_id ? analysis_pdf_url(run_id) : case_pdf_url(case_id);
  const page_counts: Partial<Record<CasePage, number>> = {
    findings: findings.length,
    evidence:
      (report.evidence.flows?.length ?? 0) +
      (report.evidence.sessions?.length ?? 0) +
      (report.evidence.handshakes?.length ?? 0) +
      (report.evidence.certificates?.length ?? 0),
    context: advisory_items.length + analyst_notes.length,
  };

  return (
    <motion.div
      animate={{ opacity: 1, y: 0 }}
      initial={reduced_motion ? false : { opacity: 0, y: 8 }}
      transition={{ duration: 0.24 }}
    >
      <CaseHeader
        case_id={case_id}
        generated_at={report.manifest.generated_at}
        html_href={html_href}
        pdf_href={pdf_href}
        policy_profile={report.manifest.policy_profile}
        state={report.evidence.posture.assessment_state}
      />

      <nav aria-label="Case sections" className="case-page-tabs" role="tablist">
        {case_pages.map((page) => (
          <button
            aria-controls={`case-panel-${page.id}`}
            aria-selected={active_page === page.id}
            className={active_page === page.id ? "active" : ""}
            id={`case-tab-${page.id}`}
            key={page.id}
            onKeyDown={(event) => {
              const offset = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
              if (offset === 0 && event.key !== "Home" && event.key !== "End") return;
              event.preventDefault();
              const current_index = case_pages.findIndex((candidate) => candidate.id === active_page);
              const next_index = event.key === "Home"
                ? 0
                : event.key === "End"
                  ? case_pages.length - 1
                  : (current_index + offset + case_pages.length) % case_pages.length;
              const next_page = case_pages[next_index]?.id ?? "overview";
              set_active_page(next_page);
              document.getElementById(`case-tab-${next_page}`)?.focus();
            }}
            onClick={() => set_active_page(page.id)}
            role="tab"
            tabIndex={active_page === page.id ? 0 : -1}
            type="button"
          >
            {active_page === page.id ? <motion.span className="case-tab-indicator" layoutId="active-case-tab" /> : null}
            <span>{page.label}</span>
            {page_counts[page.id] === undefined ? null : <small>{page_counts[page.id]}</small>}
          </button>
        ))}
      </nav>

      <AnimatePresence mode="wait" initial={false}>
        <motion.div
          animate={{ opacity: 1, x: 0 }}
          aria-labelledby={`case-tab-${active_page}`}
          className="case-page-panel"
          exit={reduced_motion ? {} : { opacity: 0, x: -12 }}
          id={`case-panel-${active_page}`}
          initial={reduced_motion ? false : { opacity: 0, x: 12 }}
          key={active_page}
          role="tabpanel"
          transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
        >
          {active_page === "overview" ? (
            <OverviewPage findings={findings} on_open_findings={() => set_active_page("findings")} report={report} />
          ) : null}
          {active_page === "findings" ? (
            <section aria-label="Deterministic Conclusions" data-region="deterministic-conclusions">
              <WorkspaceHeading eyebrow="Deterministic conclusions" text="Ranked by the canonical endpoint score. Select a finding to inspect its exact evidence references." title="Prioritized findings" />
              <FindingsTable report={report} />
            </section>
          ) : null}
          {active_page === "evidence" ? <EvidencePage report={report} /> : null}
          {active_page === "context" ? (
            <ContextPage advisory_items={advisory_items} analyst_notes={analyst_notes} report={report} />
          ) : null}
        </motion.div>
      </AnimatePresence>
    </motion.div>
  );
}

function OverviewPage({ findings, on_open_findings, report }: { findings: FindingRow[]; on_open_findings: () => void; report: CanonicalReport }) {
  const coverage = select_coverage(report);
  const visibility_gaps = coverage.unknown_count + coverage.not_observable_count;
  const affected_endpoints = new Set(findings.map((finding) => finding.affected_endpoint)).size;
  const top_finding = findings[0] ?? null;
  return (
    <section aria-label="Posture command deck">
      <div className="command-deck">
        <div className="briefing-panel">
          <div className="flex items-center gap-2 text-amber-300"><Radio size={15} /><span className="section-label !text-amber-300">Admin briefing</span></div>
          <h2 className="mt-4 text-xl font-semibold leading-snug">{briefing_title({ top_finding, visibility_gaps })}</h2>
          <p className="mt-3 text-sm leading-6 text-[var(--muted)]">{briefing_detail({ top_finding, visibility_gaps, failed_checks: coverage.failed_count })}</p>
          {top_finding ? <button className="briefing-action" onClick={on_open_findings} type="button">Review prioritized finding <ChevronRight size={15} /></button> : null}
          <div className="mt-auto grid grid-cols-2 gap-2 pt-6"><BriefStat label="Affected endpoints" value={affected_endpoints} /><BriefStat label="Policy profile" value={report.manifest.policy_profile} /></div>
        </div>
        <div className="posture-core"><AnalystRings report={report} /></div>
        <AttentionQueue findings={findings} on_open_findings={on_open_findings} visibility_gaps={visibility_gaps} />
      </div>

      <div className="case-section">
        <WorkspaceHeading eyebrow="Posture picture" text="What failed, what was visible, and where the exposure sits." title="Control and transport posture" />
        <div className="control-posture-bento"><SeverityChart report={report} /><CoverageChart report={report} /><TransportProfileCard report={report} /></div>
      </div>

      <div className="case-section"><VisibilityCard report={report} visibility_gaps={visibility_gaps} /></div>
    </section>
  );
}

function EvidencePage({ report }: { report: CanonicalReport }) {
  const fact_count =
    (report.evidence.flows?.length ?? 0) +
    (report.evidence.sessions?.length ?? 0) +
    (report.evidence.handshakes?.length ?? 0) +
    (report.evidence.certificates?.length ?? 0);
  return (
    <section aria-label="Observed Facts" data-region="observed-facts">
      <WorkspaceHeading count={fact_count} eyebrow="Observed facts" text="Scan every evidence family at once, select a record, then use the ledgers for packet-level context." title="Evidence workspace" />
      <EvidenceBento report={report} />
      <EvidenceHeatmap report={report} />
      <div className="case-section"><FlowTopology report={report} /></div>
      <ProtocolObservations report={report} />
    </section>
  );
}

function ContextPage({ advisory_items, analyst_notes, report }: { advisory_items: { code: string; reason: string }[]; analyst_notes: string[]; report: CanonicalReport }) {
  return (
    <section aria-label="Analysis context">
      <WorkspaceHeading eyebrow="Analysis context" text="Advisory signals and analyst interpretation remain separate from deterministic findings." title="Human and model context" />
      <div className="grid gap-4 xl:grid-cols-2">
        <ContextCard empty="No advisory analysis is present for this report." items={advisory_items.map((item) => ({ title: item.code, text: item.reason }))} label="Advisory / ML" present={Boolean(report.advisory?.present)} />
        <ContextCard empty="No analyst notes were published with this report." items={analyst_notes.map((note, index) => ({ title: `Analyst note ${index + 1}`, text: note }))} label="Analyst Notes" present={Boolean(report.analyst_conclusions?.present)} />
      </div>
      <Card className="case-section p-5">
        <p className="section-label">Run provenance</p>
        <div className="mt-4 grid gap-4 text-xs sm:grid-cols-2 xl:grid-cols-3">
          <Detail label="Capture SHA-256" value={report.manifest.source_capture_sha256} />
          <Detail label="Analyzer bundle" value={report.manifest.analyzer_bundle_digest} />
          <Detail label="Policy pack" value={report.manifest.policy_pack_version} />
          <Detail label="Configuration" value={report.manifest.configuration_digest} />
          <Detail label="Schema" value={report.schema_version ?? "unavailable"} />
          <Detail label="Generated" value={report.manifest.generated_at} />
        </div>
      </Card>
    </section>
  );
}

function CaseHeader({ case_id, generated_at, html_href, pdf_href, policy_profile, state }: { case_id: string; generated_at: string; html_href: string; pdf_href: string; policy_profile: string; state: string }) {
  return (
    <div className="mb-5 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2"><Badge tone="info">Case intelligence</Badge><Badge tone={state === "complete" ? "success" : "unknown"}>{state}</Badge><span className="text-xs text-[var(--muted)]">{new Date(generated_at).toLocaleString()}</span></div>
        <h1 className="forensic-text mt-3 break-all text-2xl font-semibold tracking-tight sm:text-3xl">{render_forensic_text(case_id)}</h1>
        <p className="mt-2 text-sm text-[var(--muted)]">Policy <span className="forensic-text text-[var(--text-soft)]">{render_forensic_text(policy_profile)}</span></p>
      </div>
      <div className="flex flex-wrap gap-2"><a aria-label="Download HTML" className="report-link" href={html_href}><FileText size={15} /> HTML report</a><a aria-label="Download PDF" className="report-link report-link-primary" href={pdf_href}><Download size={15} /> PDF report</a></div>
    </div>
  );
}

function AttentionQueue({ findings, on_open_findings, visibility_gaps }: { findings: FindingRow[]; on_open_findings: () => void; visibility_gaps: number }) {
  const visible_findings = findings.slice(0, 4);
  return (
    <div className="attention-queue">
      <div className="flex items-center justify-between gap-3"><div><p className="section-label !text-red-300">Attention queue</p><h2 className="mt-1 font-semibold">Investigate in this order</h2></div><span className="queue-count">{findings.length}</span></div>
      <div className="mt-4 space-y-2">
        {visible_findings.length > 0 ? visible_findings.map((finding) => (
          <button className="attention-item w-full text-left" key={finding.finding_id} onClick={on_open_findings} type="button">
            <span className={`priority-index priority-${priority_for(finding)}`}>P{priority_for(finding)}</span>
            <span className="min-w-0 flex-1"><span className="block truncate text-sm font-semibold">{render_forensic_text(finding.title)}</span><span className="forensic-text mt-0.5 block truncate text-xs text-[var(--muted)]">{render_forensic_text(finding.affected_endpoint)} · {finding.protocol}</span></span>
            <span className="font-mono text-sm font-semibold">{finding.score}</span>
          </button>
        )) : <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-4 text-sm text-emerald-300">No deterministic failures in the observable scope.</div>}
      </div>
      {visibility_gaps > 0 ? <p className="mt-3 flex gap-2 text-xs leading-5 text-[var(--muted)]"><EyeOff className="mt-0.5 shrink-0 text-violet-300" size={14} />{visibility_gaps} unresolved checks still need capture or telemetry review.</p> : null}
    </div>
  );
}

function VisibilityCard({ report, visibility_gaps }: { report: CanonicalReport; visibility_gaps: number }) {
  return (
    <Card className="visibility-card p-5">
      <div className="flex flex-wrap items-start justify-between gap-4"><div className="max-w-2xl"><p className="section-label !text-amber-300">Confidence boundary</p><h2 className="mt-2 text-lg font-semibold">Visibility limits that can change the conclusion</h2><p className="mt-2 text-sm leading-6 text-[var(--muted)]">Missing or encrypted evidence is unresolved scope. It is not evidence of a secure service.</p></div><Badge tone={visibility_gaps > 0 ? "warning" : "success"}>{visibility_gaps} unresolved checks</Badge></div>
      <div className="mt-5 grid gap-3 sm:grid-cols-3"><Limit label="Incomplete flows" value={report.limitations.incomplete_flow_count} /><Limit label="Conflicting flows" value={report.limitations.conflicting_flow_count} /><Limit label="Certificates not observable" value={report.limitations.not_observable_certificate_count} /></div>
      {(report.limitations.notes ?? []).map((note, index) => <p className="forensic-text mt-3 text-xs leading-5 text-[var(--muted)]" key={index}>{render_forensic_text(note)}</p>)}
    </Card>
  );
}

function ProtocolObservations({ report }: { report: CanonicalReport }) {
  const observations = (report.evidence.sessions ?? []).flatMap((session) => (session.events ?? []).filter((event) => event.text).map((event) => ({ session, event })));
  return (
    <Card className="evidence-observations-card case-section p-5">
      <div className="flex items-start justify-between gap-4"><div><p className="section-label">Protocol transcript</p><h3 className="mt-1 font-semibold">Bounded observations</h3><p className="mt-1 text-sm text-[var(--muted)]">Redacted analyzer events for quick triage.</p></div><Badge>{observations.length}</Badge></div>
      {observations.length === 0 ? <p className="mt-5 text-sm text-[var(--muted)]">No text observations were retained.</p> : <div className="mt-4 grid gap-2 lg:grid-cols-2">{observations.slice(0, 8).map(({ session, event }, index) => <div className="observation-row" key={`${session.uid}-${event.frame_number ?? index}-${index}`}><div className="flex items-center justify-between gap-3 text-xs text-[var(--muted)]"><span className="uppercase tracking-wider">{session.protocol ?? session.payload_evidence}</span><span className="font-mono">frame {event.frame_number ?? "—"}</span></div><bdi className="forensic-text mt-2 block text-xs leading-5" dir="ltr">{render_forensic_text(event.text ?? "")}</bdi></div>)}</div>}
    </Card>
  );
}

function ContextCard({ empty, items, label, present }: { empty: string; items: { title: string; text: string }[]; label: string; present: boolean }) {
  return (
    <section aria-label={label} data-region={label === "Advisory / ML" ? "advisory-ml" : "analyst-notes"}>
      <Card className="min-h-44 p-5"><div className="flex items-center justify-between gap-3"><div className="flex items-center gap-3"><span className="panel-icon"><LockKeyhole size={17} /></span><p className="font-semibold">{label}</p></div><Badge tone={present ? "info" : "neutral"}>{items.length}</Badge></div>{present && items.length > 0 ? <div className="mt-4 space-y-3">{items.map((item, index) => <div className="border-t border-[var(--border)] pt-3 first:border-0 first:pt-0" key={`${item.title}-${index}`}><p className="text-sm font-medium">{render_forensic_text(item.title)}</p><p className="forensic-text mt-1 text-xs leading-5 text-[var(--muted)]">{render_forensic_text(item.text)}</p></div>)}</div> : <p className="mt-5 text-sm text-[var(--muted)]">{empty}</p>}</Card>
    </section>
  );
}

function WorkspaceHeading({ eyebrow, text, title, count }: { eyebrow: string; text: string; title: string; count?: number }) {
  return <div className="mb-5 flex items-end justify-between gap-4"><div><p className="section-label">{eyebrow}</p><h2 className="mt-1 text-xl font-semibold">{title}</h2><p className="mt-1 text-sm text-[var(--muted)]">{text}</p></div>{count === undefined ? null : <Badge>{count}</Badge>}</div>;
}

function BriefStat({ label, value }: { label: string; value: string | number }) {
  return <div className="brief-stat"><span>{label}</span><b className="forensic-text">{render_forensic_text(String(value))}</b></div>;
}

function Limit({ label, value }: { label: string; value: number }) {
  return <div className="limit-cell"><p className="text-xs text-[var(--muted)]">{label}</p><p className="mt-1 font-mono text-lg font-semibold">{value.toLocaleString()}</p></div>;
}

function Detail({ label, value }: { label: string; value: string | number }) {
  return <div><dt className="text-[var(--muted)]">{label}</dt><dd className="forensic-text mt-1 break-all text-[var(--text-soft)]">{render_forensic_text(String(value))}</dd></div>;
}

function priority_for(finding: FindingRow): 1 | 2 | 3 {
  if (finding.severity === "high" || finding.score >= 80) return 1;
  if (finding.severity === "medium" || finding.score >= 50) return 2;
  return 3;
}

function briefing_title({ top_finding, visibility_gaps }: { top_finding: FindingRow | null; visibility_gaps: number }): string {
  if (top_finding) return `${top_finding.title} needs the first review.`;
  if (visibility_gaps > 0) return "No observed failure, but the evidence is incomplete.";
  return "No deterministic failures in the observed scope.";
}

function briefing_detail({ top_finding, visibility_gaps, failed_checks }: { top_finding: FindingRow | null; visibility_gaps: number; failed_checks: number }): string {
  if (top_finding) return `${top_finding.affected_endpoint} leads the queue with a score of ${top_finding.score}/100. ${failed_checks} policy checks failed and ${visibility_gaps} remain unresolved.`;
  if (visibility_gaps > 0) return `${visibility_gaps} checks are unknown or not observable. Improve capture completeness before treating this case as clear.`;
  return "All applicable checks passed within the evidence that was available to the analyzers.";
}
