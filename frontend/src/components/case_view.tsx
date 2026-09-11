import { Download, FileText, Layers3 } from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { useMemo, useState, type KeyboardEvent } from "react";
import { analysis_html_url, analysis_pdf_url, case_html_url, case_pdf_url } from "../core/api";
import { render_forensic_text } from "../core/forensic_text";
import type { CanonicalReport } from "../core/model";
import {
  select_certificate_chains,
  select_findings,
  type AnalystFocus,
  type FindingRow,
} from "../core/selectors";
import { CertificateChain } from "./certificate_chain";
import { CoverageMatrix } from "./coverage_matrix";
import { FindingDetails } from "./finding_details";
import { FindingsTable } from "./findings_table";
import { FlowTopology } from "./flow_topology";
import { RiskTree } from "./risk_tree";
import { SessionTimeline } from "./session_timeline";
import { TrustBanner } from "./trust_banner";
import { Badge, Card } from "./ui";

type CasePage = "overview" | "findings" | "evidence" | "context";

const case_pages: { id: CasePage; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "findings", label: "Findings" },
  { id: "evidence", label: "Evidence" },
  { id: "context", label: "Analysis context" },
];

const focus_options: { id: AnalystFocus; label: string }[] = [
  { id: "standard", label: "Standard" },
  { id: "incident", label: "Incident / IR" },
  { id: "mail_owner", label: "Mail owner" },
  { id: "protocol", label: "Protocol" },
  { id: "pki", label: "PKI" },
  { id: "historical", label: "Historical" },
];

export function CaseView({
  report,
  run_id,
  original_filename,
}: {
  report: CanonicalReport;
  run_id: string | null;
  original_filename?: string | null | undefined;
}) {
  const reduced_motion = useReducedMotion();
  const identity = `${report.manifest.case_id ?? "case"}:${report.manifest.analysis_run_id ?? "run"}:${report.manifest.generated_at}`;
  const [active_page, set_active_page] = useState<CasePage>("overview");
  const [acknowledged, set_acknowledged] = useState(false);
  const [focus, set_focus] = useState<AnalystFocus>("standard");
  const [selected_finding, set_selected_finding] = useState<FindingRow | null>(null);
  const findings = useMemo(() => select_findings(report), [report]);
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

  function change_focus(next: AnalystFocus): void {
    set_focus(next);
    if (next === "protocol" || next === "pki") set_active_page("evidence");
    else if (next === "historical") set_active_page("context");
    else set_active_page("overview");
  }

  function move_case_tab(event: KeyboardEvent<HTMLButtonElement>, page: CasePage): void {
    const current_index = case_pages.findIndex((candidate) => candidate.id === page);
    const next_index =
      event.key === "Home"
        ? 0
        : event.key === "End"
          ? case_pages.length - 1
          : event.key === "ArrowLeft"
            ? (current_index - 1 + case_pages.length) % case_pages.length
            : event.key === "ArrowRight"
              ? (current_index + 1) % case_pages.length
              : current_index;
    if (next_index === current_index && event.key !== "Home" && event.key !== "End") return;
    const next_page = case_pages[next_index];
    if (!next_page) return;
    event.preventDefault();
    set_active_page(next_page.id);
    window.requestAnimationFrame(() => document.getElementById(`case-tab-${next_page.id}`)?.focus());
  }

  return (
    <div key={identity}>
      <CaseHeader case_id={case_id} generated_at={report.manifest.generated_at} html_href={html_href} pdf_href={pdf_href} policy_profile={report.manifest.policy_profile} state={report.evidence.posture.assessment_state} />
      <TrustBanner acknowledged={acknowledged} on_acknowledge={() => set_acknowledged(true)} original_filename={original_filename} report={report} />
      <div className="case-focus"><span><Layers3 size={15} /> View focus</span><select aria-label="View focus" onChange={(event) => change_focus(event.target.value as AnalystFocus)} value={focus}>{focus_options.map((option) => <option key={option.id} value={option.id}>{option.label}</option>)}</select></div>
      <nav aria-label="Case sections" className="case-page-tabs" role="tablist">
        {case_pages.map((page) => <button aria-controls={`case-panel-${page.id}`} aria-selected={active_page === page.id} className={active_page === page.id ? "active" : ""} id={`case-tab-${page.id}`} key={page.id} onClick={() => set_active_page(page.id)} onKeyDown={(event) => move_case_tab(event, page.id)} role="tab" tabIndex={active_page === page.id ? 0 : -1} type="button"><span>{page.label}</span>{page_counts[page.id] === undefined ? null : <small>{page_counts[page.id]}</small>}</button>)}
      </nav>
      <AnimatePresence mode="wait" initial={false}>
        <motion.div animate={{ opacity: 1, x: 0 }} aria-labelledby={`case-tab-${active_page}`} className={`case-page-panel ${!acknowledged && report.evidence.posture.assessment_state !== "complete" ? "case-secondary-until-acknowledged" : ""}`} exit={reduced_motion ? {} : { opacity: 0, x: -12 }} id={`case-panel-${active_page}`} initial={reduced_motion ? false : { opacity: 0, x: 12 }} key={active_page} role="tabpanel" transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}>
          {active_page === "overview" ? <OverviewPage on_select={set_selected_finding} report={report} /> : null}
          {active_page === "findings" ? <section aria-label="Deterministic Conclusions" data-region="deterministic-conclusions"><WorkspaceHeading eyebrow="Deterministic conclusions" text="Canonical endpoint findings remain separate from passes, coverage, and advisory output." title="Prioritized findings" /><RiskTree initial_mode={focus === "mail_owner" ? "remediation" : "endpoint"} key={focus} on_select={set_selected_finding} report={report} /><div className="case-section"><FindingsTable on_select={set_selected_finding} report={report} /></div></section> : null}
          {active_page === "evidence" ? <EvidencePage focus={focus} report={report} /> : null}
          {active_page === "context" ? <ContextPage advisory_items={advisory_items} analyst_notes={analyst_notes} focus={focus} report={report} /> : null}
        </motion.div>
      </AnimatePresence>
      <FindingDetails finding={selected_finding} on_close={() => set_selected_finding(null)} report={report} />
    </div>
  );
}

function OverviewPage({ on_select, report }: { on_select: (finding: FindingRow) => void; report: CanonicalReport }) {
  return <><section aria-label="Deterministic Conclusions" data-region="deterministic-conclusions"><div className="overview-intro"><p className="section-label">Analyst workflow</p><h2>Trust the capture before acting on findings.</h2><p>Endpoint priority ranks observed weaknesses. Coverage and limitations stay visible above this queue.</p></div><RiskTree on_select={on_select} report={report} /></section><CoverageMatrix report={report} /><section aria-label="Observed Facts" className="case-section" data-region="observed-facts"><WorkspaceHeading eyebrow="Observed facts" text="Continue to Evidence for flow, session, handshake, and certificate records." title="Evidence inventory" /><FactCounts report={report} /></section></>;
}

function EvidencePage({ focus, report }: { focus: AnalystFocus; report: CanonicalReport }) {
  const sessions = report.evidence.sessions ?? [];
  const visible_sessions = sessions.slice(0, 128);
  const [selected_uid, set_selected_uid] = useState<string | null>(sessions[0]?.uid ?? null);
  const selected_session = sessions.find((session) => session.uid === selected_uid) ?? null;
  const chains = select_certificate_chains(report);
  return <section aria-label="Observed Facts" data-region="observed-facts"><WorkspaceHeading eyebrow="Observed facts" text="These records describe the capture. They are not policy conclusions." title="Evidence workspace" />{focus === "historical" ? null : <CoverageMatrix report={report} />}<div className="evidence-workspace case-section"><Card className="p-5"><p className="section-label">Mail sessions</p><h3 className="mt-1 font-semibold">Select a session</h3><div className="mt-4 max-h-80 space-y-2 overflow-y-auto">{sessions.length === 0 ? <p className="text-sm text-[var(--muted)]">No decoded mail sessions.</p> : visible_sessions.map((session) => <button aria-pressed={selected_session?.uid === session.uid} className="session-picker" key={session.uid} onClick={() => set_selected_uid(session.uid)} type="button"><span className="forensic-text">{session.uid}</span><b>{session.protocol ?? session.payload_evidence}</b><small>{session.explicit_upgrade?.state ?? "no explicit upgrade"}</small></button>)}{visible_sessions.length < sessions.length ? <p className="text-xs text-[var(--muted)]">Showing the first {visible_sessions.length} of {sessions.length} sessions.</p> : null}</div></Card><div>{selected_session ? <SessionTimeline session={selected_session} /> : <Card className="p-5 text-sm text-[var(--muted)]">Select a session to inspect protocol and upgrade evidence.</Card>}</div></div><HandshakeFacts report={report} /><div className="case-section"><WorkspaceHeading eyebrow="TLS and certificates" text="Path validation, identity matching, and revocation are independent evidence fields." title="Presented certificate chains" />{chains.length === 0 ? <CertificateAbsence report={report} /> : <><div className="grid gap-4 xl:grid-cols-2">{chains.slice(0, 64).map((chain) => <CertificateChain chain={chain} key={chain.uid} />)}</div>{chains.length > 64 ? <p className="mt-3 text-xs text-[var(--muted)]">Showing the first 64 of {chains.length} certificate chains.</p> : null}</>}</div><div className="case-section"><FlowTopology report={report} /></div></section>;
}

function HandshakeFacts({ report }: { report: CanonicalReport }) {
  const handshakes = report.evidence.handshakes ?? [];
  return <section aria-label="TLS handshake facts" className="case-section"><WorkspaceHeading eyebrow="Observed facts" text="Selected version, cipher, key exchange, and message visibility are captured facts—not a finding until policy publishes one." title="TLS handshakes" />{handshakes.length === 0 ? <Card className="p-5 text-sm text-[var(--muted)]">No TLS handshake records were published.</Card> : <><div className="grid gap-3 xl:grid-cols-2">{handshakes.slice(0, 64).map((handshake) => <Card className="p-4" key={handshake.uid}><div className="flex flex-wrap items-center justify-between gap-2"><b className="forensic-text">{handshake.uid}</b><Badge tone={handshake.visibility === "full" ? "info" : "unknown"}>{handshake.visibility}</Badge></div><dl className="mt-4 grid gap-3 text-xs sm:grid-cols-2"><Detail label="Selected version" value={handshake.version.selected ?? "not observable"} /><Detail label="Cipher suite" value={handshake.cipher_suite.name ?? handshake.cipher_suite.code ?? "not observable"} /><Detail label="Key exchange" value={handshake.key_exchange.mechanism ?? "indeterminate"} /><Detail label="Server certificate" value={handshake.server_certificate_state} /></dl><div className="mt-4 border-t border-[var(--border)] pt-3"><p className="section-label">Handshake messages</p>{(handshake.messages ?? []).length === 0 ? <p className="mt-2 text-xs text-[var(--muted)]">No message sequence was retained.</p> : <ol className="mt-2 flex flex-wrap gap-2">{(handshake.messages ?? []).map((message, index) => <li className="frame-chip" key={`${message.frame_number ?? "none"}-${index}`}>{message.kind}{message.frame_number === null || message.frame_number === undefined ? "" : ` · frame ${message.frame_number}`}</li>)}</ol>}</div></Card>)}</div>{handshakes.length > 64 ? <p className="mt-3 text-xs text-[var(--muted)]">Showing the first 64 of {handshakes.length} handshakes.</p> : null}</>}</section>;
}

function CertificateAbsence({ report }: { report: CanonicalReport }) {
  const has_not_observable = (report.evidence.handshakes ?? []).some((handshake) => handshake.server_certificate_state === "not_observable");
  return <Card className="certificate-unobservable p-5"><p className="section-label">Certificate evidence</p><h3 className="mt-1 font-semibold">{has_not_observable ? "Certificates not observable" : "No certificate records"}</h3><p className="mt-2 text-sm text-[var(--muted)]">{has_not_observable ? "Not observable (typical for TLS 1.3 without authorized secrets). This does not mean the certificate was valid." : "No certificate fact was published for this report."}</p></Card>;
}

function ContextPage({ advisory_items, analyst_notes, focus, report }: { advisory_items: { code: string; reason: string }[]; analyst_notes: string[]; focus: AnalystFocus; report: CanonicalReport }) {
  const historical = report.manifest.policy_profile === "historical_at_capture";
  return <section aria-label="Analysis context"><WorkspaceHeading eyebrow="Separate context" text="Advisory signals and human conclusions never rewrite deterministic findings." title="Advisory, notes, and provenance" />{focus === "historical" && !historical ? <Card className="mb-4 border-violet-500/30 bg-violet-500/5 p-5"><p className="font-semibold">A new analysis with historical_at_capture is required.</p><p className="mt-2 text-sm text-[var(--muted)]">This dashboard does not re-run policy or switch profiles in the browser.</p></Card> : null}<div className="grid gap-4 xl:grid-cols-2"><ContextCard empty="No advisory analysis is present for this report." items={advisory_items.map((item) => ({ title: item.code, text: item.reason }))} label="Advisory / ML" present={Boolean(report.advisory?.present)} /><ContextCard empty="No analyst conclusions were published. This dashboard does not currently provide a notes write path." items={analyst_notes.map((note, index) => ({ title: `Analyst conclusion ${index + 1}`, text: note }))} label="Analyst Conclusions" present={Boolean(report.analyst_conclusions?.present)} /></div><Card className="case-section p-5"><p className="section-label">Run provenance</p><div className="mt-4 grid gap-4 text-xs sm:grid-cols-2 xl:grid-cols-3"><Detail label="Capture SHA-256" value={report.manifest.source_capture_sha256} /><Detail label="Analysis run" value={report.manifest.analysis_run_id ?? "not retained"} /><Detail label="Analyzer bundle" value={report.manifest.analyzer_bundle_digest} /><Detail label="Policy pack" value={report.manifest.policy_pack_version} /><Detail label="Trust store" value={report.manifest.trust_store_digest ?? "not available"} /><Detail label="Signature" value={report.manifest.signature.availability ?? "unavailable"} /></div></Card></section>;
}

function CaseHeader({ case_id, generated_at, html_href, pdf_href, policy_profile, state }: { case_id: string; generated_at: string; html_href: string; pdf_href: string; policy_profile: string; state: string }) {
  return <div className="mb-5 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between"><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><Badge tone={state === "limited" ? "warning" : state === "none" ? "unknown" : "info"}>{state} assessment</Badge><span className="text-xs text-[var(--muted)]">{new Date(generated_at).toLocaleString()}</span></div><h1 className="forensic-text mt-3 break-all text-2xl font-semibold tracking-tight sm:text-3xl">{render_forensic_text(case_id)}</h1><p className="mt-2 text-sm text-[var(--muted)]">Policy <span className="forensic-text text-[var(--text-soft)]">{render_forensic_text(policy_profile)}</span></p></div><div className="flex flex-wrap gap-2"><a aria-label="Download HTML" className="report-link" href={html_href}><FileText size={15} /> HTML report</a><a aria-label="Download PDF" className="report-link report-link-primary" href={pdf_href}><Download size={15} /> PDF report</a></div></div>;
}

function FactCounts({ report }: { report: CanonicalReport }) {
  const values = [["Flows", report.evidence.flows?.length ?? 0], ["Sessions", report.evidence.sessions?.length ?? 0], ["Handshakes", report.evidence.handshakes?.length ?? 0], ["Certificates", report.evidence.certificates?.length ?? 0]];
  return <div className="fact-counts">{values.map(([label, value]) => <Card className="p-4" key={label}><p>{label}</p><b>{value}</b></Card>)}</div>;
}

function ContextCard({ empty, items, label, present }: { empty: string; items: { title: string; text: string }[]; label: string; present: boolean }) {
  return <section aria-label={label} data-region={label === "Advisory / ML" ? "advisory-ml" : "analyst-notes"}><Card className="min-h-44 p-5"><div className="flex items-center justify-between gap-3"><p className="font-semibold">{label}</p><Badge tone={present ? "unknown" : "neutral"}>{items.length}</Badge></div>{label === "Advisory / ML" ? <p className="mt-2 text-xs text-violet-300">Does not change deterministic findings.</p> : null}{present && items.length > 0 ? <div className="mt-4 space-y-3">{items.map((item, index) => <div className="border-t border-[var(--border)] pt-3 first:border-0 first:pt-0" key={`${item.title}-${index}`}><p className="forensic-text text-sm font-medium">{render_forensic_text(item.title)}</p><p className="forensic-text mt-1 text-xs leading-5 text-[var(--muted)]">{render_forensic_text(item.text)}</p></div>)}</div> : <p className="mt-5 text-sm text-[var(--muted)]">{empty}</p>}</Card></section>;
}

function WorkspaceHeading({ eyebrow, text, title }: { eyebrow: string; text: string; title: string }) {
  return <div className="mb-5"><p className="section-label">{eyebrow}</p><h2 className="mt-1 text-xl font-semibold">{title}</h2><p className="mt-1 text-sm text-[var(--muted)]">{text}</p></div>;
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div><dt className="text-[var(--muted)]">{label}</dt><dd className="forensic-text mt-1 break-all text-[var(--text-soft)]">{render_forensic_text(value)}</dd></div>;
}
