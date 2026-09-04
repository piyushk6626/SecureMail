import { useEffect, useMemo, useState, type DragEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  BarChart3,
  FileJson,
  FolderOpen,
  Moon,
  ShieldCheck,
  Sun,
  Upload,
  X,
} from "lucide-react";
import { motion, useReducedMotion } from "motion/react";
import { get_case_report, get_cases, get_health, preview_report } from "./core/api";
import type { CanonicalReport, CaseSummary, ViewMode } from "./core/model";
import { coverage_percent, select_coverage } from "./core/selectors";
import { render_forensic_text } from "./core/forensic_text";
import { CoverageChart, SeverityChart } from "./components/charts";
import { FindingsTable } from "./components/findings_table";
import { Badge, Button, Card, EmptyState } from "./components/ui";

type Theme = "dark" | "light";

function initial_theme(): Theme {
  const saved = localStorage.getItem("securemail-theme");
  if (saved === "dark" || saved === "light") return saved;
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

function case_label(item: CaseSummary): string {
  const title = item.title?.trim();
  return title && title.length > 0 ? title : item.case_id;
}

export default function App() {
  const query_client = useQueryClient();
  const [theme, set_theme] = useState<Theme>(initial_theme);
  const [view_mode, set_view_mode] = useState<ViewMode>("case");
  const [selected_case_id, set_selected_case_id] = useState<string | null>(null);
  const [uploaded_report, set_uploaded_report] = useState<CanonicalReport | null>(null);
  const [upload_error, set_upload_error] = useState<string | null>(null);
  const [is_uploading, set_is_uploading] = useState(false);
  const health_query = useQuery({
    queryKey: ["health"],
    queryFn: ({ signal }) => get_health({ signal }),
    retry: 1,
    staleTime: 30_000,
  });
  const cases_query = useQuery({
    queryKey: ["cases"],
    queryFn: ({ signal }) => get_cases({ signal }),
    retry: 1,
  });
  const report_query = useQuery({
    queryKey: ["case-report", selected_case_id],
    queryFn: ({ signal }) => {
      if (selected_case_id === null) throw new Error("No case selected.");
      return get_case_report({ case_id: selected_case_id, signal });
    },
    enabled: selected_case_id !== null && uploaded_report === null,
    retry: false,
    staleTime: 0,
  });
  const visible_report = uploaded_report ?? report_query.data ?? null;
  const selected_label = uploaded_report
    ? uploaded_report.manifest.case_id ?? "Uploaded report"
    : selected_case_id;

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  function apply_theme(next_theme: Theme): void {
    document.documentElement.dataset.theme = next_theme;
    localStorage.setItem("securemail-theme", next_theme);
    set_theme(next_theme);
  }

  function select_case(case_id: string): void {
    set_uploaded_report(null);
    set_upload_error(null);
    set_selected_case_id(case_id || null);
    if (case_id) set_view_mode("case");
  }

  function clear_selection(): void {
    set_selected_case_id(null);
    set_uploaded_report(null);
    set_upload_error(null);
    query_client.removeQueries({ queryKey: ["case-report"] });
  }

  async function upload_file(file: File): Promise<void> {
    if (!file.name.toLocaleLowerCase().endsWith(".json") && file.type !== "application/json") {
      set_upload_error("Choose a JSON report.");
      return;
    }
    set_is_uploading(true);
    set_upload_error(null);
    set_selected_case_id(null);
    query_client.removeQueries({ queryKey: ["case-report"] });
    try {
      const report = await preview_report({ file });
      set_uploaded_report(report);
      set_view_mode("case");
    } catch (error) {
      set_uploaded_report(null);
      set_upload_error(error instanceof Error ? error.message : "Report preview failed.");
    } finally {
      set_is_uploading(false);
    }
  }

  return (
    <div className="min-h-screen bg-[var(--background)] text-[var(--text)]">
      <header className="sticky top-0 z-30 border-b border-[var(--border)] bg-[color:var(--background-alpha)] backdrop-blur-xl">
        <div className="mx-auto flex max-w-[1600px] items-center gap-4 px-4 py-3 sm:px-6">
          <div className="flex min-w-0 items-center gap-3">
            <div className="grid size-9 place-items-center rounded-xl border border-cyan-500/25 bg-cyan-500/10 text-cyan-400">
              <ShieldCheck aria-hidden size={19} />
            </div>
            <div className="min-w-0">
              <p className="truncate text-sm font-semibold tracking-tight">SecureMail</p>
              <p className="truncate text-[10px] uppercase tracking-[0.16em] text-[var(--muted)]">
                Cryptographic posture console
              </p>
            </div>
          </div>
          <div
            aria-label={health_query.isSuccess ? "API online" : "API unavailable"}
            className="ml-auto hidden items-center gap-2 text-[10px] uppercase tracking-wider text-[var(--muted)] md:flex"
          >
            <span
              className={`size-1.5 rounded-full ${
                health_query.isSuccess ? "bg-emerald-400" : "bg-slate-500"
              }`}
            />
            {health_query.isSuccess ? "API online" : "API unavailable"}
          </div>
          <nav aria-label="Primary" className="ml-auto flex items-center rounded-lg border border-[var(--border)] bg-[var(--surface)] p-1">
            <Button
              aria-current={view_mode === "portfolio" ? "page" : undefined}
              className={view_mode === "portfolio" ? "bg-[var(--surface-raised)] text-[var(--text)]" : ""}
              onClick={() => set_view_mode("portfolio")}
              variant="ghost"
            >
              <BarChart3 size={15} /> <span className="hidden sm:inline">Portfolio</span>
            </Button>
            <Button
              aria-current={view_mode === "case" ? "page" : undefined}
              className={view_mode === "case" ? "bg-[var(--surface-raised)] text-[var(--text)]" : ""}
              onClick={() => set_view_mode("case")}
              variant="ghost"
            >
              <FolderOpen size={15} /> <span className="hidden sm:inline">Case</span>
            </Button>
          </nav>
          <Button
            aria-label={`Use ${theme === "dark" ? "light" : "dark"} theme`}
            onClick={() => apply_theme(theme === "dark" ? "light" : "dark")}
            variant="secondary"
          >
            {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
          </Button>
        </div>
      </header>

      <div className="mx-auto grid max-w-[1600px] lg:grid-cols-[280px_minmax(0,1fr)]">
        <aside className="border-b border-[var(--border)] p-4 lg:min-h-[calc(100vh-65px)] lg:border-b-0 lg:border-r lg:p-5">
          <CasePicker
            cases={cases_query.data?.cases ?? []}
            error={cases_query.isError ? "Catalog unavailable" : null}
            selected_case_id={selected_case_id}
            on_select={select_case}
          />
          <div className="my-4 flex items-center gap-3 text-[10px] uppercase tracking-widest text-[var(--muted)]">
            <span className="h-px flex-1 bg-[var(--border)]" /> or <span className="h-px flex-1 bg-[var(--border)]" />
          </div>
          <ReportDropzone
            error={upload_error}
            is_uploading={is_uploading}
            on_upload={upload_file}
          />
          {selected_label ? (
            <div className="mt-4 rounded-lg border border-[var(--border)] bg-[var(--surface)] p-3">
              <p className="text-[10px] uppercase tracking-wider text-[var(--muted)]">Active case</p>
              <p className="forensic-text mt-1 truncate text-sm font-medium">
                {render_forensic_text(selected_label)}
              </p>
              <Button className="mt-3 w-full" onClick={clear_selection} variant="secondary">
                <X size={14} /> Clear case
              </Button>
            </div>
          ) : null}
          <p className="mt-4 text-xs leading-5 text-[var(--muted)]">
            Uploaded reports remain in this tab’s memory and are never added to the catalog.
          </p>
        </aside>

        <main className="min-w-0 p-4 sm:p-6 lg:p-8">
          {view_mode === "portfolio" ? (
            <PortfolioView cases={cases_query.data?.cases ?? []} is_loading={cases_query.isLoading} on_select={select_case} />
          ) : visible_report ? (
            <CaseView key={selected_label ?? "uploaded"} report={visible_report} />
          ) : report_query.isLoading ? (
            <LoadingState />
          ) : report_query.isError ? (
            <EmptyState
              description={report_query.error.message}
              title="Case report unavailable"
            >
              <Button onClick={clear_selection} variant="secondary">Return to no case selected</Button>
            </EmptyState>
          ) : (
            <NoCaseState />
          )}
        </main>
      </div>
    </div>
  );
}

function CasePicker({
  cases,
  error,
  selected_case_id,
  on_select,
}: {
  cases: CaseSummary[];
  error: string | null;
  selected_case_id: string | null;
  on_select: (case_id: string) => void;
}) {
  return (
    <label className="grid gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-[var(--muted)]">
      Case catalog
      <select
        aria-label="Select a case"
        className="h-10 w-full rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 text-sm font-normal normal-case tracking-normal text-[var(--text)] focus:border-cyan-500 focus:outline-none"
        disabled={Boolean(error)}
        onChange={(event) => on_select(event.target.value)}
        value={selected_case_id ?? ""}
      >
        <option value="">{error ?? "No case selected"}</option>
        {cases.map((item) => (
          <option key={item.case_id} value={item.case_id}>
            {case_label(item)}
          </option>
        ))}
      </select>
    </label>
  );
}

function ReportDropzone({
  error,
  is_uploading,
  on_upload,
}: {
  error: string | null;
  is_uploading: boolean;
  on_upload: (file: File) => Promise<void>;
}) {
  function handle_drop(event: DragEvent<HTMLLabelElement>): void {
    event.preventDefault();
    const file = event.dataTransfer.files.item(0);
    if (file) void on_upload(file);
  }
  return (
    <div>
      <label
        className="group grid min-h-36 cursor-pointer place-items-center rounded-xl border border-dashed border-[var(--border-strong)] bg-[var(--surface)] p-4 text-center transition-colors hover:border-cyan-500/60 hover:bg-cyan-500/5 focus-within:outline-2 focus-within:outline-cyan-400"
        onDragOver={(event) => event.preventDefault()}
        onDrop={handle_drop}
      >
        <input
          accept=".json,application/json"
          className="sr-only"
          disabled={is_uploading}
          onChange={(event) => {
            const file = event.target.files?.item(0);
            if (file) void on_upload(file);
            event.target.value = "";
          }}
          type="file"
        />
        <span>
          <span className="mx-auto grid size-9 place-items-center rounded-full bg-cyan-500/10 text-cyan-400">
            {is_uploading ? <Activity className="animate-pulse" size={17} /> : <Upload size={17} />}
          </span>
          <span className="mt-3 block text-sm font-medium text-[var(--text)]">
            {is_uploading ? "Validating report…" : "Drop canonical JSON"}
          </span>
          <span className="mt-1 block text-xs text-[var(--muted)]">or choose a local file</span>
        </span>
      </label>
      {error ? <p className="mt-2 text-xs text-red-400" role="alert">{error}</p> : null}
    </div>
  );
}

function NoCaseState() {
  return (
    <div data-testid="no-case-selected">
      <EmptyState
        description="Choose an authorized catalog case or preview a canonical report. Case queries remain disabled until you select one."
        title="No case selected"
      >
        <div className="flex items-center gap-2 text-xs text-[var(--muted)]">
          <FileJson size={15} /> Canonical JSON · memory-only preview
        </div>
      </EmptyState>
    </div>
  );
}

function LoadingState() {
  return (
    <div aria-label="Loading case" className="space-y-4">
      <div className="h-28 animate-pulse rounded-xl bg-[var(--surface)]" />
      <div className="grid gap-4 md:grid-cols-2">
        <div className="h-64 animate-pulse rounded-xl bg-[var(--surface)]" />
        <div className="h-64 animate-pulse rounded-xl bg-[var(--surface)]" />
      </div>
    </div>
  );
}

function PortfolioView({
  cases,
  is_loading,
  on_select,
}: {
  cases: CaseSummary[];
  is_loading: boolean;
  on_select: (case_id: string) => void;
}) {
  const [search, set_search] = useState("");
  const [assessment, set_assessment] = useState("");
  const filtered_cases = useMemo(
    () =>
      cases.filter((item) => {
        if (assessment && item.assessment_state !== assessment) return false;
        const haystack = `${case_label(item)} ${item.case_id}`.toLocaleLowerCase();
        return haystack.includes(search.trim().toLocaleLowerCase());
      }),
    [assessment, cases, search],
  );
  return (
    <section aria-labelledby="portfolio-title">
      <div className="mb-6 flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <p className="section-label">Portfolio comparison</p>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight" id="portfolio-title">Cases</h1>
          <p className="mt-2 text-sm text-[var(--muted)]">Compare published posture summaries without loading case evidence.</p>
        </div>
        <div className="flex gap-2">
          <input aria-label="Filter portfolio" className="control" onChange={(event) => set_search(event.target.value)} placeholder="Filter cases" type="search" value={search} />
          <select aria-label="Filter assessment state" className="control" onChange={(event) => set_assessment(event.target.value)} value={assessment}>
            <option value="">All states</option>
            <option value="complete">Complete</option>
            <option value="limited">Limited</option>
            <option value="none">None</option>
          </select>
        </div>
      </div>
      {is_loading ? <LoadingState /> : filtered_cases.length === 0 ? (
        <EmptyState description="No catalog cases match the current portfolio filters." title="No matching cases" />
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {filtered_cases.map((item) => (
            <Card className="p-5" data-testid="portfolio-case" key={item.case_id}>
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <h2 className="forensic-text truncate font-semibold">{render_forensic_text(case_label(item))}</h2>
                  <p className="forensic-text mt-1 truncate font-mono text-[10px] text-[var(--muted)]">{render_forensic_text(item.case_id)}</p>
                </div>
                <Badge tone={item.assessment_state === "complete" ? "success" : "unknown"}>{item.assessment_state ?? "unknown"}</Badge>
              </div>
              <div className="mt-5 grid grid-cols-3 gap-2">
                <PortfolioMetric label="Risk" value={item.risk_score ?? "—"} />
                <PortfolioMetric label="Findings" value={item.finding_count ?? "—"} />
                <PortfolioMetric label="Unknown" value={(item.unknown_count ?? 0) + (item.not_observable_count ?? 0)} />
              </div>
              <Button className="mt-5 w-full" onClick={() => on_select(item.case_id)} variant="secondary">Open case</Button>
            </Card>
          ))}
        </div>
      )}
    </section>
  );
}

function PortfolioMetric({ label, value }: { label: string; value: string | number }) {
  return <div className="rounded-lg bg-[var(--surface-raised)] p-2"><p className="text-[10px] uppercase text-[var(--muted)]">{label}</p><p className="mt-1 font-mono font-semibold">{value}</p></div>;
}

function CaseView({ report }: { report: CanonicalReport }) {
  const reduced_motion = useReducedMotion();
  const coverage = select_coverage(report);
  const coverage_value = coverage_percent(coverage);
  const advisory_items = report.advisory?.items ?? [];
  const analyst_notes = report.analyst_conclusions?.notes ?? [];
  const case_id = report.manifest.case_id ?? "Uploaded report";
  const fact_count =
    (report.evidence.flows?.length ?? 0) +
    (report.evidence.sessions?.length ?? 0) +
    (report.evidence.handshakes?.length ?? 0) +
    (report.evidence.certificates?.length ?? 0);
  return (
    <motion.div initial={reduced_motion ? false : { opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.24 }}>
      <div className="mb-6">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone="info">Case view</Badge>
          <Badge tone={report.evidence.posture.assessment_state === "complete" ? "success" : "unknown"}>{report.evidence.posture.assessment_state}</Badge>
          <span className="text-xs text-[var(--muted)]">{new Date(report.manifest.generated_at).toLocaleString()}</span>
        </div>
        <h1 className="forensic-text mt-3 break-all text-2xl font-semibold tracking-tight">{render_forensic_text(case_id)}</h1>
      </div>
      <section aria-label="Posture KPIs" className="mb-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi label="Risk score" value={report.evidence.posture.risk_score ?? "—"} suffix="/100" tone="danger" />
        <Kpi label="Findings" value={report.manifest.posture_summary.finding_count} tone="warning" />
        <Kpi label="Coverage passed" value={coverage_value ?? "—"} suffix={coverage_value === null ? "" : "%"} tone="success" />
        <Kpi label="Unknown / obscured" value={coverage.unknown_count + coverage.not_observable_count} tone="unknown" />
      </section>
      <div className="mb-6 grid gap-4 xl:grid-cols-2">
        <SeverityChart report={report} />
        <CoverageChart report={report} />
      </div>
      <section aria-labelledby="limitations-title" className="mb-6">
        <Card className="border-amber-500/25 p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div><p className="section-label">Visibility constraints</p><h2 className="mt-1 font-semibold" id="limitations-title">Limitations are not passes</h2></div>
            <Badge tone="warning">{report.limitations.unknown_check_count + report.limitations.not_observable_check_count} unresolved checks</Badge>
          </div>
          <div className="mt-4 grid gap-3 text-sm sm:grid-cols-3">
            <Limit label="Incomplete flows" value={report.limitations.incomplete_flow_count} />
            <Limit label="Conflicting flows" value={report.limitations.conflicting_flow_count} />
            <Limit label="Certificates not observable" value={report.limitations.not_observable_certificate_count} />
          </div>
          {(report.limitations.notes ?? []).map((note, index) => <p className="forensic-text mt-3 text-xs leading-5 text-[var(--muted)]" key={index}>{render_forensic_text(note)}</p>)}
        </Card>
      </section>
      <section aria-label="Observed Facts" className="mb-6" data-region="observed-facts">
        <RegionHeading count={fact_count} label="Observed Facts" description="Analyzer-derived records and frame-linked protocol observations." />
        <Card className="p-5">
          <div className="grid gap-3 sm:grid-cols-4">
            <Limit label="Flows" value={report.evidence.flows?.length ?? 0} />
            <Limit label="Sessions" value={report.evidence.sessions?.length ?? 0} />
            <Limit label="TLS handshakes" value={report.evidence.handshakes?.length ?? 0} />
            <Limit label="Certificates" value={report.evidence.certificates?.length ?? 0} />
          </div>
          <div className="mt-4 space-y-2">
            {(report.evidence.sessions ?? []).flatMap((session) =>
              (session.events ?? []).map((event, index) => event.text ? (
                <div className="rounded-lg bg-[var(--surface-raised)] p-3 text-xs" key={`${session.uid}-${index}`}>
                  <span className="mr-2 font-mono text-[var(--muted)]">frame {event.frame_number ?? "—"}</span>
                  <bdi className="forensic-text" dir="ltr">{render_forensic_text(event.text)}</bdi>
                </div>
              ) : []),
            )}
          </div>
        </Card>
      </section>
      <section aria-label="Deterministic Conclusions" className="mb-6" data-region="deterministic-conclusions">
        <FindingsTable report={report} />
      </section>
      <div className="grid gap-6 xl:grid-cols-2">
        <section aria-label="Advisory / ML" data-region="advisory-ml">
          <RegionHeading count={advisory_items.length} label="Advisory / ML" description="Shadow-mode signals that never alter deterministic findings." />
          <Card className="min-h-36 p-5">
            {report.advisory?.present && advisory_items.length > 0 ? advisory_items.map((item) => (
              <div className="border-b border-[var(--border)] py-3 first:pt-0 last:border-0 last:pb-0" key={item.code}>
                <p className="font-medium">{render_forensic_text(item.code)}</p><p className="forensic-text mt-1 text-sm text-[var(--muted)]">{render_forensic_text(item.reason)}</p>
              </div>
            )) : <p className="text-sm text-[var(--muted)]">No advisory analysis is present for this report.</p>}
          </Card>
        </section>
        <section aria-label="Analyst Notes" data-region="analyst-notes">
          <RegionHeading count={analyst_notes.length} label="Analyst Notes" description="Read-only conclusions retained in the canonical report." />
          <Card className="min-h-36 p-5">
            {report.analyst_conclusions?.present && analyst_notes.length > 0 ? (
              <ul className="list-disc space-y-2 pl-5 text-sm">{analyst_notes.map((note, index) => <li className="forensic-text" key={index}>{render_forensic_text(note)}</li>)}</ul>
            ) : <p className="text-sm text-[var(--muted)]">No analyst notes were published with this report.</p>}
          </Card>
        </section>
      </div>
    </motion.div>
  );
}

function Kpi({ label, value, suffix = "", tone }: { label: string; value: string | number; suffix?: string; tone: "danger" | "warning" | "success" | "unknown" }) {
  const reduced_motion = useReducedMotion();
  const colors = { danger: "text-red-400", warning: "text-amber-400", success: "text-emerald-400", unknown: "text-violet-300" };
  return <Card className="p-4"><p className="text-[11px] uppercase tracking-wider text-[var(--muted)]">{label}</p><motion.p className={`mt-2 font-mono text-2xl font-semibold ${colors[tone]}`} initial={reduced_motion ? false : { opacity: 0 }} animate={{ opacity: 1 }}>{value}<span className="ml-1 text-xs text-[var(--muted)]">{suffix}</span></motion.p></Card>;
}

function Limit({ label, value }: { label: string; value: number }) {
  return <div className="rounded-lg bg-[var(--surface-raised)] p-3"><p className="text-xs text-[var(--muted)]">{label}</p><p className="mt-1 font-mono text-lg font-semibold">{value}</p></div>;
}

function RegionHeading({ count, label, description }: { count: number; label: string; description: string }) {
  return <div className="mb-3 flex items-end justify-between gap-4"><div><p className="section-label">{label}</p><p className="mt-1 text-sm text-[var(--muted)]">{description}</p></div><Badge>{count}</Badge></div>;
}
