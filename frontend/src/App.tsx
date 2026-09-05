import { useEffect, useMemo, useState, type DragEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  BarChart3,
  FolderOpen,
  Menu,
  Moon,
  ShieldCheck,
  Sun,
  Upload,
  X,
} from "lucide-react";
import {
  cancel_analysis,
  create_analysis,
  get_analysis,
  get_analysis_report,
  get_case_report,
  get_cases,
  get_health,
} from "./core/api";
import type { AnalysisJob, CanonicalReport, CaseSummary, ViewMode } from "./core/model";
import { render_forensic_text } from "./core/forensic_text";
import { CaseView } from "./components/case_view";
import { Badge, Button, Card, EmptyState } from "./components/ui";

type Theme = "dark" | "light";

const STAGES = [
  "intake",
  "deterministic_analysis",
  "policy_scoring",
  "ml_advisory",
  "report_rendering",
  "publication",
] as const;

function initial_theme(): Theme {
  const saved = localStorage.getItem("securemail-theme");
  if (saved === "dark" || saved === "light") return saved;
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

function case_label(item: CaseSummary): string {
  const title = item.title?.trim();
  return title && title.length > 0 ? title : item.case_id;
}

function is_capture_file(file: File): boolean {
  const name = file.name.toLocaleLowerCase();
  return name.endsWith(".pcap") || name.endsWith(".pcapng");
}

export default function App() {
  const query_client = useQueryClient();
  const [theme, set_theme] = useState<Theme>(initial_theme);
  const [view_mode, set_view_mode] = useState<ViewMode>("case");
  const [sidebar_open, set_sidebar_open] = useState(false);
  const [selected_case_id, set_selected_case_id] = useState<string | null>(null);
  const [active_run, set_active_run] = useState<AnalysisJob | null>(null);
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
  const analysis_query = useQuery({
    queryKey: ["analysis", active_run?.run_id],
    queryFn: ({ signal }) => {
      if (active_run === null) throw new Error("No analysis selected.");
      return get_analysis({ run_id: active_run.run_id, signal });
    },
    enabled: active_run !== null && (active_run.status === "queued" || active_run.status === "running"),
    refetchInterval: 1000,
    retry: false,
  });
  const live_run = analysis_query.data ?? active_run;
  const completed_run_id = live_run?.status === "completed" ? live_run.run_id : null;
  const analysis_report_query = useQuery({
    queryKey: ["analysis-report", completed_run_id],
    queryFn: ({ signal }) => {
      if (completed_run_id === null) throw new Error("No analysis report.");
      return get_analysis_report({ run_id: completed_run_id, signal });
    },
    enabled: completed_run_id !== null,
    retry: false,
    staleTime: 0,
  });
  const report_query = useQuery({
    queryKey: ["case-report", selected_case_id],
    queryFn: ({ signal }) => {
      if (selected_case_id === null) throw new Error("No case selected.");
      return get_case_report({ case_id: selected_case_id, signal });
    },
    enabled: selected_case_id !== null && completed_run_id === null,
    retry: false,
    staleTime: 0,
  });
  const visible_report: CanonicalReport | null =
    analysis_report_query.data ?? report_query.data ?? null;
  const selected_label = selected_case_id;

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  useEffect(() => {
    if (!sidebar_open) return;
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    function on_key(event: KeyboardEvent): void {
      if (event.key === "Escape") set_sidebar_open(false);
    }
    window.addEventListener("keydown", on_key);
    return () => {
      document.body.style.overflow = previous;
      window.removeEventListener("keydown", on_key);
    };
  }, [sidebar_open]);

  useEffect(() => {
    if (!analysis_query.data) return;
    set_active_run(analysis_query.data);
    if (analysis_query.data.status === "completed") {
      set_selected_case_id(analysis_query.data.case_id);
      void query_client.invalidateQueries({ queryKey: ["cases"] });
    }
  }, [analysis_query.data, query_client]);

  function apply_theme(next_theme: Theme): void {
    document.documentElement.dataset.theme = next_theme;
    localStorage.setItem("securemail-theme", next_theme);
    set_theme(next_theme);
  }

  function select_case(case_id: string): void {
    set_active_run(null);
    set_upload_error(null);
    set_selected_case_id(case_id || null);
    if (case_id) set_view_mode("case");
    set_sidebar_open(false);
  }

  function clear_selection(): void {
    set_selected_case_id(null);
    set_active_run(null);
    set_upload_error(null);
    query_client.removeQueries({ queryKey: ["case-report"] });
    query_client.removeQueries({ queryKey: ["analysis"] });
    query_client.removeQueries({ queryKey: ["analysis-report"] });
  }

  async function upload_file(file: File): Promise<void> {
    if (!is_capture_file(file)) {
      set_upload_error("Choose a .pcap or .pcapng capture.");
      return;
    }
    set_is_uploading(true);
    set_upload_error(null);
    set_selected_case_id(null);
    query_client.removeQueries({ queryKey: ["case-report"] });
    try {
      const job = await create_analysis({ file });
      set_active_run(job);
      set_view_mode("case");
    } catch (error) {
      set_active_run(null);
      set_upload_error(error instanceof Error ? error.message : "Capture upload failed.");
    } finally {
      set_is_uploading(false);
    }
  }

  const in_progress_job =
    live_run !== null && (live_run.status === "queued" || live_run.status === "running")
      ? live_run
      : null;

  return (
    <div className="min-h-screen bg-[var(--background)] text-[var(--text)]">
      <header className="sticky top-0 z-30 border-b border-[var(--border)] bg-[color:var(--background-alpha)] backdrop-blur-xl">
        <div className="mx-auto flex max-w-[1680px] items-center gap-3 px-4 py-3 sm:px-6">
          <Button
            aria-label="Open navigation"
            className="lg:hidden"
            onClick={() => set_sidebar_open(true)}
            variant="secondary"
          >
            <Menu size={16} />
          </Button>
          <div className="flex min-w-0 items-center gap-3">
            <div className="grid size-9 place-items-center rounded-xl border border-cyan-500/25 bg-cyan-500/10 text-cyan-400">
              <ShieldCheck aria-hidden size={19} />
            </div>
            <div className="min-w-0">
              <p className="truncate text-sm font-semibold tracking-tight">SecureMail</p>
              <p className="truncate text-[10px] uppercase tracking-[0.16em] text-[var(--muted)]">
                Offline capture analysis
              </p>
            </div>
          </div>
          <div
            aria-label={health_query.isSuccess ? "API online" : "API unavailable"}
            className="ml-auto hidden items-center gap-2 text-[10px] uppercase tracking-wider text-[var(--muted)] md:flex"
          >
            <span className={`size-1.5 rounded-full ${health_query.isSuccess ? "bg-emerald-400" : "bg-slate-500"}`} />
            {health_query.isSuccess ? "API online" : "API unavailable"}
          </div>
          <nav aria-label="Primary" className="flex items-center rounded-lg border border-[var(--border)] bg-[var(--surface)] p-1">
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

      <div className="mx-auto grid max-w-[1680px] lg:grid-cols-[300px_minmax(0,1fr)]">
        {sidebar_open ? (
          <button
            aria-label="Close navigation"
            className="fixed inset-0 z-40 bg-slate-950/55 lg:hidden"
            onClick={() => set_sidebar_open(false)}
            type="button"
          />
        ) : null}
        <aside
          className={`border-b border-[var(--border)] bg-[var(--sidebar)] p-4 lg:min-h-[calc(100vh-65px)] lg:border-b-0 lg:border-r lg:p-5 ${
            sidebar_open ? "fixed inset-y-0 left-0 z-50 w-[min(100%,20rem)] overflow-y-auto shadow-2xl lg:static lg:z-0 lg:w-auto lg:shadow-none" : "hidden lg:block"
          }`}
        >
          <div className="mb-4 flex items-center justify-between lg:hidden">
            <p className="text-sm font-semibold">Navigation</p>
            <Button aria-label="Close navigation" onClick={() => set_sidebar_open(false)} variant="ghost">
              <X size={16} />
            </Button>
          </div>
          <CasePicker
            cases={cases_query.data?.cases ?? []}
            error={cases_query.isError ? "Catalog unavailable" : null}
            on_select={select_case}
            selected_case_id={selected_case_id}
          />
          <div className="my-4 flex items-center gap-3 text-[10px] uppercase tracking-widest text-[var(--muted)]">
            <span className="h-px flex-1 bg-[var(--border)]" /> or <span className="h-px flex-1 bg-[var(--border)]" />
          </div>
          <CaptureDropzone error={upload_error} is_uploading={is_uploading} on_upload={upload_file} />
          {selected_label || live_run ? (
            <div className="mt-4 rounded-lg border border-[var(--border)] bg-[var(--surface)] p-3">
              <p className="text-[10px] uppercase tracking-wider text-[var(--muted)]">Active case</p>
              <p className="forensic-text mt-1 truncate text-sm font-medium">
                {render_forensic_text(selected_label ?? live_run?.case_id ?? "")}
              </p>
              <Button className="mt-3 w-full" onClick={clear_selection} variant="secondary">
                <X size={14} /> Clear case
              </Button>
            </div>
          ) : null}
          <p className="mt-4 text-xs leading-5 text-[var(--muted)]">
            Captures stay on this host. Analyzers run with no network. Advisory ML never changes findings.
          </p>
        </aside>

        <main className="min-w-0 p-4 sm:p-6 lg:p-8">
          {view_mode === "portfolio" ? (
            <PortfolioView
              cases={cases_query.data?.cases ?? []}
              is_loading={cases_query.isLoading}
              on_select={select_case}
            />
          ) : in_progress_job ? (
            <RunProgress
              job={in_progress_job}
              on_cancel={async () => {
                const updated = await cancel_analysis({ run_id: in_progress_job.run_id });
                set_active_run(updated);
              }}
            />
          ) : live_run?.status === "failed" ? (
            <EmptyState description={live_run.error_message ?? "Analysis failed."} title="Analysis failed">
              <Button onClick={clear_selection} variant="secondary">
                Return to no case selected
              </Button>
            </EmptyState>
          ) : live_run?.status === "cancelled" ? (
            <EmptyState description="The capture job was cancelled before publication." title="Analysis cancelled">
              <Button onClick={clear_selection} variant="secondary">
                Return to no case selected
              </Button>
            </EmptyState>
          ) : visible_report ? (
            <CaseView
              key={selected_label ?? live_run?.run_id ?? "uploaded"}
              report={visible_report}
              run_id={completed_run_id}
            />
          ) : report_query.isLoading || analysis_report_query.isLoading ? (
            <LoadingState />
          ) : report_query.isError ? (
            <EmptyState description={report_query.error.message} title="Case report unavailable">
              <Button onClick={clear_selection} variant="secondary">
                Return to no case selected
              </Button>
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

function CaptureDropzone({
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
    const file = event.dataTransfer.files[0];
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
          accept=".pcap,.pcapng,application/vnd.tcpdump.pcap"
          aria-label="Upload capture"
          className="sr-only"
          disabled={is_uploading}
          onChange={(event) => {
            const file = event.target.files?.[0];
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
            {is_uploading ? "Uploading capture…" : "Drop PCAP / PCAPNG"}
          </span>
          <span className="mt-1 block text-xs text-[var(--muted)]">offline analysis · HTML and PDF reports</span>
        </span>
      </label>
      {error ? (
        <p className="mt-2 text-xs text-red-400" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

function RunProgress({ job, on_cancel }: { job: AnalysisJob; on_cancel: () => Promise<void> }) {
  const current = STAGES.indexOf(job.stage as (typeof STAGES)[number]);
  return (
    <section aria-label="Analysis progress">
      <p className="section-label">Capture pipeline</p>
      <h1 className="mt-2 text-2xl font-semibold tracking-tight">Analyzing capture</h1>
      <p className="forensic-text mt-2 text-sm text-[var(--muted)]">
        {render_forensic_text(job.original_filename)} · {job.status}
      </p>
      <Card className="mt-6 space-y-3 p-5">
        {STAGES.map((stage, index) => {
          const done = current > index || job.status === "completed";
          const active = current === index && job.status === "running";
          return (
            <div className="flex items-center gap-3" key={stage}>
              <span
                className={`size-2.5 rounded-full ${
                  done ? "bg-emerald-400" : active ? "bg-cyan-400" : "bg-slate-600"
                }`}
              />
              <span className="text-sm capitalize">{stage.replaceAll("_", " ")}</span>
            </div>
          );
        })}
      </Card>
      <Button className="mt-4" onClick={() => void on_cancel()} variant="danger">
        Cancel analysis
      </Button>
    </section>
  );
}

function NoCaseState() {
  return (
    <div data-testid="no-case-selected">
      <EmptyState
        description="Upload a PCAP/PCAPNG capture or choose a catalog case. Analysis stays on this host and does not run until you select a file or case."
        title="No case selected"
      >
        <div className="flex items-center gap-2 text-xs text-[var(--muted)]">
          <Upload size={15} /> PCAP/PCAPNG · sandboxed Zeek/TShark
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
          <h1 className="mt-2 text-2xl font-semibold tracking-tight" id="portfolio-title">
            Cases
          </h1>
          <p className="mt-2 text-sm text-[var(--muted)]">
            Compare published posture summaries without loading case evidence.
          </p>
        </div>
        <div className="flex gap-2">
          <input
            aria-label="Filter portfolio"
            className="control"
            onChange={(event) => set_search(event.target.value)}
            placeholder="Filter cases"
            type="search"
            value={search}
          />
          <select
            aria-label="Filter assessment state"
            className="control"
            onChange={(event) => set_assessment(event.target.value)}
            value={assessment}
          >
            <option value="">All states</option>
            <option value="complete">Complete</option>
            <option value="limited">Limited</option>
            <option value="none">None</option>
          </select>
        </div>
      </div>
      {is_loading ? (
        <LoadingState />
      ) : filtered_cases.length === 0 ? (
        <EmptyState description="No catalog cases match the current portfolio filters." title="No matching cases" />
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {filtered_cases.map((item) => (
            <Card className="p-5" data-testid="portfolio-case" key={item.case_id}>
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <h2 className="forensic-text truncate font-semibold">{render_forensic_text(case_label(item))}</h2>
                  <p className="forensic-text mt-1 truncate font-mono text-[10px] text-[var(--muted)]">
                    {render_forensic_text(item.case_id)}
                  </p>
                </div>
                <Badge tone={item.assessment_state === "complete" ? "success" : "unknown"}>
                  {item.assessment_state ?? "unknown"}
                </Badge>
              </div>
              <div className="mt-5 grid grid-cols-3 gap-2">
                <PortfolioMetric label="Risk" value={item.risk_score ?? "—"} />
                <PortfolioMetric label="Findings" value={item.finding_count ?? "—"} />
                <PortfolioMetric
                  label="Unknown"
                  value={(item.unknown_count ?? 0) + (item.not_observable_count ?? 0)}
                />
              </div>
              <Button className="mt-5 w-full" onClick={() => on_select(item.case_id)} variant="secondary">
                Open case
              </Button>
            </Card>
          ))}
        </div>
      )}
    </section>
  );
}

function PortfolioMetric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-lg bg-[var(--surface-raised)] p-2">
      <p className="text-[10px] uppercase text-[var(--muted)]">{label}</p>
      <p className="mt-1 font-mono font-semibold">{value}</p>
    </div>
  );
}
