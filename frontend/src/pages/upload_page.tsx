import { memo, useEffect, useState, type DragEvent } from "react";
import { Link, useNavigate } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, Upload } from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { cancel_analysis, create_analysis, get_analysis } from "../core/api";
import type { AnalysisJob } from "../core/model";
import { render_forensic_text } from "../core/forensic_text";
import { Button, Card, EmptyState } from "../components/ui";

type AnalysisStage =
  | "intake"
  | "deterministic_analysis"
  | "policy_scoring"
  | "ml_advisory"
  | "report_rendering"
  | "publication";

interface StagePresentation {
  id: AnalysisStage;
  label: string;
  active_title: string;
  supporting_copy: string;
}

const STAGES = [
  {
    id: "intake",
    label: "Capture intake",
    active_title: "Preparing capture analysis",
    supporting_copy: "The local worker is preparing the accepted capture for offline analysis.",
  },
  {
    id: "deterministic_analysis",
    label: "Deterministic analysis",
    active_title: "Examining protocol and TLS evidence",
    supporting_copy: "Zeek is analyzing the capture in a network-disabled worker.",
  },
  {
    id: "policy_scoring",
    label: "Assemble report",
    active_title: "Assembling the deterministic report",
    supporting_copy: "Normalized evidence and scored findings are being wrapped in the canonical report.",
  },
  {
    id: "ml_advisory",
    label: "Advisory evaluation",
    active_title: "Evaluating advisory signals",
    supporting_copy: "Advisory analysis remains separate and cannot change deterministic findings.",
  },
  {
    id: "report_rendering",
    label: "Report rendering",
    active_title: "Rendering report artifacts",
    supporting_copy: "The same canonical report is being rendered as JSON, HTML, and PDF.",
  },
  {
    id: "publication",
    label: "Publication",
    active_title: "Publishing the local report",
    supporting_copy: "Report artifacts are being committed to the local catalog.",
  },
] as const satisfies readonly StagePresentation[];

type StageState = "queued" | "active" | "complete" | "pending";

function stage_presentation(stage: string): StagePresentation {
  return STAGES.find((item) => item.id === stage) ?? STAGES[0];
}

function stage_state(job: AnalysisJob, index: number, current_index: number): StageState {
  if (job.status === "queued") return index === current_index ? "queued" : "pending";
  if (index < current_index) return "complete";
  if (index === current_index) return "active";
  return "pending";
}

function elapsed_time(created_at: string, now: number): string {
  const created = Date.parse(created_at);
  const elapsed_seconds = Number.isNaN(created) ? 0 : Math.max(0, Math.floor((now - created) / 1000));
  const minutes = Math.floor(elapsed_seconds / 60);
  const seconds = elapsed_seconds % 60;
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

function useElapsedTime(created_at: string): string {
  const [now, set_now] = useState(() => Date.now());

  useEffect(() => {
    set_now(Date.now());
    const timer = window.setInterval(() => set_now(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [created_at]);

  return elapsed_time(created_at, now);
}

function is_capture_file(file: File): boolean {
  const name = file.name.toLocaleLowerCase();
  return name.endsWith(".pcap") || name.endsWith(".pcapng");
}

export function UploadPage() {
  const navigate = useNavigate();
  const query_client = useQueryClient();
  const [active_run, set_active_run] = useState<AnalysisJob | null>(null);
  const [upload_error, set_upload_error] = useState<string | null>(null);
  const [is_uploading, set_is_uploading] = useState(false);
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
  const in_progress_job =
    live_run !== null && (live_run.status === "queued" || live_run.status === "running") ? live_run : null;

  useEffect(() => {
    if (analysis_query.data) set_active_run(analysis_query.data);
  }, [analysis_query.data]);

  useEffect(() => {
    if (live_run?.status !== "completed") return;
    void query_client.invalidateQueries({ queryKey: ["cases"] });
    void navigate(
      `/cases/${encodeURIComponent(live_run.case_id)}?run=${encodeURIComponent(live_run.run_id)}`,
      { replace: true },
    );
  }, [live_run, navigate, query_client]);

  async function upload_file(file: File): Promise<void> {
    if (!is_capture_file(file)) {
      set_upload_error("Choose a .pcap or .pcapng capture.");
      return;
    }
    set_is_uploading(true);
    set_upload_error(null);
    query_client.removeQueries({ queryKey: ["case-report"] });
    query_client.removeQueries({ queryKey: ["analysis"] });
    query_client.removeQueries({ queryKey: ["analysis-report"] });
    try {
      const job = await create_analysis({ file });
      set_active_run(job);
    } catch (error) {
      set_active_run(null);
      set_upload_error(error instanceof Error ? error.message : "Capture upload failed.");
    } finally {
      set_is_uploading(false);
    }
  }

  function reset_upload(): void {
    set_active_run(null);
    set_upload_error(null);
    query_client.removeQueries({ queryKey: ["analysis"] });
    query_client.removeQueries({ queryKey: ["analysis-report"] });
  }

  if (in_progress_job) {
    return (
      <RunProgress
        job={in_progress_job}
        on_cancel={async () => {
          const updated = await cancel_analysis({ run_id: in_progress_job.run_id });
          set_active_run(updated);
        }}
      />
    );
  }
  if (live_run?.status === "failed") {
    return (
      <EmptyState description={live_run.error_message ?? "Analysis failed."} title="Analysis failed">
        <Button onClick={reset_upload} variant="secondary">
          Return to upload
        </Button>
      </EmptyState>
    );
  }
  if (live_run?.status === "cancelled") {
    return (
      <EmptyState description="The capture job was cancelled before publication." title="Analysis cancelled">
        <Button onClick={reset_upload} variant="secondary">
          Return to upload
        </Button>
      </EmptyState>
    );
  }

  return (
    <section aria-labelledby="upload-title" className="intake-sheet">
      <header>
      <p className="section-label">01 Capture intake</p>
      <h1 className="mt-2 text-2xl font-semibold tracking-tight" id="upload-title">
        Upload a capture
      </h1>
      <p className="mt-2 max-w-2xl text-sm text-[var(--muted)]">
        Drop a .pcap or .pcapng file. Analysis stays on this host. Analyzers run with no network. Advisory ML never
        changes findings.
      </p>
      </header>
      <div className="mt-6">
        <CaptureDropzone error={upload_error} is_uploading={is_uploading} on_upload={upload_file} />
      </div>
      <p className="mt-6 text-sm text-[var(--muted)]">
        <Link className="font-semibold text-cyan-400 hover:text-cyan-300" to="/cases">
          Back to catalog
        </Link>
      </p>
    </section>
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
        className="intake-dropzone group cursor-pointer p-6 transition-colors hover:border-[var(--accent)] focus-within:outline-2 focus-within:outline-[var(--accent)]"
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
          <span className="upload-mark block">
            {is_uploading ? <Activity className="animate-pulse" size={17} /> : <Upload size={17} />}
          </span>
          <span className="mt-3 block text-sm font-medium text-[var(--text)]">
            {is_uploading ? "Uploading capture…" : "Drop PCAP / PCAPNG"}
          </span>
          <span className="mt-1 block text-xs text-[var(--muted)]">offline analysis · HTML and PDF reports · or choose a file</span>
        </span>
      </label>
      {error ? (
        <p className="intake-error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

function RunProgress({ job, on_cancel }: { job: AnalysisJob; on_cancel: () => Promise<void> }) {
  const reduced_motion = useReducedMotion();
  const [is_cancelling, set_is_cancelling] = useState(false);
  const stage = stage_presentation(job.stage);
  const current = STAGES.findIndex((item) => item.id === stage.id);
  const is_queued = job.status === "queued";
  const cancellation_requested = job.cancel_requested;
  const operation_title = is_queued ? "Waiting for the local worker" : stage.active_title;
  const supporting_copy = is_queued
    ? "Capture accepted, hashed, and queued for offline analysis."
    : stage.supporting_copy;
  const phase_key = `${job.status}:${stage.id}:${cancellation_requested ? "cancellation-requested" : "normal"}`;
  const elapsed = useElapsedTime(job.created_at);

  async function request_cancel(): Promise<void> {
    if (is_cancelling || cancellation_requested) return;
    set_is_cancelling(true);
    try {
      await on_cancel();
    } finally {
      set_is_cancelling(false);
    }
  }

  return (
    <section aria-label="Analysis progress" className="intake-sheet">
      <div className="analysis-progress-heading">
        <p className="section-label">Capture pipeline</p>
        <p aria-label={`Elapsed time ${elapsed}`} className="analysis-elapsed">
          <span>Elapsed</span> {elapsed}
        </p>
      </div>
      <h1 className="mt-2 text-2xl font-semibold tracking-tight">Analyzing capture</h1>
      <p className="analysis-filename forensic-text mt-2 text-sm text-[var(--muted)]">
        {render_forensic_text(job.original_filename)}
      </p>
      <Card className="analysis-ledger mt-6">
        <div className="analysis-operation">
          <div className="analysis-operation-meta">
            <span>Active operation</span>
            <span>{String(current + 1).padStart(2, "0")} / {String(STAGES.length).padStart(2, "0")}</span>
          </div>
          <PhaseAnnouncement
            cancellation_requested={cancellation_requested}
            phase_key={phase_key}
            status={job.status}
            supporting_copy={supporting_copy}
            title={operation_title}
            reduced_motion={reduced_motion}
          />
          {!cancellation_requested ? <span aria-hidden className="analysis-tracer" /> : null}
        </div>
        <ol className="analysis-stages">
          {STAGES.map((item, index) => {
            const state = stage_state(job, index, current);
            const is_current = index === current;
            return (
              <li
                aria-current={is_current ? "step" : undefined}
                className={`analysis-stage analysis-stage-${state}`}
                key={item.id}
              >
                {state === "active" ? (
                  <motion.span
                    aria-hidden
                    className="analysis-active-rail"
                    layoutId="analysis-active-rail"
                    transition={reduced_motion ? { duration: 0 } : { duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
                  />
                ) : null}
                <span aria-hidden className="analysis-stage-index">{String(index + 1).padStart(2, "0")}</span>
                <motion.span
                  aria-hidden
                  className="analysis-stage-marker"
                  layout
                  transition={reduced_motion ? { duration: 0 } : { duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
                >
                  {state === "complete" ? "✓" : null}
                </motion.span>
                <span className="analysis-stage-label">{item.label}</span>
                <span className="analysis-stage-status">
                  {state === "complete" ? "Complete" : state === "active" ? "In progress" : state === "queued" ? "Queued" : "Pending"}
                </span>
              </li>
            );
          })}
        </ol>
      </Card>
      {cancellation_requested ? (
        <p className="analysis-cancellation-state" role="status">Cancellation requested…</p>
      ) : null}
      <Button
        aria-busy={is_cancelling || undefined}
        className="analysis-cancel mt-4"
        disabled={is_cancelling || cancellation_requested}
        onClick={() => void request_cancel()}
        variant="danger"
      >
        {is_cancelling ? "Requesting cancellation…" : cancellation_requested ? "Cancellation requested…" : "Cancel analysis"}
      </Button>
    </section>
  );
}

const PhaseAnnouncement = memo(function PhaseAnnouncement({
  cancellation_requested,
  phase_key,
  reduced_motion,
  status,
  supporting_copy,
  title,
}: {
  cancellation_requested: boolean;
  phase_key: string;
  reduced_motion: boolean | null;
  status: AnalysisJob["status"];
  supporting_copy: string;
  title: string;
}) {
  const transition = reduced_motion
    ? { duration: 0.1 }
    : { duration: 0.2, ease: [0.22, 1, 0.36, 1] as const };
  const movement = reduced_motion ? {} : { opacity: 0, y: 4 };

  return (
    <div aria-atomic="true" aria-live="polite" className="analysis-operation-status" role="status">
      <AnimatePresence initial={false} mode="wait">
        <motion.div
          animate={{ opacity: 1, y: 0 }}
          exit={movement}
          initial={movement}
          key={phase_key}
          transition={transition}
        >
          <h2>{title}</h2>
          <p>{supporting_copy}</p>
          <span className="analysis-job-status">
            {cancellation_requested ? "Cancellation requested" : status}
          </span>
        </motion.div>
      </AnimatePresence>
    </div>
  );
});
