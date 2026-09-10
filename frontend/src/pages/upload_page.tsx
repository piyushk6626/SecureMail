import { useEffect, useState, type DragEvent } from "react";
import { Link, useNavigate } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, Upload } from "lucide-react";
import { cancel_analysis, create_analysis, get_analysis } from "../core/api";
import type { AnalysisJob } from "../core/model";
import { render_forensic_text } from "../core/forensic_text";
import { Button, Card, EmptyState } from "../components/ui";

const STAGES = [
  "intake",
  "deterministic_analysis",
  "policy_scoring",
  "ml_advisory",
  "report_rendering",
  "publication",
] as const;

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
    <section aria-labelledby="upload-title">
      <p className="section-label">Capture intake</p>
      <h1 className="mt-2 text-2xl font-semibold tracking-tight" id="upload-title">
        Upload a capture
      </h1>
      <p className="mt-2 max-w-2xl text-sm text-[var(--muted)]">
        Drop a .pcap or .pcapng file. Analysis stays on this host. Analyzers run with no network. Advisory ML never
        changes findings.
      </p>
      <div className="mt-6 max-w-xl">
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
        className="group grid min-h-48 cursor-pointer place-items-center rounded-xl border border-dashed border-[var(--border-strong)] bg-[var(--surface)] p-6 text-center transition-colors hover:border-cyan-500/60 hover:bg-cyan-500/5 focus-within:outline-2 focus-within:outline-cyan-400"
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
              <span className={`size-2.5 rounded-full ${done ? "bg-emerald-400" : active ? "bg-cyan-400" : "bg-slate-600"}`} />
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
