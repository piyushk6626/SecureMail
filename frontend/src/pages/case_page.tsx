import { Link, Navigate, useParams, useSearchParams } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { get_analysis, get_analysis_report, get_case_report } from "../core/api";
import { CaseView } from "../components/case_view";
import { EmptyState, LoadingState } from "../components/ui";

export function CasePage() {
  const query_client = useQueryClient();
  const { case_id } = useParams();
  const [params] = useSearchParams();
  const run_id = params.get("run");

  const analysis_report_query = useQuery({
    queryKey: ["analysis-report", run_id],
    queryFn: ({ signal }) => {
      if (run_id === null) throw new Error("No analysis report.");
      return get_analysis_report({ run_id, signal });
    },
    enabled: run_id !== null,
    retry: false,
    staleTime: 0,
  });
  const report_query = useQuery({
    queryKey: ["case-report", case_id],
    queryFn: ({ signal }) => {
      if (!case_id) throw new Error("No case selected.");
      return get_case_report({ case_id, signal });
    },
    enabled: Boolean(case_id) && run_id === null,
    retry: false,
    staleTime: 0,
  });
  const analysis_query = useQuery({
    queryKey: ["analysis", run_id],
    queryFn: ({ signal }) => {
      if (run_id === null) throw new Error("No analysis job.");
      return get_analysis({ run_id, signal });
    },
    enabled: run_id !== null,
    retry: false,
    staleTime: 0,
  });

  if (!case_id) return <Navigate replace to="/cases" />;

  const report = analysis_report_query.data ?? report_query.data ?? null;
  const is_loading = analysis_report_query.isLoading || report_query.isLoading;
  const error_message = analysis_report_query.error?.message ?? report_query.error?.message;

  function clear_selection(): void {
    query_client.removeQueries({ queryKey: ["case-report"] });
    query_client.removeQueries({ queryKey: ["analysis"] });
    query_client.removeQueries({ queryKey: ["analysis-report"] });
  }

  return (
    <div className="space-y-4">
      <Link
        className="inline-flex min-h-9 items-center text-sm font-semibold text-[var(--muted)] hover:text-[var(--text)]"
        onClick={clear_selection}
        to="/cases"
      >
        Back to catalog
      </Link>
      {is_loading ? (
        <LoadingState />
      ) : report ? (
        <CaseView key={`${case_id}-${report.manifest.generated_at}`} original_filename={analysis_query.data?.original_filename} report={report} run_id={run_id} />
      ) : (
        <EmptyState description={error_message ?? "The selected case has no report."} title="Case report unavailable">
          <Link
            className="inline-flex min-h-9 items-center justify-center rounded-md border border-[var(--border)] bg-[var(--surface)] px-3 text-sm font-semibold text-[var(--text)] hover:bg-[var(--surface-raised)]"
            onClick={clear_selection}
            to="/cases"
          >
            Return to catalog
          </Link>
        </EmptyState>
      )}
    </div>
  );
}
