import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router";
import { get_cases } from "../core/api";
import { case_label, type CaseSummary } from "../core/model";
import { render_forensic_text } from "../core/forensic_text";
import { Badge, Button, Card, EmptyState, LoadingState } from "../components/ui";

export function CatalogPage() {
  const navigate = useNavigate();
  const cases_query = useQuery({
    queryKey: ["cases"],
    queryFn: ({ signal }) => get_cases({ signal }),
    retry: 1,
  });
  const [search, set_search] = useState("");
  const [assessment, set_assessment] = useState("");
  const cases = cases_query.data?.cases ?? [];
  const filtered_cases = useMemo(() => {
    const catalog = cases_query.data?.cases ?? [];
    return catalog
      .filter((item) => {
        if (assessment && item.assessment_state !== assessment) return false;
        const haystack = `${case_label(item)} ${item.case_id}`.toLocaleLowerCase();
        return haystack.includes(search.trim().toLocaleLowerCase());
      })
      .sort(
        (left, right) =>
          (right.risk_score ?? -1) - (left.risk_score ?? -1) ||
          (right.unknown_count ?? 0) + (right.not_observable_count ?? 0) -
            ((left.unknown_count ?? 0) + (left.not_observable_count ?? 0)),
      );
  }, [assessment, cases_query.data, search]);
  const scored_cases = cases.filter((item) => item.risk_score !== null && item.risk_score !== undefined);
  const average_risk =
    scored_cases.length > 0
      ? Math.round(scored_cases.reduce((sum, item) => sum + (item.risk_score ?? 0), 0) / scored_cases.length)
      : null;
  const urgent_cases = cases.filter((item) => (item.risk_score ?? 0) >= 80).length;
  const unresolved = cases.reduce(
    (sum, item) => sum + (item.unknown_count ?? 0) + (item.not_observable_count ?? 0),
    0,
  );

  return (
    <section aria-labelledby="catalog-title" data-testid="no-case-selected">
      <div className="mb-6 flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <p className="section-label">Published catalog</p>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight" id="catalog-title">
            Cases
          </h1>
          <p className="mt-2 text-sm text-[var(--muted)]">
            Highest-risk cases are ordered first. Open one to inspect its evidence and control failures.
          </p>
        </div>
        <div className="flex gap-2">
          <input
            aria-label="Filter catalog"
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
      <div className="mb-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <CatalogSummary label="Published cases" value={cases.length} />
        <CatalogSummary label="Immediate attention" tone="danger" value={urgent_cases} />
        <CatalogSummary label="Average risk" tone="warning" value={average_risk ?? "—"} />
        <CatalogSummary label="Unresolved checks" tone="unknown" value={unresolved} />
      </div>
      {cases_query.isLoading ? (
        <LoadingState />
      ) : cases_query.isError ? (
        <EmptyState description="The report catalog could not be loaded." title="Catalog unavailable" />
      ) : filtered_cases.length === 0 ? (
        <EmptyState
          description="Upload a PCAP/PCAPNG capture or wait for a published catalog case. Analysis stays on this host."
          title="No matching cases"
        />
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {filtered_cases.map((item) => (
            <CatalogCard
              item={item}
              key={item.case_id}
              on_open={() => void navigate(`/cases/${encodeURIComponent(item.case_id)}`)}
            />
          ))}
        </div>
      )}
    </section>
  );
}

function CatalogCard({ item, on_open }: { item: CaseSummary; on_open: () => void }) {
  return (
    <Card className="portfolio-case-card p-5" data-testid="catalog-case">
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
        <CatalogMetric label="Risk" value={item.risk_score ?? "—"} />
        <CatalogMetric label="Findings" value={item.finding_count ?? "—"} />
        <CatalogMetric label="Unknown" value={(item.unknown_count ?? 0) + (item.not_observable_count ?? 0)} />
      </div>
      <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-[var(--surface-raised)]" aria-hidden="true">
        <div
          className={`h-full rounded-full ${
            (item.risk_score ?? 0) >= 80 ? "bg-red-400" : (item.risk_score ?? 0) >= 50 ? "bg-amber-400" : "bg-emerald-400"
          }`}
          style={{ width: `${Math.max(0, Math.min(100, item.risk_score ?? 0))}%` }}
        />
      </div>
      <Button aria-label="Open case" className="mt-5 w-full" onClick={on_open} variant="secondary">
        Open case intelligence
      </Button>
    </Card>
  );
}

function CatalogSummary({
  label,
  tone = "info",
  value,
}: {
  label: string;
  tone?: "info" | "danger" | "warning" | "unknown";
  value: string | number;
}) {
  const colors = {
    info: "text-cyan-400",
    danger: "text-red-400",
    warning: "text-amber-400",
    unknown: "text-violet-300",
  };
  return (
    <Card className="p-4">
      <p className="text-xs text-[var(--muted)]">{label}</p>
      <p className={`mt-2 font-mono text-2xl font-semibold ${colors[tone]}`}>{value}</p>
    </Card>
  );
}

function CatalogMetric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-lg bg-[var(--surface-raised)] p-2">
      <p className="text-[10px] uppercase text-[var(--muted)]">{label}</p>
      <p className="mt-1 font-mono font-semibold">{value}</p>
    </div>
  );
}
