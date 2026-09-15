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
          Number(right.risk_score !== null && right.risk_score !== undefined) -
            Number(left.risk_score !== null && left.risk_score !== undefined) ||
          (right.risk_score ?? -1) - (left.risk_score ?? -1) ||
          (right.unknown_count ?? 0) + (right.not_observable_count ?? 0) -
            ((left.unknown_count ?? 0) + (left.not_observable_count ?? 0)) ||
          Date.parse(right.generated_at ?? "") - Date.parse(left.generated_at ?? "") ||
          left.case_id.localeCompare(right.case_id),
      );
  }, [assessment, cases_query.data, search]);
  const urgent_cases = cases.filter((item) => (item.risk_score ?? 0) >= 80).length;
  const not_proven = cases.filter((item) => item.risk_score === null || item.risk_score === undefined).length;

  return (
    <section aria-labelledby="catalog-title" data-testid="no-case-selected">
      <div className="mb-6 flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <p className="section-label">Published catalog</p>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight" id="catalog-title">
            Cases
          </h1>
          <p className="mt-2 text-sm text-[var(--muted)]">
            Highest endpoint priority is ordered first. It is not a mail-system health score.
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
      <div className="catalog-summary-line" aria-label="Catalog summary">
        <CatalogSummary label="Published cases" value={cases.length} />
        <CatalogSummary label="Immediate attention" tone="danger" value={urgent_cases} />
        <CatalogSummary label="Not proven" tone="unknown" value={not_proven} />
        <CatalogSummary label="Catalog order" tone="info" value="Priority first" />
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
        <div className="catalog-docket">
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
    <Card className="portfolio-case-card" data-testid="catalog-case">
      <div className="catalog-priority" data-urgent={(item.risk_score ?? 0) >= 80}>{item.risk_score ?? "Not proven"}</div>
      <div className="min-w-0">
        <h2 className="forensic-text truncate font-semibold">{render_forensic_text(case_label(item))}</h2>
        <p className="catalog-case-id forensic-text mt-1">{render_forensic_text(item.case_id)}</p>
        <p className="catalog-case-metadata mt-1">{item.generated_at ? new Date(item.generated_at).toLocaleString() : "Generated time unavailable"} · findings {item.finding_count ?? "—"}</p>
      </div>
      <div><Badge tone={item.assessment_state === "limited" ? "warning" : item.assessment_state === "none" ? "unknown" : "info"}>{item.assessment_state ?? "unknown"}</Badge><p className="catalog-case-metadata mt-2">Highest endpoint priority</p></div>
      <div className="catalog-severity" aria-label="Severity counts">{(["high", "medium", "low", "informational"] as const).map((severity) => <Badge className="normal-case" key={severity} tone={severity === "high" ? "danger" : severity === "medium" ? "warning" : severity === "low" ? "info" : "neutral"}>{severity === "informational" ? "I" : severity.charAt(0).toUpperCase()} {item.severity_counts?.[severity] ?? 0}</Badge>)}{item.advisory_present ? <Badge tone="unknown">Advisory</Badge> : null}</div>
      <div className="catalog-counts"><span><strong>U</strong> {item.unknown_count ?? 0} unknown</span><span><strong>O</strong> {item.not_observable_count ?? 0} not observable</span></div>
      <Button aria-label="Open case" className="catalog-open" onClick={on_open} variant="secondary">
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
  return (
    <div>
      <p className="text-xs text-[var(--muted)]">{label}</p>
      <b className={`catalog-summary-${tone}`}>{value}</b>
    </div>
  );
}
