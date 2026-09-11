import { useMemo, useState } from "react";
import {
  createColumnHelper,
  createPaginatedRowModel,
  createSortedRowModel,
  rowPaginationFeature,
  rowSortingFeature,
  tableFeatures,
  useTable,
  type SortingState,
} from "@tanstack/react-table";
import { ChevronDown, ChevronLeft, ChevronRight, ChevronUp, Search } from "lucide-react";
import type { CanonicalReport, EvidenceState, FindingSeverity } from "../core/model";
import {
  filter_findings,
  select_findings,
  select_protocols,
  type FindingFilters,
  type FindingRow,
} from "../core/selectors";
import { render_forensic_text } from "../core/forensic_text";
import { Badge, Button, Card, EmptyState, Input } from "./ui";

const evidence_states: EvidenceState[] = [
  "observed",
  "verified",
  "inferred",
  "incomplete",
  "conflicting",
  "not_observable",
  "indeterminate",
];

const severities: FindingSeverity[] = ["high", "medium", "low", "informational"];

const finding_features = tableFeatures({
  rowSortingFeature,
  sortedRowModel: createSortedRowModel(),
  rowPaginationFeature,
  paginatedRowModel: createPaginatedRowModel(),
});
const column_helper = createColumnHelper<typeof finding_features, FindingRow>();

function finding_tone(severity: FindingSeverity): "danger" | "warning" | "info" | "neutral" {
  if (severity === "high") return "danger";
  if (severity === "medium") return "warning";
  if (severity === "low") return "info";
  return "neutral";
}

function SelectFilter({
  label,
  value,
  options,
  on_change,
}: {
  label: string;
  value: string;
  options: string[];
  on_change: (value: string) => void;
}) {
  return (
    <label className="grid gap-1 text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
      {label}
      <select
        className="h-9 min-w-36 rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 text-sm font-normal normal-case tracking-normal text-[var(--text)] focus:border-cyan-500 focus:outline-none"
        onChange={(event) => on_change(event.target.value)}
        value={value}
      >
        <option value="">All</option>
        {options.map((option) => (
          <option key={option} value={option}>
            {option.replaceAll("_", " ")}
          </option>
        ))}
      </select>
    </label>
  );
}

export function FindingsTable({
  report,
  on_select,
}: {
  report: CanonicalReport;
  on_select: (finding: FindingRow) => void;
}) {
  const [filters, set_filters] = useState<FindingFilters>({
    search: "",
    severities: [],
    protocols: [],
    evidence_states: [],
  });
  const [sorting, set_sorting] = useState<SortingState>([{ id: "score", desc: true }]);
  const rows = useMemo(
    () => filter_findings({ rows: select_findings(report), filters }),
    [filters, report],
  );
  const protocols = useMemo(() => select_protocols(report), [report]);
  const columns = useMemo(
    () =>
      column_helper.columns([
      column_helper.accessor("severity", {
        header: "Severity",
        cell: ({ row }) => (
          <Badge tone={finding_tone(row.original.severity)}>{row.original.severity}</Badge>
        ),
      }),
      column_helper.accessor("title", {
        header: "Finding",
        cell: ({ row }) => (
          <button
            className="text-left font-medium text-[var(--text)] hover:text-cyan-400 focus-visible:outline-2 focus-visible:outline-cyan-400"
            onClick={() => on_select(row.original)}
            type="button"
          >
            <span className="block">{render_forensic_text(row.original.title)}</span>
            <span className="mt-1 block font-mono text-[10px] font-normal text-[var(--muted)]">
              {row.original.code}
            </span>
          </button>
        ),
      }),
      column_helper.accessor("affected_endpoint", {
        header: "Endpoint",
        cell: ({ getValue }) => (
          <bdi className="forensic-text text-xs" dir="ltr">
            {render_forensic_text(getValue())}
          </bdi>
        ),
      }),
      column_helper.accessor("protocol", {
        header: "Protocol",
        cell: ({ getValue }) => <Badge>{getValue()}</Badge>,
      }),
      column_helper.accessor("basis_state", {
        header: "Evidence",
        cell: ({ getValue }) => {
          const value = getValue();
          const tone =
            value === "observed" || value === "verified"
              ? "info"
              : value === "inferred"
                ? "neutral"
                : "unknown";
          return <Badge tone={tone}>{value.replaceAll("_", " ")}</Badge>;
        },
      }),
      column_helper.accessor("score", {
        header: "Score",
        cell: ({ getValue }) => <span className="font-mono font-semibold">{String(getValue())}</span>,
      }),
    ]),
    [on_select],
  );
  const table = useTable({
    features: finding_features,
    data: rows,
    columns,
    state: { sorting },
    onSortingChange: set_sorting,
    initialState: { pagination: { pageIndex: 0, pageSize: 8 } },
  });

  return (
    <>
      <Card className="overflow-hidden">
        <div className="border-b border-[var(--border)] p-4">
          <div className="flex flex-col justify-between gap-3 lg:flex-row lg:items-end">
            <div>
              <p className="section-label">Deterministic conclusions</p>
              <h2 className="mt-1 text-lg font-semibold">Prioritized findings</h2>
            </div>
            <div className="grid gap-2 sm:grid-cols-2 lg:flex">
              <label className="relative block">
                <span className="sr-only">Search findings</span>
                <Search
                  aria-hidden
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--muted)]"
                  size={15}
                />
                <Input
                  className="pl-9 lg:w-56"
                  onChange={(event) =>
                    set_filters((current) => ({ ...current, search: event.target.value }))
                  }
                  placeholder="Search findings"
                  type="search"
                  value={filters.search}
                />
              </label>
              <SelectFilter
                label="Severity"
                on_change={(value) =>
                  set_filters((current) => ({
                    ...current,
                    severities: value ? [value as FindingSeverity] : [],
                  }))
                }
                options={severities}
                value={filters.severities[0] ?? ""}
              />
              <SelectFilter
                label="Protocol"
                on_change={(value) =>
                  set_filters((current) => ({ ...current, protocols: value ? [value] : [] }))
                }
                options={protocols}
                value={filters.protocols[0] ?? ""}
              />
              <SelectFilter
                label="Evidence state"
                on_change={(value) =>
                  set_filters((current) => ({
                    ...current,
                    evidence_states: value ? [value as EvidenceState] : [],
                  }))
                }
                options={evidence_states}
                value={filters.evidence_states[0] ?? ""}
              />
            </div>
          </div>
        </div>
        {rows.length === 0 ? (
          <div className="p-4">
            <EmptyState
              description="Adjust the search or filters. Unknown and not-observable evidence are never hidden as passing checks."
              title="No findings match"
            />
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[850px] border-collapse text-sm">
                <thead>
                  {table.getHeaderGroups().map((header_group) => (
                    <tr className="bg-[var(--surface-raised)]" key={header_group.id}>
                      {header_group.headers.map((header) => (
                        <th className="px-4 py-3 text-left text-[11px] uppercase tracking-wider text-[var(--muted)]" key={header.id}>
                          {header.isPlaceholder ? null : (
                            <button
                              className="inline-flex items-center gap-1"
                              onClick={header.column.getToggleSortingHandler()}
                              type="button"
                            >
                              <table.FlexRender header={header} />
                              {header.column.getIsSorted() === "asc" ? <ChevronUp size={13} /> : null}
                              {header.column.getIsSorted() === "desc" ? <ChevronDown size={13} /> : null}
                            </button>
                          )}
                        </th>
                      ))}
                    </tr>
                  ))}
                </thead>
                <tbody>
                  {table.getRowModel().rows.map((row) => (
                    <tr className="border-t border-[var(--border)] hover:bg-[var(--surface-raised)]" key={row.id}>
                      {row.getAllCells().map((cell) => (
                        <td className="max-w-80 px-4 py-3 align-top" key={cell.id}>
                          <table.FlexRender cell={cell} />
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex items-center justify-between border-t border-[var(--border)] px-4 py-3 text-xs text-[var(--muted)]">
              <span>
                Page {table.state.pagination.pageIndex + 1} of {table.getPageCount()}
                {" · "}
                {rows.length} findings
              </span>
              <div className="flex gap-2">
                <Button
                  aria-label="Previous findings page"
                  disabled={!table.getCanPreviousPage()}
                  onClick={() => table.previousPage()}
                  variant="secondary"
                >
                  <ChevronLeft size={15} />
                </Button>
                <Button
                  aria-label="Next findings page"
                  disabled={!table.getCanNextPage()}
                  onClick={() => table.nextPage()}
                  variant="secondary"
                >
                  <ChevronRight size={15} />
                </Button>
              </div>
            </div>
          </>
        )}
      </Card>
    </>
  );
}
