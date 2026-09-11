import { useMemo, useState } from "react";
import type { CanonicalReport } from "../core/model";
import { render_forensic_text } from "../core/forensic_text";
import {
  coverage_categories,
  coverage_protocols,
  select_coverage,
  select_coverage_cells,
  select_policy_checks,
  type CoverageCell,
} from "../core/selectors";
import { Badge, Card } from "./ui";

function humanize(value: string): string {
  return value.replaceAll("_", " ");
}

function outcome_tone(outcome: string): "success" | "danger" | "unknown" | "warning" {
  if (outcome === "pass") return "success";
  if (outcome === "fail") return "danger";
  if (outcome === "unknown") return "unknown";
  return "warning";
}

function coverage_gradient(values: number[]): string {
  const total = values.reduce((sum, value) => sum + value, 0);
  if (total === 0) return "conic-gradient(var(--border) 0deg 360deg)";
  const colors = ["#22c55e", "#ef4444", "#a78bfa", "#94a3b8"];
  let degrees = 0;
  return `conic-gradient(${values
    .map((value, index) => {
      const start = degrees;
      degrees += (value / total) * 360;
      return `${colors[index]} ${start}deg ${degrees}deg`;
    })
    .join(", ")})`;
}

export function CoverageMatrix({ report }: { report: CanonicalReport }) {
  const [selected, set_selected] = useState<CoverageCell | null>(null);
  const [ledger_limit, set_ledger_limit] = useState(100);
  const cells = select_coverage_cells(report);
  const coverage = select_coverage(report);
  const selected_checks = useMemo(
    () => select_policy_checks(report, selected ?? undefined),
    [report, selected],
  );
  const visible_checks = selected_checks.slice(0, ledger_limit);
  const slices = [
    { key: "passed", label: "Passed", value: coverage.passed_count, tone: "success" as const },
    { key: "failed", label: "Failed", value: coverage.failed_count, tone: "danger" as const },
    { key: "unknown", label: "Unknown", value: coverage.unknown_count, tone: "unknown" as const },
    { key: "not_observable", label: "Not observable", value: coverage.not_observable_count, tone: "warning" as const },
  ];
  const donut_style = { background: coverage_gradient(slices.map((slice) => slice.value)) };

  function cell_for(protocol: string, category: string): CoverageCell {
    const cell = cells.find(
      (candidate) => candidate.protocol === protocol && candidate.category === category,
    );
    if (!cell) throw new Error("Coverage matrix invariant was not met");
    return cell;
  }

  return (
    <section aria-label="Coverage matrix" className="case-section">
      <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
        <div><p className="section-label">Coverage remainder</p><h2 className="mt-1 text-xl font-semibold">Where results could not be asserted</h2><p className="mt-1 text-sm text-[var(--muted)]">Applicable = passed + failed + unknown + not observable. Select a cell to inspect its checks.</p></div>
        <Badge tone="neutral">{coverage.applicable_count} applicable</Badge>
      </div>
      <div className="coverage-layout">
        <Card className="overflow-x-auto p-4">
          <table className="coverage-table">
            <thead><tr><th scope="col">Protocol</th>{coverage_categories.map((category) => <th key={category} scope="col">{humanize(category)}</th>)}</tr></thead>
            <tbody>{coverage_protocols.map((protocol) => <tr key={protocol}><th scope="row">{protocol}</th>{coverage_categories.map((category) => {
              const cell = cell_for(protocol, category);
              const selected_cell = selected?.protocol === protocol && selected.category === category;
              const counts = cell.counts;
              return <td key={category}><button aria-pressed={selected_cell} aria-label={`${protocol} ${category}: ${counts.passed_count} passed, ${counts.failed_count} failed, ${counts.unknown_count} unknown, ${counts.not_observable_count} not observable`} className="coverage-cell" onClick={() => { set_selected(selected_cell ? null : cell); set_ledger_limit(100); }} type="button"><span className="coverage-cell-counts"><i className="coverage-pass">P {counts.passed_count}</i><i className="coverage-fail">F {counts.failed_count}</i><i className="coverage-unknown">U {counts.unknown_count}</i><i className="coverage-not-observable">O {counts.not_observable_count}</i></span></button></td>;
            })}</tr>)}</tbody>
          </table>
        </Card>
        <Card className="coverage-summary p-5">
          <p className="section-label">Overall disposition</p>
          <div className="coverage-overall-visual">
            <div aria-label={`Coverage donut: ${slices.map((slice) => `${slice.label} ${slice.value}`).join(", ")}`} className="coverage-donut" role="img" style={donut_style}><span><b>{coverage.applicable_count}</b><small>applicable</small></span></div>
            <div aria-label={`Coverage summary: ${slices.map((slice) => `${slice.label} ${slice.value}`).join(", ")}`} className="coverage-slices" role="img">
              {slices.map((slice) => <div className={`coverage-slice coverage-slice-${slice.key}`} key={slice.key}><span>{slice.label}</span><b>{slice.value}</b></div>)}
            </div>
          </div>
          <p className="mt-4 text-xs leading-5 text-[var(--muted)]">Passed checks are specific assertions with usable evidence. Unknown and not-observable checks remain unresolved.</p>
        </Card>
      </div>
      {selected ? (
        <Card className="coverage-ledger mt-4 overflow-hidden" data-testid="coverage-ledger">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] p-4"><div><p className="section-label">Policy checks</p><h3 className="mt-1 font-semibold">{humanize(selected.protocol)} × {humanize(selected.category)}</h3></div><button className="text-sm text-cyan-400 hover:text-cyan-200" onClick={() => { set_selected(null); set_ledger_limit(100); }} type="button">Clear filter</button></div>
          {selected_checks.length === 0 ? <p className="p-4 text-sm text-[var(--muted)]">No applicable checks were published for this cell.</p> : <><div className="overflow-x-auto"><table className="w-full min-w-[920px] text-left text-xs"><thead className="bg-[var(--surface-raised)] text-[var(--muted)]"><tr><th className="p-3">Outcome</th><th className="p-3">Check</th><th className="p-3">Endpoint</th><th className="p-3">Record</th><th className="p-3">Evidence</th></tr></thead><tbody>{visible_checks.map((check) => <tr className="border-t border-[var(--border)]" key={check.check_id}><td className="p-3"><Badge tone={outcome_tone(check.outcome)}>{check.outcome}</Badge></td><td className="p-3"><b>{render_forensic_text(check.title)}</b><span className="forensic-text mt-1 block text-[10px] text-[var(--muted)]">{check.code} · {check.protocol} · {check.category}</span></td><td className="forensic-text p-3">{render_forensic_text(check.affected_endpoint)}</td><td className="forensic-text p-3"><b>{check.record_type}</b><span className="mt-1 block break-all text-[10px] text-[var(--muted)]">{render_forensic_text(check.record_key)}</span></td><td className="p-3"><Badge tone={check.evidence_state === "observed" || check.evidence_state === "verified" ? "info" : "unknown"}>{check.evidence_state}</Badge></td></tr>)}</tbody></table></div>{visible_checks.length < selected_checks.length ? <div className="flex items-center justify-between gap-3 p-4 text-xs text-[var(--muted)]"><span>Showing {visible_checks.length} of {selected_checks.length} checks.</span><button className="text-cyan-400 hover:text-cyan-200" onClick={() => set_ledger_limit((value) => value + 100)} type="button">Show 100 more</button></div> : null}</>}
        </Card>
      ) : null}
    </section>
  );
}
