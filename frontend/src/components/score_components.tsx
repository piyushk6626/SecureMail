import type { ScoredEndpointFinding } from "../types/canonical_report.generated";

const component_labels = {
  severity: "Severity",
  confidence: "Confidence",
  exposure: "Exposure",
  recurrence: "Recurrence",
  asset_criticality: "Asset criticality",
  blast_radius: "Blast radius",
} as const;

export function ScoreComponents({ finding }: { finding: ScoredEndpointFinding }) {
  const entries = Object.entries(finding.components) as [keyof typeof component_labels, number][];
  const total = entries.reduce((sum, [, value]) => sum + value, 0);
  const expected = Math.min(100, total);
  const consistent = expected === finding.score;
  return (
    <section aria-label="Score components" className="score-components">
      <div className="flex items-end justify-between gap-3"><div><p className="section-label">Priority arithmetic</p><h3 className="mt-1 font-semibold">Why this finding ranks {finding.score}</h3></div><b className="font-mono text-lg">{finding.score}/100</b></div>
      <div aria-label={entries.map(([name, value]) => `${component_labels[name]} ${value}`).join(", ")} className="score-bar" role="img">
        {entries.map(([name, value]) => <span className={`score-segment score-${name}`} key={name} style={{ flexGrow: Math.max(0.2, value) }} title={`${component_labels[name]}: ${value} points`}>{value > 0 ? value : ""}</span>)}
      </div>
      <dl className="score-legend">{entries.map(([name, value]) => <div key={name}><dt>{component_labels[name]}</dt><dd>{value}</dd></div>)}</dl>
      <p className="mt-3 text-xs text-[var(--muted)]">min(100, {total}) = {expected}. {consistent ? "Matches the canonical endpoint score." : "Component data is inconsistent; the canonical score is shown unchanged."}</p>
    </section>
  );
}
