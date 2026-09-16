import { useEffect, useMemo, useState, type KeyboardEvent } from "react";
import type { CanonicalReport } from "../core/model";
import type { CertificateEvidence, EmailSession, Flow, TlsHandshake } from "../types/canonical_report.generated";
import { render_forensic_text } from "../core/forensic_text";
import { select_evidence_bands, type EvidenceBand, type EvidenceBandType, type EvidenceCell } from "../core/selectors";
import { Badge, Button, evidence_state_tone, outcome_tone } from "./ui";

const initial_limit = 104;
const increment = 104;
const heatmap_rows = 7;

function cell_id(cell: EvidenceCell): string {
  return `${cell.band}:${cell.key}`;
}

function endpoint_for(cell: EvidenceCell): string | null {
  if (cell.band === "flow") {
    const flow = cell.record as Flow;
    return `${flow.orig.host}:${flow.orig.port} → ${flow.resp.host}:${flow.resp.port}`;
  }
  return null;
}

function summary_for(cell: EvidenceCell): string {
  if (cell.band === "flow") return `${(cell.record as Flow).reconstruction_quality} reconstruction`;
  if (cell.band === "session") {
    const session = cell.record as EmailSession;
    return `${session.protocol ?? "unclassified"} · ${session.explicit_upgrade?.state ?? "no explicit upgrade"}`;
  }
  if (cell.band === "handshake") {
    const handshake = cell.record as TlsHandshake;
    return `${handshake.version.selected ?? "version not observable"} · ${handshake.cipher_suite.name ?? "cipher not observable"}`;
  }
  const certificate = cell.record as CertificateEvidence;
  return `${certificate.role} · chain ${certificate.chain_index} · ${certificate.subject ?? "subject not retained"}`;
}

function accessible_name(cell: EvidenceCell): string {
  return `${cell.band} ${cell.key}; evidence state ${cell.evidence_state}; ${cell.marker}; ${cell.checks.length} linked checks; ${cell.findings.length} linked findings`;
}

function RecordInspector({ cell, on_open_finding }: { cell: EvidenceCell | null; on_open_finding: (finding_id: string) => void }) {
  if (!cell) return <div className="heatmap-inspector"><p>No records published.</p></div>;
  const endpoint = endpoint_for(cell);
  return <section aria-label="Selected evidence record" className="heatmap-inspector">
    <div className="heatmap-inspector-heading"><div><p className="section-label">Selected record</p><h4>{cell.band}</h4></div><Badge tone={evidence_state_tone(cell.evidence_state)}>{cell.evidence_state}</Badge></div>
    <dl className="heatmap-record-facts"><div><dt>Canonical key</dt><dd className="forensic-text">{render_forensic_text(cell.key)}</dd></div><div><dt>UID</dt><dd className="forensic-text">{render_forensic_text(cell.uid)}</dd></div>{endpoint ? <div><dt>Endpoint</dt><dd className="forensic-text">{render_forensic_text(endpoint)}</dd></div> : null}<div><dt>Published summary</dt><dd>{render_forensic_text(summary_for(cell))}</dd></div></dl>
    <div className="heatmap-linked"><p>Exactly linked policy checks</p>{cell.checks.length === 0 ? <small>No applicable linked check was published.</small> : <ul>{cell.checks.map((check) => <li key={check.check_id}><Badge tone={outcome_tone(check.outcome)}>{check.outcome}</Badge><span><b className="forensic-text">{render_forensic_text(check.code)}</b> · {render_forensic_text(check.title)}</span><Badge tone={evidence_state_tone(check.evidence_state)}>{check.evidence_state}</Badge></li>)}</ul>}</div>
    <div className="heatmap-linked"><p>Exactly linked findings</p>{cell.findings.length === 0 ? <small>No linked finding was published.</small> : <ul>{cell.findings.map((finding) => <li key={finding.finding_id}><span><b>{render_forensic_text(finding.title)}</b><small className="forensic-text">{finding.severity} · score {finding.score}</small></span><Button onClick={() => on_open_finding(finding.finding_id)} variant="secondary">Open finding</Button></li>)}</ul>}</div>
  </section>;
}

export function EvidenceHeatmap({ report, on_open_finding }: { report: CanonicalReport; on_open_finding: (finding_id: string) => void }) {
  const bands = useMemo(() => select_evidence_bands(report), [report]);
  const identity = `${report.manifest.case_id ?? "case"}:${report.manifest.analysis_run_id ?? "run"}:${report.manifest.generated_at}`;
  const [limits, set_limits] = useState<Record<EvidenceBandType, number>>(() => limits_for(bands));
  const [selected_id, set_selected_id] = useState<string | null>(null);
  const [active_id, set_active_id] = useState<string | null>(null);
  useEffect(() => {
    const first = bands.flatMap((band) => band.cells)[0];
    set_limits(limits_for(bands));
    set_selected_id(first ? cell_id(first) : null);
    set_active_id(first ? cell_id(first) : null);
  }, [identity, bands]);
  const visible_bands = bands.map((band) => ({ ...band, cells: band.cells.slice(0, limits[band.type]) }));
  const visible_cells = visible_bands.flatMap((band) => band.cells);
  const selected = visible_cells.find((cell) => cell_id(cell) === selected_id) ?? visible_cells[0] ?? null;

  function select_cell(cell: EvidenceCell): void {
    const band = bands.find((candidate) => candidate.type === cell.band);
    const index = band?.cells.findIndex((candidate) => cell_id(candidate) === cell_id(cell)) ?? -1;
    if (index >= 0) set_limits((current) => ({ ...current, [cell.band]: Math.max(current[cell.band], index + 1) }));
    set_selected_id(cell_id(cell));
    set_active_id(cell_id(cell));
  }
  function move(event: KeyboardEvent<HTMLButtonElement>, cell: EvidenceCell, cells: EvidenceCell[]): void {
    const index = cells.findIndex((item) => cell_id(item) === cell_id(cell));
    const next_index = event.key === "Home" ? 0 : event.key === "End" ? cells.length - 1 : event.key === "ArrowLeft" ? Math.max(0, index - 1) : event.key === "ArrowRight" ? Math.min(cells.length - 1, index + 1) : event.key === "ArrowUp" ? Math.max(0, index - heatmap_rows) : event.key === "ArrowDown" ? Math.min(cells.length - 1, index + heatmap_rows) : index;
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); select_cell(cell); return; }
    if (next_index === index) return;
    event.preventDefault();
    const next = cells[next_index];
    if (!next) return;
    set_active_id(cell_id(next));
    window.requestAnimationFrame(() => document.getElementById(`evidence-cell-${cell_id(next)}`)?.focus());
  }
  function load_more(band: EvidenceBand): void {
    set_limits((current) => ({
      ...current,
      [band.type]: Math.min(band.cells.length, current[band.type] + increment),
    }));
  }
  return <section aria-label="Unified evidence contribution grid" className="evidence-heatmap">
    <div className="heatmap-heading"><div><p className="section-label">Unified evidence contribution grid</p><h3>Published record navigation</h3><p>Report order, not capture chronology. One square is one canonical evidence record.</p></div><HeatmapLegend /></div>
    <div aria-label="Evidence records" className="heatmap-scroll" role="grid"><div className="heatmap-groups">{visible_bands.map((band) => <EvidenceGroup active_id={active_id} all_band={bands.find((candidate) => candidate.type === band.type) ?? band} band={band} key={band.type} on_load_more={load_more} on_move={move} on_select={select_cell} />)}</div></div>
    <RecordInspector cell={selected} on_open_finding={on_open_finding} />
    <details className="heatmap-text-list"><summary>Text record list</summary>{bands.map((band) => <div key={band.type}><b>{band.label}</b><ul>{band.cells.map((cell) => <li key={cell_id(cell)}><button onClick={() => select_cell(cell)} type="button">{accessible_name(cell)}</button></li>)}</ul></div>)}</details>
  </section>;
}

function limits_for(bands: EvidenceBand[]): Record<EvidenceBandType, number> {
  return Object.fromEntries(bands.map((band) => [band.type, initial_limit])) as Record<EvidenceBandType, number>;
}

function EvidenceGroup({ active_id, all_band, band, on_load_more, on_move, on_select }: { active_id: string | null; all_band: EvidenceBand; band: EvidenceBand; on_load_more: (band: EvidenceBand) => void; on_move: (event: KeyboardEvent<HTMLButtonElement>, cell: EvidenceCell, cells: EvidenceCell[]) => void; on_select: (cell: EvidenceCell) => void }) {
  const remaining = all_band.cells.length - band.cells.length;
  return <section aria-label={`${band.label} evidence group`} className="heatmap-group" role="rowgroup"><div className="heatmap-group-heading"><b>{band.label}</b><span>{band.cells.length}/{all_band.cells.length}</span>{remaining > 0 ? <button className="heatmap-more" onClick={() => on_load_more(all_band)} type="button">Show {Math.min(increment, remaining)} more</button> : null}</div>{band.cells.length === 0 ? <p className="heatmap-empty">No records published.</p> : <div aria-label={`${band.label} evidence records`} className="heatmap-group-cells" role="row">{band.cells.map((cell) => <HeatmapCell active_id={active_id} cell={cell} key={cell_id(cell)} on_move={(event, moving_cell) => on_move(event, moving_cell, band.cells)} on_select={on_select} />)}</div>}</section>;
}

function HeatmapCell({ active_id, cell, on_move, on_select }: { active_id: string | null; cell: EvidenceCell; on_move: (event: KeyboardEvent<HTMLButtonElement>, cell: EvidenceCell) => void; on_select: (cell: EvidenceCell) => void }) {
  const label = accessible_name(cell);
  return <button aria-label={label} aria-pressed={active_id === cell_id(cell)} className={`heatmap-cell heatmap-cell-${cell.tone}`} id={`evidence-cell-${cell_id(cell)}`} onClick={() => on_select(cell)} onKeyDown={(event) => on_move(event, cell)} role="gridcell" tabIndex={active_id === cell_id(cell) ? 0 : -1} title={label} type="button"><span aria-hidden="true">{cell.marker === "PASS" ? "✓" : cell.marker === "NOT OBSERVABLE" ? "○" : cell.marker === "OBSERVED · NOT EVALUATED" ? "·" : "!"}</span>{cell.unresolved_states.length > 0 || cell.checks.some((check) => check.outcome === "not_observable") ? <i aria-hidden="true" className="heatmap-secondary-marker" /> : null}</button>;
}

function HeatmapLegend() {
  const items = [["neutral", "Not evaluated"], ["success", "Pass"], ["info", "Low / informational"], ["warning", "Medium attention"], ["danger", "High / failed"], ["unknown", "Unresolved"], ["not_observable", "Not observable"]] as const;
  return <div aria-label="Evidence grid legend" className="heatmap-legend" role="group">{items.map(([tone, label]) => <span key={tone}><i className={`heatmap-legend-cell heatmap-cell-${tone}`} />{label}</span>)}</div>;
}
