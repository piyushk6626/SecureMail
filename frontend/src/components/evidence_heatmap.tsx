import { Fingerprint, Mail, Network, ShieldCheck } from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import type { CSSProperties, ReactNode } from "react";
import { useState } from "react";
import type { CanonicalReport } from "../core/model";
import { render_forensic_text } from "../core/forensic_text";
import { Badge } from "./ui";

type HeatmapKind = "flows" | "sessions" | "handshakes" | "certificates";
type CellState = "clear" | "attention" | "limited" | "unknown";

interface HeatCell {
  details: { label: string; value: string }[];
  id: string;
  label: string;
  state: CellState;
}

interface TileMetric {
  label: string;
  value: string;
}

const MAX_VISIBLE_CELLS = 168;

const heatmap_metadata: Record<HeatmapKind, { accent: string; icon: ReactNode; label: string }> = {
  flows: { accent: "#5A82B4", icon: <Network size={18} />, label: "Flows" },
  sessions: { accent: "#A05B8E", icon: <Mail size={18} />, label: "Mail sessions" },
  handshakes: { accent: "#6E67B5", icon: <ShieldCheck size={18} />, label: "TLS handshakes" },
  certificates: { accent: "#4F837A", icon: <Fingerprint size={18} />, label: "Certificates" },
};

export function EvidenceHeatmap({ report }: { report: CanonicalReport }) {
  const reduced_motion = useReducedMotion();
  const groups = build_groups(report);
  const tile_metrics = build_tile_metrics(report);
  const initial_kind = (Object.keys(groups) as HeatmapKind[]).find((kind) => groups[kind].length > 0) ?? "flows";
  const [selected_record, set_selected_record] = useState<{ index: number; kind: HeatmapKind }>({ index: 0, kind: initial_kind });
  const selected = groups[selected_record.kind][selected_record.index] ?? null;

  return (
    <section aria-label="Evidence heatmaps" className="evidence-heatmap-board">
      <div className="evidence-heatmap-heading">
        <p className="section-label">Record health matrix</p>
        <h3>Evidence heatmaps</h3>
        <p>Each square is one parsed record. Select any square to inspect it without leaving this workspace.</p>
      </div>

      <div className="evidence-heatmap-tiles">
        {(Object.keys(groups) as HeatmapKind[]).map((kind) => (
          <HeatmapTile
            cells={groups[kind]}
            kind={kind}
            key={kind}
            metrics={tile_metrics[kind]}
            on_select={(index) => set_selected_record({ index, kind })}
            selected_id={selected?.id ?? null}
          />
        ))}
      </div>

      <div className="heatmap-board-footer">
        <div><Legend state="clear" text="clear" /><Legend state="attention" text="needs attention" /><Legend state="limited" text="limited evidence" /><Legend state="unknown" text="unknown" /></div>
        <span>Up to {MAX_VISIBLE_CELLS} records are shown per tile</span>
      </div>

      <AnimatePresence mode="wait" initial={false}>
        <motion.aside
          animate={{ opacity: 1, y: 0 }}
          className="heatmap-inspector"
          exit={reduced_motion ? {} : { opacity: 0, y: 5 }}
          initial={reduced_motion ? false : { opacity: 0, y: 5 }}
          key={selected?.id ?? "empty"}
          transition={{ duration: 0.16 }}
        >
          {selected ? (
            <>
              <div className="heatmap-inspector-heading">
                <div><p className="section-label">Selected record</p><h4>{heatmap_metadata[selected_record.kind].label}</h4></div>
                <Badge tone={tone_for(selected.state)}>{selected.state}</Badge>
              </div>
              <p className="forensic-text heatmap-inspector-label">{render_forensic_text(selected.label)}</p>
              <dl>
                {selected.details.map((detail) => (
                  <div key={detail.label}>
                    <dt>{detail.label}</dt>
                    <dd className="forensic-text">{render_forensic_text(detail.value)}</dd>
                  </div>
                ))}
              </dl>
            </>
          ) : <p className="text-sm text-[var(--muted)]">Select a tile containing parsed records to inspect it.</p>}
        </motion.aside>
      </AnimatePresence>
    </section>
  );
}

function HeatmapTile({ cells, kind, metrics, on_select, selected_id }: { cells: HeatCell[]; kind: HeatmapKind; metrics: TileMetric[]; on_select: (index: number) => void; selected_id: string | null }) {
  const metadata = heatmap_metadata[kind];
  const counts = count_states(cells);
  const visible_cells = cells.slice(0, MAX_VISIBLE_CELLS);
  const columns = group_into_columns(visible_cells, 7);
  return (
    <section
      aria-label={`${metadata.label} heatmap`}
      className={`heatmap-tile heatmap-tile-${kind}`}
      data-selected={visible_cells.some((cell) => cell.id === selected_id)}
      style={{ "--tile-accent": metadata.accent } as CSSProperties}
    >
      <div className="heatmap-tile-header">
        <div><span>{metadata.icon}</span><h4>{metadata.label}</h4></div>
        <b>{cells.length}</b>
      </div>
      <div className="heatmap-tile-content">
        {visible_cells.length === 0 ? (
          <div className="heatmap-tile-empty">No records parsed</div>
        ) : (
          <div className="heatmap-tile-matrix">
            {columns.map((column, column_index) => (
              <div className="heatmap-cell-column" key={`column-${column_index}`}>
                {column.map((cell, row_index) => {
                  const record_index = column_index * 7 + row_index;
                  return (
                    <button
                      aria-label={`${cell.label}, ${cell.state}`}
                      aria-pressed={selected_id === cell.id}
                      className={`heat-cell heat-cell-${cell.state}`}
                      key={`${cell.id}-${record_index}`}
                      onClick={() => on_select(record_index)}
                      title={`${cell.label} · ${cell.state}`}
                      type="button"
                    />
                  );
                })}
              </div>
            ))}
          </div>
        )}
        <div className="heatmap-tile-context">
          <span aria-hidden="true" className="heatmap-tile-watermark">{metadata.icon}</span>
          {metrics.map((metric) => (
            <div key={metric.label}><b>{metric.value}</b><span>{metric.label}</span></div>
          ))}
        </div>
      </div>
      <div className="heatmap-tile-summary">
        <span><i className="heat-cell-clear" />{counts.clear} clear</span>
        <span><i className="heat-cell-attention" />{counts.attention} attention</span>
        <span><i className="heat-cell-limited" />{counts.limited} limited</span>
        <span><i className="heat-cell-unknown" />{counts.unknown} unknown</span>
      </div>
      {cells.length > MAX_VISIBLE_CELLS ? <small>Showing {MAX_VISIBLE_CELLS} of {cells.length}</small> : null}
    </section>
  );
}

function group_into_columns(cells: HeatCell[], column_height: number): HeatCell[][] {
  const columns: HeatCell[][] = [];
  for (let index = 0; index < cells.length; index += column_height) {
    columns.push(cells.slice(index, index + column_height));
  }
  return columns;
}

function build_tile_metrics(report: CanonicalReport): Record<HeatmapKind, TileMetric[]> {
  const flows = report.evidence.flows ?? [];
  const sessions = report.evidence.sessions ?? [];
  const handshakes = report.evidence.handshakes ?? [];
  const certificates = report.evidence.certificates ?? [];
  const complete_flows = flows.filter((flow) => flow.reconstruction_quality === "complete").length;
  const observed_bytes = flows.reduce((total, flow) => total + flow.orig_bytes + flow.resp_bytes, 0);
  const missing_bytes = flows.reduce((total, flow) => total + flow.gap_bytes + flow.missed_bytes, 0);
  const identified_sessions = sessions.filter((session) => session.protocol !== null && session.protocol !== undefined).length;
  const protocol_count = new Set(sessions.map((session) => session.protocol).filter(Boolean)).size;
  const secure_upgrades = sessions.filter((session) => session.explicit_upgrade?.state === "tls_established").length;
  const established_tls = handshakes.filter((handshake) => handshake.established).length;
  const full_visibility = handshakes.filter((handshake) => handshake.visibility === "full").length;
  const tls_versions = new Set(handshakes.map((handshake) => handshake.version.selected).filter(Boolean)).size;
  const healthy_certificates = certificates.filter(
    (certificate) =>
      certificate.syntax_valid &&
      certificate.valid_at_capture_time !== false &&
      certificate.validation?.identity_match !== false &&
      certificate.validation?.path_valid_at_capture_time !== false,
  ).length;
  const identity_failures = certificates.filter((certificate) => certificate.validation?.identity_match === false).length;
  return {
    flows: [
      { label: "Complete", value: `${complete_flows}/${flows.length}` },
      { label: "Observed bytes", value: format_bytes(observed_bytes) },
      { label: "Missing bytes", value: format_bytes(missing_bytes) },
    ],
    sessions: [
      { label: "Identified", value: `${identified_sessions}/${sessions.length}` },
      { label: "Protocols", value: String(protocol_count) },
      { label: "TLS upgraded", value: String(secure_upgrades) },
    ],
    handshakes: [
      { label: "Established", value: `${established_tls}/${handshakes.length}` },
      { label: "Full visibility", value: String(full_visibility) },
      { label: "Versions", value: String(tls_versions) },
    ],
    certificates: [
      { label: "Healthy", value: `${healthy_certificates}/${certificates.length}` },
      { label: "Identity failure", value: String(identity_failures) },
      { label: "Not observable", value: String(report.limitations.not_observable_certificate_count) },
    ],
  };
}

function format_bytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function build_groups(report: CanonicalReport): Record<HeatmapKind, HeatCell[]> {
  return {
    flows: (report.evidence.flows ?? []).map((flow) => ({
      id: `flow-${flow.uid}`,
      label: `${flow.orig.host}:${flow.orig.port} → ${flow.resp.host}:${flow.resp.port}`,
      state:
        flow.reconstruction_quality === "conflicting" || flow.evidence_state === "conflicting"
          ? "attention"
          : flow.reconstruction_quality !== "complete" || flow.gap_bytes > 0 || flow.missed_bytes > 0
            ? "limited"
            : "clear",
      details: [
        { label: "Flow UID", value: flow.uid },
        { label: "Reconstruction", value: flow.reconstruction_quality },
        { label: "Connection state", value: flow.conn_state },
        { label: "Observed bytes", value: String(flow.orig_bytes + flow.resp_bytes) },
      ],
    })),
    sessions: (report.evidence.sessions ?? []).map((session) => {
      const upgrade = session.explicit_upgrade?.state ?? "not applicable";
      const state: CellState =
        upgrade === "violation" || upgrade === "plaintext_fallback"
          ? "attention"
          : session.evidence_state === "not_observable"
            ? "unknown"
            : is_limited(session.evidence_state) ||
                session.payload_evidence === "indeterminate" ||
                (session.explicit_upgrade !== null &&
                  session.explicit_upgrade !== undefined &&
                  upgrade !== "tls_established")
            ? "limited"
            : session.protocol === null || session.protocol === undefined
              ? "unknown"
              : "clear";
      return {
        id: `session-${session.uid}`,
        label: `${session.protocol ?? session.payload_evidence} · ${session.uid}`,
        state,
        details: [
          { label: "Session UID", value: session.uid },
          { label: "Protocol", value: session.protocol ?? session.payload_evidence },
          { label: "Upgrade outcome", value: upgrade },
          { label: "Evidence state", value: session.evidence_state },
        ],
      };
    }),
    handshakes: (report.evidence.handshakes ?? []).map((handshake) => {
      const version = handshake.version.selected ?? "not observable";
      const legacy_version = /SSL|TLSv10|TLSv11|TLS 1\.0|TLS 1\.1/i.test(version);
      const state: CellState =
        !handshake.established || legacy_version
          ? "attention"
          : handshake.visibility !== "full" || is_limited(handshake.evidence_state)
            ? "limited"
            : version === "not observable"
              ? "unknown"
              : "clear";
      return {
        id: `handshake-${handshake.uid}`,
        label: `${version} · ${handshake.uid}`,
        state,
        details: [
          { label: "Flow UID", value: handshake.uid },
          { label: "TLS version", value: version },
          { label: "Cipher", value: handshake.cipher_suite.name ?? handshake.cipher_suite.code ?? "not observable" },
          { label: "Visibility", value: handshake.visibility },
        ],
      };
    }),
    certificates: (report.evidence.certificates ?? []).map((certificate, index) => {
      const has_failure =
        !certificate.syntax_valid ||
        certificate.valid_at_capture_time === false ||
        certificate.validation?.identity_match === false ||
        certificate.validation?.path_valid_at_capture_time === false;
      const state: CellState = has_failure
        ? "attention"
        : is_limited(certificate.evidence_state)
          ? "limited"
          : certificate.evidence_state === "not_observable"
            ? "unknown"
            : "clear";
      return {
        id: `certificate-${certificate.der_sha256}-${index}`,
        label: certificate.subject ?? `Certificate ${index + 1}`,
        state,
        details: [
          { label: "Certificate SHA-256", value: certificate.der_sha256 },
          { label: "Role", value: certificate.role },
          { label: "Issuer", value: certificate.issuer ?? "not observed" },
          { label: "Valid at capture", value: String(certificate.valid_at_capture_time ?? "not observed") },
        ],
      };
    }),
  };
}

function count_states(cells: HeatCell[]): Record<CellState, number> {
  const counts: Record<CellState, number> = { clear: 0, attention: 0, limited: 0, unknown: 0 };
  for (const cell of cells) counts[cell.state] += 1;
  return counts;
}

function Legend({ state, text }: { state: CellState; text: string }) {
  return <span className="inline-flex items-center gap-1.5"><span className={`heatmap-legend-cell heat-cell-${state}`} />{text}</span>;
}

function is_limited(state: string): boolean {
  return state === "incomplete" || state === "conflicting" || state === "indeterminate";
}

function tone_for(state: CellState): "success" | "danger" | "warning" | "unknown" {
  if (state === "clear") return "success";
  if (state === "attention") return "danger";
  if (state === "limited") return "warning";
  return "unknown";
}
