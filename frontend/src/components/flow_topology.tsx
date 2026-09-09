import { GitBranch, Network } from "lucide-react";
import type { CSSProperties } from "react";
import { useState } from "react";
import { render_forensic_text } from "../core/forensic_text";
import type { CanonicalReport } from "../core/model";
import { Badge, Card } from "./ui";

const MAX_TOPOLOGY_FLOWS = 8;
const GRAPH_HEIGHT = 360;
const GRAPH_TOP = 42;
const GRAPH_BOTTOM = 322;

interface FlowView {
  bytes: number;
  destination: string;
  protocol: string;
  quality: string;
  source: string;
  tls: string;
  uid: string;
}

interface EndpointNode {
  degree: number;
  id: string;
  label: string;
  y: number;
}

export function FlowTopology({ report }: { report: CanonicalReport }) {
  const flows = build_flow_views(report).slice(0, MAX_TOPOLOGY_FLOWS);
  const [selected_uid, set_selected_uid] = useState<string | null>(flows[0]?.uid ?? null);
  const [hovered_uid, set_hovered_uid] = useState<string | null>(null);
  const active_uid = hovered_uid ?? selected_uid ?? flows[0]?.uid ?? null;
  const active_flow = flows.find((flow) => flow.uid === active_uid) ?? null;
  const origins = build_endpoint_nodes(flows.map((flow) => flow.source));
  const responders = build_endpoint_nodes(flows.map((flow) => flow.destination));
  const flow_positions = new Map(flows.map((flow, index) => [flow.uid, vertical_position(index, flows.length)]));

  return (
    <Card className="flow-topology-card overflow-hidden">
      <header className="flow-topology-header">
        <div><p className="section-label">Communication topology</p><h3>Flow path explorer</h3><p>Select or hover a flow to isolate its origin, protocol context, and responder path.</p></div>
        <Badge>{flows.length} of {report.evidence.flows?.length ?? 0} flows</Badge>
      </header>

      {flows.length === 0 ? (
        <div className="flow-topology-empty"><Network size={26} /><p>No TCP flows were recorded for topology mapping.</p></div>
      ) : (
        <div className="flow-topology-layout">
          <section aria-label="Flow list" className="flow-topology-list">
            <div className="flow-topology-list-heading"><span>Observed paths</span><span>Quality</span></div>
            <div role="list">
              {flows.map((flow, index) => (
                <div key={flow.uid} role="listitem">
                  <button
                    aria-label={`Flow ${index + 1}: ${flow.source} to ${flow.destination}, ${flow.protocol}, ${flow.quality}`}
                    aria-pressed={flow.uid === active_uid}
                    className="flow-topology-row"
                    onBlur={() => set_hovered_uid(null)}
                    onClick={() => set_selected_uid(flow.uid)}
                    onFocus={() => set_hovered_uid(flow.uid)}
                    onPointerEnter={() => set_hovered_uid(flow.uid)}
                    onPointerLeave={() => set_hovered_uid(null)}
                    type="button"
                  >
                    <span className="flow-row-number">{String(index + 1).padStart(2, "0")}</span>
                    <span className="flow-row-route">
                      <b className="forensic-text">{render_forensic_text(flow.source)}</b>
                      <span className="forensic-text">→ {render_forensic_text(flow.destination)}</span>
                      <small>{flow.protocol} · {flow.tls} · {format_bytes(flow.bytes)}</small>
                    </span>
                    <span className={`flow-quality flow-quality-${flow.quality}`}>{flow.quality}</span>
                  </button>
                </div>
              ))}
            </div>
            {(report.evidence.flows?.length ?? 0) > MAX_TOPOLOGY_FLOWS ? <p className="flow-topology-limit">Showing the first {MAX_TOPOLOGY_FLOWS} flows. The full ledger remains in the report export.</p> : null}
          </section>

          <section aria-label="Selected flow topology" className="flow-topology-graph-pane">
            <div className="flow-topology-selection" aria-live="polite">
              <div><span>Active path</span><b className="forensic-text">{active_flow ? render_forensic_text(`${active_flow.source} → ${active_flow.destination}`) : "—"}</b></div>
              <div><span>Transport</span><b>{active_flow ? `${active_flow.protocol} · ${active_flow.tls}` : "—"}</b></div>
            </div>
            <div className="topology-column-labels" aria-hidden="true"><span>Origin</span><span>Flow / protocol</span><span>Responder</span></div>
            <svg
              aria-label={active_flow ? `Network graph highlighting ${active_flow.source} through ${active_flow.protocol} to ${active_flow.destination}` : "Network flow graph"}
              className="flow-topology-graph"
              preserveAspectRatio="xMidYMid meet"
              role="img"
              viewBox={`0 0 720 ${GRAPH_HEIGHT}`}
            >
              <g className="topology-guide-lines" aria-hidden="true"><line x1="78" x2="78" y1="28" y2="336" /><line x1="360" x2="360" y1="28" y2="336" /><line x1="642" x2="642" y1="28" y2="336" /></g>
              <g className="topology-edges">
                {flows.map((flow) => {
                  const source_y = origins.find((node) => node.id === flow.source)?.y ?? GRAPH_TOP;
                  const destination_y = responders.find((node) => node.id === flow.destination)?.y ?? GRAPH_TOP;
                  const flow_y = flow_positions.get(flow.uid) ?? GRAPH_TOP;
                  const active = flow.uid === active_uid;
                  return (
                    <g className={active ? "active" : "muted"} key={`edges-${flow.uid}`} style={{ "--path-color": color_for_quality(flow.quality) } as CSSProperties}>
                      <path d={`M 78 ${source_y} C 175 ${source_y}, 252 ${flow_y}, 360 ${flow_y}`} />
                      <path d={`M 360 ${flow_y} C 468 ${flow_y}, 545 ${destination_y}, 642 ${destination_y}`} />
                    </g>
                  );
                })}
              </g>
              <g className="topology-endpoints topology-origins">
                {origins.map((node) => <TopologyEndpoint active={active_flow?.source === node.id} key={node.id} node={node} x={78} />)}
              </g>
              <g className="topology-flow-nodes">
                {flows.map((flow) => {
                  const active = flow.uid === active_uid;
                  return (
                    <g className={active ? "active" : "muted"} key={`flow-node-${flow.uid}`}>
                      <circle cx="360" cy={flow_positions.get(flow.uid)} r={active ? 9 : 5} style={{ "--path-color": color_for_quality(flow.quality) } as CSSProperties} />
                      {active ? <text x="360" y={(flow_positions.get(flow.uid) ?? 0) - 15}>{flow.protocol}</text> : null}
                    </g>
                  );
                })}
              </g>
              <g className="topology-endpoints topology-responders">
                {responders.map((node) => <TopologyEndpoint active={active_flow?.destination === node.id} key={node.id} node={node} x={642} />)}
              </g>
            </svg>
            <div className="flow-topology-legend"><span><i className="origin" />Endpoint</span><span><i className="flow" />Observed flow</span><span><GitBranch size={12} />Path direction is left to right</span></div>
          </section>
        </div>
      )}
    </Card>
  );
}

function TopologyEndpoint({ active, node, x }: { active: boolean; node: EndpointNode; x: number }) {
  return (
    <g className={active ? "active" : "muted"}>
      <circle cx={x} cy={node.y} r={Math.min(10, 5 + node.degree)} />
      <title>{node.label} · {node.degree} flow{node.degree === 1 ? "" : "s"}</title>
      {active ? <text textAnchor={x < 360 ? "start" : "end"} x={x < 360 ? x + 14 : x - 14} y={node.y - 10}>{truncate_label(node.label)}</text> : null}
    </g>
  );
}

function build_flow_views(report: CanonicalReport): FlowView[] {
  const sessions = new Map((report.evidence.sessions ?? []).map((session) => [session.uid, session]));
  const handshakes = new Map((report.evidence.handshakes ?? []).map((handshake) => [handshake.uid, handshake]));
  return (report.evidence.flows ?? []).map((flow) => {
    const session = sessions.get(flow.uid);
    const handshake = handshakes.get(flow.uid);
    return {
      bytes: flow.orig_bytes + flow.resp_bytes,
      destination: `${flow.resp.host}:${flow.resp.port}`,
      protocol: session?.protocol ?? session?.payload_evidence ?? "TCP",
      quality: flow.reconstruction_quality,
      source: `${flow.orig.host}:${flow.orig.port}`,
      tls: handshake?.version.selected ?? (handshake ? "TLS version unavailable" : "TLS not observed"),
      uid: flow.uid,
    };
  });
}

function build_endpoint_nodes(labels: string[]): EndpointNode[] {
  const unique_labels = [...new Set(labels)];
  return unique_labels.map((label, index) => ({
    degree: labels.filter((candidate) => candidate === label).length,
    id: label,
    label,
    y: vertical_position(index, unique_labels.length),
  }));
}

function vertical_position(index: number, total: number): number {
  if (total <= 1) return (GRAPH_TOP + GRAPH_BOTTOM) / 2;
  return GRAPH_TOP + (index * (GRAPH_BOTTOM - GRAPH_TOP)) / (total - 1);
}

function color_for_quality(quality: string): string {
  if (quality === "complete") return "#5CB3C7";
  if (quality === "conflicting") return "#CE4760";
  return "#ECA400";
}

function truncate_label(value: string): string {
  const safe = render_forensic_text(value);
  return safe.length > 25 ? `${safe.slice(0, 22)}…` : safe;
}

function format_bytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}
