import { GitBranch, Network } from "lucide-react";
import type { CSSProperties } from "react";
import { useEffect, useRef, useState, useMemo } from "react";
import { render_forensic_text } from "../core/forensic_text";
import type { CanonicalReport } from "../core/model";
import { Badge, Card } from "./ui";
import { init, use as register_echarts, type ECharts } from "echarts/core";
import { ZoomIn, ZoomOut } from "lucide-react";
import { GraphChart } from "echarts/charts";
import { TooltipComponent, AriaComponent, DataZoomComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";

// Register only required ECharts modules
register_echarts([GraphChart, TooltipComponent, AriaComponent, DataZoomComponent, CanvasRenderer]);

const PROTOCOL_COLORS: Record<string, string> = {
  smtp: "#22D3EE",
  imap: "#A78BFA",
  pop3: "#F59E0B",
  indeterminate: "#F97316",
  none: "#64748B",
  tcp: "#64748B",
};

function protocolColor(protocol: string): string {
  const key = protocol?.toLowerCase() ?? "none";
  return PROTOCOL_COLORS[key] ?? "#94A3B8";
}

export function FlowTopology({ report }: { report: CanonicalReport }) {
  // Zoom range for dataZoom (0-100). start/end represent the visible window.
  const [zoomStart, setZoomStart] = useState<number>(0);
  const [zoomEnd, setZoomEnd] = useState<number>(100);
  const flows = useMemo(() => build_flow_views(report), [report]);
  const [selected_uid, set_selected_uid] = useState<string | null>(flows[0]?.uid ?? null);
  const [hovered_uid, set_hovered_uid] = useState<string | null>(null);
  const active_uid = hovered_uid ?? selected_uid ?? flows[0]?.uid ?? null;
  const active_flow = flows.find((flow) => flow.uid === active_uid) ?? null;

  // Filter out any flows with missing source or destination to avoid ECharts errors
  const validFlows = flows.filter((flow) => flow.source && flow.destination);

  const nodesMap = new Map<string, { id: string; label: string; degree: number }>();
  validFlows.forEach((flow) => {
    [flow.source, flow.destination].forEach((ep) => {
      const ip = ep.split(":")[0];
      const existing = nodesMap.get(ip);
      if (existing) {
        existing.degree += 1;
      } else {
        nodesMap.set(ip, { id: ip, label: ip, degree: 1 });
      }
    });
  });
    const nodes = useMemo(() => {
      const nodeArray = Array.from(nodesMap.values());
      const cols = Math.ceil(Math.sqrt(nodeArray.length));
      return nodeArray.map((node, i) => ({
        id: node.id,
        name: node.label,
        symbolSize: Math.min(30, Math.max(14, node.degree * 2 + 14)),
        x: (i % cols) * 120,
        y: Math.floor(i / cols) * 120,
        label: {
          show: false,
          formatter: node.label,
          fontFamily: "JetBrains Mono Variable",
        },
      }));
    }, [nodesMap]);

  const curvenessSeq = [0, 0.08, -0.08, 0.16, -0.16];
  const edgeCounters = new Map<string, number>();
  const edges = useMemo(() => {
    const edgeMap = new Map<string, number>();
    return validFlows.map((flow) => {
      const key = `${flow.source}->${flow.destination}`;
      const count = edgeMap.get(key) ?? 0;
      edgeMap.set(key, count + 1);
      const curveness = curvenessSeq[count % curvenessSeq.length];
      const lineStyle: any = {
        color: protocolColor(flow.protocol),
        type: flow.quality === "complete" ? "solid" : flow.quality === "incomplete" ? "dashed" : "dotted",
        curveness,
      };
      return {
        source: flow.source,
        target: flow.destination,
        lineStyle,
        uid: flow.uid,
        tooltip: {
          formatter: `Source: ${flow.source}<br/>Dest: ${flow.destination}<br/>Protocol: ${flow.protocol}<br/>TLS: ${flow.tls}<br/>Traffic: ${format_bytes(flow.bytes)}<br/>Reconstruction: ${flow.quality}<br/>UID: ${flow.uid}`,
        },
      };
    });
  }, [validFlows]);

  const chartRef = useRef<ECharts | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  // Initialize ECharts instance only once; subsequent renders keep dragged positions
  useEffect(() => {
    if (process.env.NODE_ENV === "test") return;
    if (!containerRef.current) return;
    if (chartRef.current) return; // already initialized
    const chart = init(containerRef.current, undefined, { renderer: "canvas" });
    chartRef.current = chart;
    const hasReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const enableAnimation = !hasReducedMotion && nodes.length < 500;
    const graphLayout = "none"; // static layout with manual positions
    const option = {
      aria: { enabled: true, decal: { show: true } },
      tooltip: { trigger: "item", triggerOn: "mousemove" },
      series: [
        {
          type: "graph",
          layout: "none",
          center: ["50%", "50%"],
          roam: true,
          draggable: true,
          data: nodes,
          edges: edges,
          label: {
            show: false,
            formatter: (params: any) => params.name,
            fontFamily: "JetBrains Mono Variable",
          },
          emphasis: { label: { show: true } },
          animation: enableAnimation,
          large: nodes.length > 1000,
          largeThreshold: 1000,
          progressive: nodes.length > 1500 ? 5000 : 0,
        },
      ],
      dataZoom: [{ type: "inside", start: zoomStart, end: zoomEnd }],
    } as any;
    chart.setOption(option);
    // Force a resize after layout settles — the container may not have its
    // final dimensions at the moment ECharts initialises.
    requestAnimationFrame(() => chart.resize());
    setTimeout(() => chart.resize(), 100);
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(containerRef.current);
    return () => {
      observer.disconnect();
      chart.dispose();
      chartRef.current = null; // allow re-init on StrictMode remount
    };
  }, []);

  useEffect(() => {
    if (!chartRef.current) return;
    chartRef.current.setOption({
        series: [{ data: nodes, edges: edges }],
        dataZoom: [{ start: zoomStart, end: zoomEnd }]
    });
  }, [nodes, edges, zoomStart, zoomEnd]);

  useEffect(() => {
    if (!chartRef.current) return;
    chartRef.current.dispatchAction({ type: "downplay" });
    if (active_uid) {
      const edgeIndex = edges.findIndex((e) => e.uid === active_uid);
      if (edgeIndex !== -1) {
        chartRef.current.dispatchAction({ type: "highlight", dataIndex: edgeIndex + nodes.length });
      }
    }
  }, [active_uid, nodes.length, edges]);

  return (
    <Card className="flow-topology-card overflow-hidden">
      <header className="flow-topology-header">
        <div>
          <p className="section-label">Communication topology</p>
          <h3>Flow path explorer</h3>
          <p>Drag endpoints to explore the capture topology. Edge color identifies the observed mail protocol; select a flow to isolate its path.</p>
        </div>
        <Badge>{nodesMap.size} endpoints · {flows.length} flows</Badge>
      </header>

      {flows.length === 0 ? (
        <div className="flow-topology-empty">
          <Network size={26} />
          <p>No TCP flows were recorded for topology mapping.</p>
        </div>
      ) : (
        <div className="flow-topology-fullscreen">
          <section aria-label="Flow list" className="flow-topology-list">
            <div className="flow-topology-list-heading">
              <span>Observed paths</span>
              <span>Quality</span>
            </div>
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
          </section>

          <section aria-label="Selected flow topology" className="flow-topology-graph-pane">
            <div className="flow-topology-zoom-controls" style={{ display: "flex", gap: "0.5rem", marginBottom: "0.5rem" }}>
              <button aria-label="Zoom in" onClick={() => {
                const range = zoomEnd - zoomStart;
                if (range > 20) {
                  setZoomStart(zoomStart + 5);
                  setZoomEnd(zoomEnd - 5);
                }
              }} className="zoom-button">
                <ZoomIn size={16} />
              </button>
              <button aria-label="Zoom out" onClick={() => {
                const range = zoomEnd - zoomStart;
                if (range < 100) {
                  setZoomStart(Math.max(0, zoomStart - 5));
                  setZoomEnd(Math.min(100, zoomEnd + 5));
                }
              }} className="zoom-button">
                <ZoomOut size={16} />
              </button>
            </div>
            <div className="flow-topology-selection" aria-live="polite">
              <div>
                <span>Active path</span>
                <b className="forensic-text">{active_flow ? render_forensic_text(`${active_flow.source} → ${active_flow.destination}`) : "—"}</b>
              </div>
              <div>
                <span>Transport</span>
                <b>{active_flow ? `${active_flow.protocol} · ${active_flow.tls}` : "—"}</b>
              </div>
            </div>
            {nodes.length > 2000 ? (
              <div className="flow-topology-limit" role="alert">
                Too many endpoints ({nodes.length}) to render the graph.
              </div>
            ) : (
              <div
                className="flow-topology-graph"
                role="img"
                aria-label={active_flow ? `Network graph highlighting ${active_flow.source} through ${active_flow.protocol} to ${active_flow.destination}` : `Network graph with ${nodesMap.size} endpoints and ${flows.length} flows`}
                ref={containerRef}
              ></div>
            )}
            <div className="flow-topology-legend">
              <span><i style={{ background: PROTOCOL_COLORS.smtp }}></i>SMTP</span>
              <span><i style={{ background: PROTOCOL_COLORS.imap }}></i>IMAP</span>
              <span><i style={{ background: PROTOCOL_COLORS.pop3 }}></i>POP3</span>
              <span><i style={{ background: PROTOCOL_COLORS.indeterminate }}></i>Unknown/TCP</span>
              <span>Drag nodes · Scroll to zoom · Drag canvas to pan</span>
            </div>
          </section>
        </div>
      )}
    </Card>
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

function format_bytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

interface FlowView {
  bytes: number;
  destination: string;
  protocol: string;
  quality: string;
  source: string;
  tls: string;
  uid: string;
}
