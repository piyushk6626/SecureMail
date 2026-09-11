import { Network } from "lucide-react";
import { useMemo, useState } from "react";
import { render_forensic_text } from "../core/forensic_text";
import type { CanonicalReport } from "../core/model";
import { Badge, Card } from "./ui";

interface FlowView {
  bytes: number;
  destination: string;
  protocol: string;
  quality: string;
  source: string;
  tls: string;
  uid: string;
}

function format_bytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
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

/** A textual evidence navigator, deliberately not a synthesized health graph. */
export function FlowTopology({ report }: { report: CanonicalReport }) {
  const flows = useMemo(() => build_flow_views(report), [report]);
  const visible_flows = flows.slice(0, 128);
  const [selected_uid, set_selected_uid] = useState<string | null>(flows[0]?.uid ?? null);
  const selected = flows.find((flow) => flow.uid === selected_uid) ?? flows[0] ?? null;

  return (
    <Card className="flow-topology-card overflow-hidden">
      <header className="flow-topology-header">
        <div>
          <p className="section-label">Observed flow records</p>
          <h3>Flow evidence</h3>
          <p>Choose a path to review its exact endpoints, TLS observation, traffic volume, and reconstruction quality.</p>
        </div>
        <Badge>{flows.length} flows</Badge>
      </header>
      {flows.length === 0 ? (
        <div className="flow-topology-empty"><Network size={26} /><p>No TCP flows were recorded for this capture.</p></div>
      ) : (
        <div className="flow-topology-fullscreen">
          <section aria-label="Flow list" className="flow-topology-list">
            <div className="flow-topology-list-heading"><span>Observed paths</span><span>Quality</span></div>
            <div role="list">
              {visible_flows.map((flow, index) => (
                <div key={flow.uid} role="listitem">
                  <button aria-label={`Flow ${index + 1}: ${flow.source} to ${flow.destination}, ${flow.protocol}, ${flow.quality}`} aria-pressed={flow.uid === selected?.uid} className="flow-topology-row" onClick={() => set_selected_uid(flow.uid)} type="button">
                    <span className="flow-row-number">{String(index + 1).padStart(2, "0")}</span>
                    <span className="flow-row-route"><b className="forensic-text">{render_forensic_text(flow.source)}</b><span className="forensic-text">→ {render_forensic_text(flow.destination)}</span><small>{flow.protocol} · {flow.tls} · {format_bytes(flow.bytes)}</small></span>
                    <span className={`flow-quality flow-quality-${flow.quality}`}>{flow.quality}</span>
                  </button>
                </div>
              ))}
              {visible_flows.length < flows.length ? <p className="p-3 text-xs text-[var(--muted)]">Showing the first {visible_flows.length} of {flows.length} flow records.</p> : null}
            </div>
          </section>
          <section aria-label="Selected flow evidence" className="flow-topology-graph-pane">
            <div aria-live="polite" className="flow-topology-selection">
              <div><span>Source</span><b className="forensic-text">{selected ? render_forensic_text(selected.source) : "—"}</b></div>
              <div><span>Destination</span><b className="forensic-text">{selected ? render_forensic_text(selected.destination) : "—"}</b></div>
              <div><span>Observed transport</span><b>{selected ? `${selected.protocol} · ${selected.tls}` : "—"}</b></div>
              <div><span>Traffic</span><b>{selected ? format_bytes(selected.bytes) : "—"}</b></div>
              <div><span>Reconstruction</span><b>{selected?.quality ?? "—"}</b></div>
            </div>
            <p className="mt-4 text-xs leading-5 text-[var(--muted)]">This is a record navigator, not a network-health graph. Incomplete or conflicting reconstruction remains an evidence limitation.</p>
          </section>
        </div>
      )}
    </Card>
  );
}
