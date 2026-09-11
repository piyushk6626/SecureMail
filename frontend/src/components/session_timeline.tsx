import type { EmailSession } from "../types/canonical_report.generated";
import { render_forensic_text } from "../core/forensic_text";
import { Badge, Card } from "./ui";

const states = ["advertised", "requested", "accepted", "tls_established"] as const;

function state_index(value: string | null | undefined): number {
  if (value === "plaintext_fallback" || value === "violation") return 2;
  return states.indexOf(value as (typeof states)[number]);
}

export function SessionTimeline({ session }: { session: EmailSession }) {
  const upgrade = session.explicit_upgrade;
  const implicit = session.implicit_tls;
  const terminal = upgrade?.state ?? null;
  const index = state_index(terminal);
  return (
    <Card className="session-timeline p-5">
      <div className="flex flex-wrap items-start justify-between gap-3"><div><p className="section-label">STARTTLS / STLS evidence</p><h3 className="mt-1 font-semibold">{session.protocol ?? "Unclassified"} session</h3><p className="mt-1 text-xs text-[var(--muted)]">Payload evidence: {session.payload_evidence}. Port hint: {session.port_hint}.</p></div><Badge tone={upgrade?.evidence_state === "observed" || upgrade?.evidence_state === "verified" ? "info" : "unknown"}>{upgrade?.evidence_state ?? "not recorded"}</Badge></div>
      {!upgrade ? (
        implicit ? (
          <div className="upgrade-terminal"><Badge tone={implicit.correlated_protocol ? "info" : "unknown"}>implicit TLS</Badge><p>{implicit.correlated_protocol ? `TLS correlated with payload-identified ${implicit.correlated_protocol}.` : "Implicit TLS correlation was not established; a port alone is not proof of protocol identity."}</p><div className="flex flex-wrap gap-2">{(implicit.evidence_frames ?? []).map((frame) => <span className="frame-chip" key={frame}>frame {frame}</span>)}</div></div>
        ) : <p className="mt-5 text-sm text-[var(--muted)]">No explicit upgrade state was recorded. This is not a successful upgrade path.</p>
      ) : <><ol className="upgrade-steps">{states.map((state, item_index) => <li className={item_index <= index && terminal !== "plaintext_fallback" && terminal !== "violation" ? "reached" : ""} key={state}><span>{item_index + 1}</span><b>{state.replaceAll("_", " ")}</b>{item_index === index ? <small>terminal evidence</small> : null}</li>)}</ol>{terminal === "plaintext_fallback" || terminal === "violation" ? <div className="upgrade-terminal"><Badge tone={terminal === "violation" ? "danger" : "warning"}>{terminal.replaceAll("_", " ")}</Badge><p>Upgrade did not establish protective TLS for this session.</p></div> : null}<div className="mt-4 flex flex-wrap gap-2 text-xs text-[var(--muted)]"><span>Terminal state: <b className="text-[var(--text)]">{terminal ?? "not recorded"}</b></span>{(upgrade.evidence_frames ?? []).map((frame) => <span className="frame-chip" key={frame}>frame {frame}</span>)}</div>{upgrade.downgrade_consistent ? <p className="downgrade-note">Pattern consistent with downgrade — not proof of an attacker.</p> : null}</>}
      {(session.events ?? []).length > 0 ? <div className="mt-5 border-t border-[var(--border)] pt-4"><p className="section-label">Protocol events</p><div className="mt-3 max-h-52 space-y-2 overflow-y-auto">{(session.events ?? []).map((event, index) => <div className="timeline-event" key={`${event.frame_number ?? "none"}-${index}`}><span className="font-mono">{event.frame_number ? `frame ${event.frame_number}` : "unframed"}</span><b>{event.kind}</b><span className="forensic-text">{render_forensic_text(event.command ?? event.text ?? "—")}</span></div>)}</div></div> : null}
    </Card>
  );
}
