import { useMemo, useState } from "react";
import type { CanonicalReport } from "../core/model";
import { render_forensic_text } from "../core/forensic_text";
import {
  compare_findings,
  group_findings,
  select_endpoint_groups,
  select_findings,
  type FindingGroupMode,
  type FindingRow,
} from "../core/selectors";
import { Badge, Card } from "./ui";

const modes: { id: FindingGroupMode; label: string }[] = [
  { id: "endpoint", label: "Endpoint" },
  { id: "remediation", label: "Remediation" },
  { id: "code", label: "Rule code" },
  { id: "protocol", label: "Protocol" },
];

function severity_tone(severity: string): "danger" | "warning" | "info" | "neutral" {
  if (severity === "high") return "danger";
  if (severity === "medium") return "warning";
  if (severity === "low") return "info";
  return "neutral";
}

export function RiskTree({
  report,
  on_select,
  initial_mode = "endpoint",
}: {
  report: CanonicalReport;
  on_select: (finding: FindingRow) => void;
  initial_mode?: FindingGroupMode;
}) {
  const [mode, set_mode] = useState<FindingGroupMode>(initial_mode);
  const findings = useMemo(() => [...select_findings(report)].sort(compare_findings), [report]);
  const endpoints = useMemo(() => select_endpoint_groups(report), [report]);
  const groups = useMemo(() => group_findings(findings, mode), [findings, mode]);
  return (
    <section aria-label="Endpoint-first risk tree" className="case-section">
      <div className="mb-5 flex flex-col justify-between gap-3 lg:flex-row lg:items-end"><div><p className="section-label">Deterministic conclusions</p><h2 className="mt-1 text-xl font-semibold">What needs action, where</h2><p className="mt-1 text-sm text-[var(--muted)]">Scores prioritize endpoint findings; they are not a mail-system health grade.</p></div><div aria-label="Finding grouping" className="segmented-control">{modes.map((candidate) => <button aria-pressed={mode === candidate.id} className={mode === candidate.id ? "active" : ""} key={candidate.id} onClick={() => set_mode(candidate.id)} type="button">{candidate.label}</button>)}</div></div>
      {findings.length === 0 ? <Card className="p-5"><p className="font-semibold">No prioritized deterministic findings</p><p className="mt-2 text-sm text-[var(--muted)]">This is not a secure conclusion when assessment coverage is limited or none.</p></Card> : mode === "endpoint" ? <div className="risk-tree">{endpoints.map((endpoint) => <details className="risk-endpoint" key={endpoint.endpoint} open><summary><span><b className="forensic-text">{render_forensic_text(endpoint.endpoint)}</b><small>{endpoint.service_role.replaceAll("_", " ")} · {endpoint.protocol}</small></span><span className="risk-endpoint-metrics"><i>{endpoint.session_count} sessions</i><i>{endpoint.cleartext_session_count} cleartext</i><b>{endpoint.findings[0]?.score}</b></span></summary><div className="risk-endpoint-body">{[...new Set(endpoint.findings.map((finding) => finding.domain))].map((domain) => <div className="risk-domain" key={domain}><h3>{domain}</h3>{endpoint.findings.filter((finding) => finding.domain === domain).map((finding) => <FindingLeaf finding={finding} key={finding.finding_id} on_select={on_select} />)}</div>)}{endpoint.unresolved_check_count > 0 ? <p className="risk-unresolved">{endpoint.unresolved_check_count} check(s) remain unknown or not observable.</p> : null}</div></details>)}</div> : <div className="risk-tree">{[...groups].map(([group, rows]) => <details className="risk-endpoint" key={group} open><summary><span><b>{render_forensic_text(group)}</b><small>{rows.length} finding(s)</small></span><span className="risk-endpoint-metrics"><b>{rows[0]?.score}</b></span></summary><div className="risk-endpoint-body">{[...new Set(rows.map((row) => row.domain))].map((domain) => <div className="risk-domain" key={domain}><h3>{domain}</h3>{rows.filter((row) => row.domain === domain).map((finding) => <FindingLeaf finding={finding} key={finding.finding_id} on_select={on_select} />)}</div>)}</div></details>)}</div>}
    </section>
  );
}

function FindingLeaf({ finding, on_select }: { finding: FindingRow; on_select: (finding: FindingRow) => void }) {
  return <button className="risk-leaf" onClick={() => on_select(finding)} type="button"><span className="min-w-0"><b>{render_forensic_text(finding.title)}</b><small className="forensic-text">{finding.code} · {finding.unique_occurrences} occurrence(s)</small></span><span className="risk-leaf-badges"><Badge tone={severity_tone(finding.severity)}>{finding.severity}</Badge><Badge tone={finding.basis_state === "observed" || finding.basis_state === "verified" ? "info" : "unknown"}>{finding.basis_state}</Badge><b className="font-mono">{finding.score}</b></span></button>;
}
