import type { ScoredEndpointFinding } from "../types/canonical_report.generated";
import type { CanonicalReport } from "../core/model";
import { resolve_evidence_reference } from "../core/evidence_resolver";
import { render_forensic_text, render_forensic_value } from "../core/forensic_text";
import { record_uid_from_reference } from "../core/selectors";
import { ScoreComponents } from "./score_components";
import { Badge, Card, Sheet } from "./ui";

function EvidenceStateBadge({ state }: { state: string }) {
  const tone =
    state === "observed" || state === "verified"
      ? "info"
      : state === "incomplete" || state === "conflicting"
        ? "warning"
        : "unknown";
  return <Badge tone={tone}>{state.replaceAll("_", " ")}</Badge>;
}

export function FindingDetails({
  finding,
  report,
  on_close,
}: {
  finding: ScoredEndpointFinding | null;
  report: CanonicalReport;
  on_close: () => void;
}) {
  const references =
    finding?.evidence_references?.map((reference) =>
      resolve_evidence_reference({ report, reference }),
    ) ?? [];
  const uids = Array.from(new Set([
    ...(finding?.contributing_occurrences.map((item) => item.session_uid ?? record_uid_from_reference(item.record_key)) ?? []),
    ...references.map((item) => item.record?.uid).filter((item): item is string => Boolean(item)),
  ]));

  return (
    <Sheet
      is_open={finding !== null}
      on_close={on_close}
      title={finding?.title ?? "Finding evidence"}
    >
      {finding ? (
        <div className="finding-drawer space-y-5">
          <div className="flex flex-wrap gap-2"><Badge tone={finding.severity === "high" ? "danger" : finding.severity === "medium" ? "warning" : "info"}>{finding.severity}</Badge><EvidenceStateBadge state={finding.basis_state} /><Badge>{finding.outcome}</Badge><Badge>{finding.code}</Badge></div>
          <div className="finding-detail-grid">
            <div className="space-y-5">
              <Card className="p-4">
                <p className="section-label">Deterministic judgment</p>
                <p className="forensic-text mt-3 text-sm leading-6">{render_forensic_text(finding.rationale)}</p>
                <dl className="mt-4 grid grid-cols-2 gap-3 text-xs"><Detail label="Endpoint" value={finding.affected_endpoint} /><Detail label="Outcome" value={finding.outcome} /><Detail label="Profile" value={finding.policy_profile} /><Detail label="Pack digest" value={finding.policy_pack_version} /><Detail label="Rule effective" value={finding.rule_effective_from} /><Detail label="Evaluation" value={finding.policy_evaluation_time} /></dl>
              </Card>
              <ScoreComponents finding={finding} />
              <Card className="p-4"><p className="section-label">Remediation context</p><dl className="mt-3 grid gap-3 text-xs"><Detail label="Remediation ID" value={finding.remediation_id} /><Detail label="Standards" value={(finding.standards ?? []).length ? (finding.standards ?? []).join(" · ") : "No standard citation published"} /><Detail label="Occurrences" value={`${finding.unique_occurrences} unique / ${finding.recurrence_count} recurrence`} /></dl></Card>
            </div>
            <div className="space-y-5">
              <section aria-labelledby="evidence-reference-title"><div className="mb-3 flex items-end justify-between gap-3"><div><p className="section-label">Observed evidence</p><h3 className="mt-1 font-semibold" id="evidence-reference-title">Finding-to-evidence lineage</h3></div><span className="text-xs text-[var(--muted)]">{references.length} linked</span></div><Lineage finding_state={finding.basis_state} report={report} uids={uids} /><div className="space-y-3">{references.length === 0 ? <Card className="p-4 text-sm text-[var(--muted)]">No evidence references.</Card> : references.map((resolved, index) => <Card className="p-4" data-testid="evidence-reference" key={`${resolved.reference.record_key}-${resolved.reference.field_path}-${index}`}><div className="flex flex-wrap items-center gap-2"><Badge>{resolved.reference.record_type}</Badge><EvidenceStateBadge state={resolved.reference.evidence_state} />{resolved.status !== "resolved" ? <Badge tone="warning">{resolved.status === "dangling_record" ? "record unavailable" : "field unavailable"}</Badge> : null}</div><dl className="mt-4 grid gap-3 text-xs sm:grid-cols-2"><Detail label="Record key" value={resolved.reference.record_key} /><Detail label="Field path" value={resolved.reference.field_path} /><Detail label="Direct frame" value={resolved.reference.frame_number ?? "No direct frame linked"} /><Detail label={resolved.direct_frame ? "Frame context" : "Record context"} value={resolved.frame_context ?? "No direct frame linked"} /></dl><div className="mt-4"><p className="text-[11px] uppercase tracking-wider text-[var(--muted)]">Resolved value</p><pre className="forensic-text mt-2 whitespace-pre-wrap break-all rounded-lg bg-[var(--surface-raised)] p-3 text-xs">{render_forensic_value(resolved.field_value)}</pre></div></Card>)}</div></section>
              <Card className="p-4"><p className="section-label">Contributing occurrences</p><div className="mt-3 space-y-2">{finding.contributing_occurrences.map((occurrence, index) => <div className="occurrence-row" key={`${occurrence.finding_id}-${index}`}><b className="forensic-text">{occurrence.session_uid ?? record_uid_from_reference(occurrence.record_key)}</b><span>{occurrence.record_type}</span><small className="forensic-text">{occurrence.record_key}</small></div>)}</div></Card>
            </div>
          </div>
        </div>
      ) : null}
    </Sheet>
  );
}

function Lineage({ finding_state, report, uids }: { finding_state: string; report: CanonicalReport; uids: string[] }) {
  const first_matching = (records: { uid: string; evidence_state: string }[] | undefined): string => records?.find((record) => uids.includes(record.uid))?.evidence_state ?? "not linked";
  const nodes = [
    ["Capture", "observed"],
    ["Flow", first_matching(report.evidence.flows)],
    ["Session", first_matching(report.evidence.sessions)],
    ["Handshake", first_matching(report.evidence.handshakes)],
    ["Certificate", first_matching(report.evidence.certificates)],
    ["Finding", finding_state],
  ];
  return <div aria-label="Evidence lineage" className="lineage-strip">{nodes.map(([label, state], index) => <span className="contents" key={label}><span data-evidence-state={state}>{label}<small>{state}</small></span>{index < nodes.length - 1 ? <i aria-hidden="true">→</i> : null}</span>)}{uids.length > 0 ? <small className="forensic-text">UID {uids.join(", ")}</small> : null}</div>;
}

function Detail({ label, value }: { label: string; value: string | number }) {
  return <div><dt className="text-[var(--muted)]">{label}</dt><dd className="forensic-text mt-1 break-all font-medium"><bdi dir="ltr">{render_forensic_value(value)}</bdi></dd></div>;
}
