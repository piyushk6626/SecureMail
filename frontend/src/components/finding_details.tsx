import type { ScoredEndpointFinding } from "../types/canonical_report.generated";
import type { CanonicalReport } from "../core/model";
import { resolve_evidence_reference } from "../core/evidence_resolver";
import { render_forensic_value } from "../core/forensic_text";
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

  return (
    <Sheet
      is_open={finding !== null}
      on_close={on_close}
      title={finding?.title ?? "Finding evidence"}
    >
      {finding ? (
        <div className="space-y-5">
          <div className="flex flex-wrap gap-2">
            <Badge tone={finding.severity === "high" ? "danger" : "warning"}>
              {finding.severity}
            </Badge>
            <EvidenceStateBadge state={finding.basis_state} />
            <Badge>{finding.code}</Badge>
          </div>
          <Card className="p-4">
            <p className="section-label">Deterministic conclusion</p>
            <p className="mt-3 text-sm leading-6">
              <ForensicText value={finding.rationale} />
            </p>
            <dl className="mt-4 grid grid-cols-2 gap-3 text-xs">
              <Detail label="Endpoint" value={finding.affected_endpoint} />
              <Detail label="Score" value={`${finding.score}/100`} />
              <Detail label="Exposure" value={finding.exposure} />
              <Detail label="Recurrence" value={finding.recurrence_count} />
            </dl>
          </Card>
          <section aria-labelledby="evidence-reference-title">
            <div className="mb-3 flex items-end justify-between gap-3">
              <div>
                <p className="section-label">Observed evidence</p>
                <h3 className="mt-1 font-semibold" id="evidence-reference-title">
                  Record references
                </h3>
              </div>
              <span className="text-xs text-[var(--muted)]">{references.length} linked</span>
            </div>
            {references.length === 0 ? (
              <Card className="p-4 text-sm text-[var(--muted)]">No evidence references.</Card>
            ) : (
              <div className="space-y-3">
                {references.map((resolved, index) => (
                  <Card
                    className="p-4"
                    data-testid="evidence-reference"
                    key={`${resolved.reference.record_key}-${resolved.reference.field_path}-${index}`}
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge>{resolved.reference.record_type}</Badge>
                      <EvidenceStateBadge state={resolved.reference.evidence_state} />
                      {resolved.status !== "resolved" ? (
                        <Badge tone="warning">
                          {resolved.status === "dangling_record"
                            ? "record unavailable"
                            : "field unavailable"}
                        </Badge>
                      ) : null}
                    </div>
                    <dl className="mt-4 grid gap-3 text-xs sm:grid-cols-2">
                      <Detail label="Record key" value={resolved.reference.record_key} />
                      <Detail label="Field path" value={resolved.reference.field_path} />
                      <Detail
                        label="Frame number"
                        value={resolved.reference.frame_number ?? "Not linked"}
                      />
                      <Detail
                        label="Frame context"
                        value={resolved.frame_context ?? "Not linked"}
                      />
                    </dl>
                    <div className="mt-4">
                      <p className="text-[11px] uppercase tracking-wider text-[var(--muted)]">
                        Resolved value
                      </p>
                      <pre className="forensic-text mt-2 whitespace-pre-wrap break-all rounded-lg bg-[var(--surface-raised)] p-3 text-xs">
                        {render_forensic_value(resolved.field_value)}
                      </pre>
                    </div>
                  </Card>
                ))}
              </div>
            )}
          </section>
        </div>
      ) : null}
    </Sheet>
  );
}

function ForensicText({ value }: { value: string }) {
  return (
    <bdi className="forensic-text" dir="ltr">
      {render_forensic_value(value)}
    </bdi>
  );
}

function Detail({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <dt className="text-[var(--muted)]">{label}</dt>
      <dd className="forensic-text mt-1 break-all font-medium">
        <bdi dir="ltr">{render_forensic_value(value)}</bdi>
      </dd>
    </div>
  );
}
