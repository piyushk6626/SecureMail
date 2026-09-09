import { useId, useState } from "react";
import type { CSSProperties, KeyboardEvent } from "react";
import type { CanonicalReport } from "../core/model";
import {
  coverage_percent,
  select_coverage,
  select_findings,
  select_severity_counts,
  select_starttls_states,
} from "../core/selectors";

interface RingMetric {
  colors: [string, string];
  detail: string;
  label: string;
  position: string;
  progress: number;
  value: string;
}

export function AnalystRings({ report }: { report: CanonicalReport }) {
  const gradient_id = useId().replaceAll(":", "");
  const [hovered_ring, set_hovered_ring] = useState<number | null>(null);
  const [selected_ring, set_selected_ring] = useState(0);
  const findings = select_findings(report);
  const severity = select_severity_counts(report);
  const coverage = select_coverage(report);
  const coverage_value = coverage_percent(coverage) ?? 0;
  const sessions = report.evidence.sessions ?? [];
  const upgrades = select_starttls_states(report);
  const upgrade_issues = (upgrades.violation ?? 0) + (upgrades.plaintext_fallback ?? 0);
  const certificates = report.evidence.certificates ?? [];
  const certificate_issues = certificates.filter(
    (certificate) =>
      certificate.valid_at_capture_time === false ||
      certificate.validation?.identity_match === false ||
      certificate.validation?.path_valid_at_capture_time === false,
  ).length;
  const finding_readiness = findings.length === 0 ? 100 : ratio(findings.length - severity.high, findings.length);
  const upgrade_readiness = ratio(sessions.length - upgrade_issues, sessions.length);
  const certificate_readiness = ratio(certificates.length - certificate_issues, certificates.length);
  const rings: [RingMetric, RingMetric, RingMetric, RingMetric] = [
    {
      colors: ["#CE4760", "#CE4760"],
      detail: "Share of deterministic findings that are outside the high-severity queue.",
      label: "High-risk clearance",
      position: "Ring 1 · outer",
      progress: finding_readiness,
      value: `${severity.high} high`,
    },
    {
      colors: ["#D6FF01", "#CFFC02"],
      detail: "Policy checks passed across the controls that were applicable to this capture.",
      label: "Verified controls",
      position: "Ring 2",
      progress: coverage_value,
      value: coverage.applicable_count === 0 ? "not assessed" : `${coverage.passed_count}/${coverage.applicable_count}`,
    },
    {
      colors: ["#ECA400", "#ECA400"],
      detail: "Observed mail sessions without STARTTLS violations or plaintext fallback.",
      label: "Secure upgrades",
      position: "Ring 3",
      progress: upgrade_readiness,
      value: sessions.length === 0 ? "not observed" : `${upgrade_issues} issues`,
    },
    {
      colors: ["#01E6F6", "#03B9C2"],
      detail: "Observed certificates without expiry, identity, or path-validation failure.",
      label: "Certificate health",
      position: "Ring 4 · inner",
      progress: certificate_readiness,
      value: certificates.length === 0 ? "not observed" : `${certificate_issues} issues`,
    },
  ];
  const risk_score = report.evidence.posture.risk_score;
  const default_ring = rings[0];
  const displayed_ring = rings[hovered_ring ?? selected_ring] ?? default_ring;

  function select_with_keyboard(event: KeyboardEvent<SVGGElement>, index: number) {
    if (event.key !== "Enter" && event.key !== " ") return;
    event.preventDefault();
    set_selected_ring(index);
  }

  return (
    <div className="analyst-rings">
      <div className="analyst-rings-stage">
        <div className="analyst-rings-graphic">
          <svg
            aria-label="Case posture rings. Hover or focus a ring to inspect its metric."
            role="group"
            viewBox="0 0 260 260"
          >
            <defs>
              {rings.map((ring, index) => (
                <linearGradient id={`${gradient_id}-${index}`} key={ring.label} x1="0" x2="1" y1="0" y2="1">
                  <stop offset="0%" stopColor={ring.colors[0]} />
                  <stop offset="100%" stopColor={ring.colors[1]} />
                </linearGradient>
              ))}
            </defs>
            {rings.map((ring, index) => {
              const radius = 112 - index * 23;
              const active = hovered_ring === index;
              return (
                <g
                  aria-label={`${ring.position}, ${ring.label}: ${ring.progress} percent clear, ${ring.value}`}
                  className="analyst-ring"
                  data-active={active}
                  key={ring.label}
                  onBlur={() => set_hovered_ring(null)}
                  onClick={() => set_selected_ring(index)}
                  onFocus={() => set_hovered_ring(index)}
                  onKeyDown={(event) => select_with_keyboard(event, index)}
                  onPointerEnter={() => set_hovered_ring(index)}
                  onPointerLeave={() => set_hovered_ring(null)}
                  role="button"
                  style={{ "--ring-color": ring.colors[0] } as CSSProperties}
                  tabIndex={0}
                >
                  <circle className="analyst-ring-track" cx="130" cy="130" pathLength="100" r={radius} />
                  <circle
                    className="analyst-ring-value"
                    cx="130"
                    cy="130"
                    pathLength="100"
                    r={radius}
                    style={{ stroke: `url(#${gradient_id}-${index})`, strokeDasharray: `${ring.progress} 100` }}
                  />
                </g>
              );
            })}
          </svg>
          <div className="analyst-rings-center">
            <span className="font-mono text-4xl font-semibold">{risk_score ?? "—"}</span>
            <span>case risk</span>
          </div>
        </div>
        <aside
          aria-live="polite"
          className="ring-metric-card"
          style={{ "--ring-color": displayed_ring.colors[0] } as CSSProperties}
        >
          <p className="ring-metric-position">{displayed_ring.position}</p>
          <h3>{displayed_ring.label}</h3>
          <div className="ring-metric-reading">
            <b>{displayed_ring.value}</b>
            <span>{displayed_ring.progress}% clear</span>
          </div>
          <div aria-hidden="true" className="ring-metric-progress">
            <span style={{ width: `${displayed_ring.progress}%` }} />
          </div>
          <p>{displayed_ring.detail}</p>
          <small>Hover a ring to compare</small>
        </aside>
      </div>
      <div className="analyst-rings-legend">
        {rings.map((ring, index) => (
          <button
            aria-pressed={selected_ring === index}
            className="ring-legend-item"
            key={ring.label}
            onBlur={() => set_hovered_ring(null)}
            onClick={() => set_selected_ring(index)}
            onFocus={() => set_hovered_ring(index)}
            onPointerEnter={() => set_hovered_ring(index)}
            onPointerLeave={() => set_hovered_ring(null)}
            type="button"
          >
            <span
              className="ring-legend-swatch"
              style={{ background: `linear-gradient(135deg, ${ring.colors[0]}, ${ring.colors[1]})` }}
            />
            <span className="min-w-0">
              <span className="ring-legend-position">{ring.position}</span>
              <span className="block truncate text-xs">{ring.label}</span>
              <b className="mt-0.5 block font-mono text-sm">{ring.value}</b>
            </span>
            <span className="ml-auto font-mono text-xs text-[var(--muted)]">{ring.progress}%</span>
          </button>
        ))}
      </div>
      <p className="mt-3 text-center text-xs text-[var(--muted)]">Arc length shows the share currently clear within observed scope.</p>
    </div>
  );
}

function ratio(clear: number, total: number): number {
  if (total <= 0) return 0;
  return Math.round((Math.max(0, clear) / total) * 100);
}
