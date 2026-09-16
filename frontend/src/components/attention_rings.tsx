import type { CanonicalReport } from "../core/model";
import { select_attention_metrics, type AttentionMetric } from "../core/selectors";

const ring_radius = [56, 47, 38, 29];

function ratio(metric: AttentionMetric): number {
  if (metric.denominator === 0) return 0;
  return Math.min(1, metric.numerator / metric.denominator);
}

function Ring({ metric, index }: { metric: AttentionMetric; index: number }) {
  const radius = ring_radius[index] ?? 29;
  const attention_share = ratio(metric);
  const inverse_share = 1 - attention_share;
  const dash = `${inverse_share * 100} 100`;
  if (metric.denominator === 0) return null;
  return (
    <circle
      className={`attention-ring attention-ring-inverse attention-ring-${metric.tone}`}
      cx="70"
      data-attention-share={attention_share.toFixed(4)}
      data-inverted-share={inverse_share.toFixed(4)}
      cy="70"
      fill="none"
      pathLength="100"
      r={radius}
      strokeDasharray={dash}
      strokeDashoffset="0"
      strokeWidth="7"
      transform="rotate(-90 70 70)"
    />
  );
}

function Rail({ index }: { index: number }) {
  const radius = ring_radius[index] ?? 29;
  return <circle className="attention-ring-rail" cx="70" cy="70" fill="none" r={radius} strokeWidth="7" />;
}

export function AttentionRings({ report }: { report: CanonicalReport }) {
  const metrics = select_attention_metrics(report);
  const priority = report.evidence.posture.risk_score;
  return (
    <section aria-label="Concentric attention load" className="attention-rings">
      <p className="section-label">Concentric attention load</p>
      <div className="attention-rings-visual">
        <svg aria-label="Inverse-filled rings begin at twelve o’clock and show the complement of each attention share; exact attention values are listed below" role="img" viewBox="0 0 140 140">
          {metrics.map((metric, index) => <Rail index={index} key={`rail-${metric.id}`} />)}
          {metrics.map((metric, index) => <Ring index={index} key={metric.id} metric={metric} />)}
        </svg>
        <div className="attention-centre">
          <b>{priority ?? "Not proven"}</b>
          <span>endpoint priority · 0–100</span>
        </div>
      </div>
      <p className="attention-note">Coloured arcs begin at 12 o’clock and show the inverse share; exact values below show attention required. This is not a system-health score.</p>
      <dl className="attention-metrics-grid">
        {metrics.map((metric) => {
          const percentage = metric.denominator === 0 ? null : Math.round((metric.numerator / metric.denominator) * 100);
          return <div className="attention-metric-chip" key={metric.id}><dt><i className={`attention-key attention-key-${metric.tone}`} />{metric.label}</dt><dd>{percentage === null ? "No applicable data" : <><b>{metric.numerator} / {metric.denominator}</b><span>{percentage}% attention</span></>}</dd>{metric.split ? <small><i className="attention-key attention-key-unknown" />{metric.split.unknown} unknown <i className="attention-key attention-key-not_observable" />{metric.split.not_observable} not observable</small> : null}</div>;
        })}
      </dl>
    </section>
  );
}
