import { useEffect, useRef } from "react";
import { BarChart, PieChart } from "echarts/charts";
import {
  AriaComponent,
  GridComponent,
  LegendComponent,
  TitleComponent,
} from "echarts/components";
import { init, use as register_echarts, type EChartsCoreOption } from "echarts/core";
import { SVGRenderer } from "echarts/renderers";
import type { CanonicalReport } from "../core/model";
import {
  coverage_percent,
  select_coverage,
  select_protocol_counts,
  select_severity_counts,
  select_starttls_states,
  select_tls_versions,
} from "../core/selectors";
import { Card } from "./ui";

register_echarts([
  BarChart,
  PieChart,
  AriaComponent,
  GridComponent,
  LegendComponent,
  TitleComponent,
  SVGRenderer,
]);

const chart_colors = {
  high: "#CE4760",
  medium: "#ECA400",
  low: "#4A9FB3",
  informational: "#768397",
  passed: "#5CA87D",
  failed: "#CE4760",
  unknown: "#8870B1",
  not_observable: "#687487",
};

function Chart({
  option,
  label,
  test_id,
  className = "h-56",
}: {
  option: EChartsCoreOption;
  label: string;
  test_id: string;
  className?: string;
}) {
  const container_ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!container_ref.current) return;
    const chart = init(container_ref.current, undefined, { renderer: "svg" });
    const has_reduced_motion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    chart.setOption({ ...option, animation: !has_reduced_motion });
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(container_ref.current);
    return () => {
      observer.disconnect();
      chart.dispose();
    };
  }, [option]);

  return (
    <div
      aria-label={label}
      className={className}
      data-testid={test_id}
      ref={container_ref}
      role="img"
    />
  );
}

export function SeverityChart({ report }: { report: CanonicalReport }) {
  const counts = select_severity_counts(report);
  const labels = ["High", "Medium", "Low", "Informational"];
  const values = [counts.high, counts.medium, counts.low, counts.informational];
  const total = values.reduce((sum, value) => sum + value, 0);
  const option: EChartsCoreOption = {
    aria: { enabled: true, decal: { show: true } },
    grid: { left: 8, right: 24, top: 18, bottom: 8, containLabel: true },
    xAxis: {
      type: "value",
      minInterval: 1,
      axisLabel: { show: false },
      axisLine: { show: false },
      axisTick: { show: false },
      splitLine: { show: false },
    },
    yAxis: {
      type: "category",
      data: labels,
      inverse: true,
      axisLabel: { color: "#94a3b8", fontSize: 12 },
      axisLine: { show: false },
      axisTick: { show: false },
    },
    series: [
      {
        type: "bar",
        data: values.map((value, index) => ({
          value,
          itemStyle: {
            color: [
              chart_colors.high,
              chart_colors.medium,
              chart_colors.low,
              chart_colors.informational,
            ][index],
            borderRadius: 6,
          },
        })),
        barMaxWidth: 14,
        showBackground: true,
        backgroundStyle: { color: "rgba(100,116,139,.10)", borderRadius: 6 },
        label: { show: true, position: "right", color: "#cbd5e1", fontSize: 12 },
      },
    ],
  };
  return (
    <Card className="posture-metric-card posture-severity-card p-5">
      <div className="posture-card-heading"><div><p>Control failures</p><h3>Findings by severity</h3></div><span><b>{total}</b> total</span></div>
      <Chart
        label={`Severity chart: ${labels.map((label, i) => `${label} ${values[i]}`).join(", ")}`}
        option={option}
        test_id="severity-chart"
        className="h-52"
      />
    </Card>
  );
}

export function CoverageChart({ report }: { report: CanonicalReport }) {
  const coverage = select_coverage(report);
  const percent = coverage_percent(coverage);
  const data = [
    { name: "Passed", value: coverage.passed_count, itemStyle: { color: chart_colors.passed } },
    { name: "Failed", value: coverage.failed_count, itemStyle: { color: chart_colors.failed } },
    { name: "Unknown", value: coverage.unknown_count, itemStyle: { color: chart_colors.unknown } },
    {
      name: "Not observable",
      value: coverage.not_observable_count,
      itemStyle: { color: chart_colors.not_observable },
    },
  ];
  const option: EChartsCoreOption = {
    aria: { enabled: true, decal: { show: true } },
    title: {
      text: percent === null ? "—" : `${percent}%`,
      subtext: "verified pass",
      left: "center",
      top: "33%",
      textStyle: { color: "#e2e8f0", fontSize: 26, fontFamily: "JetBrains Mono" },
      subtextStyle: { color: "#94a3b8", fontSize: 11 },
    },
    legend: {
      bottom: 0,
      textStyle: { color: "#94a3b8", fontSize: 11 },
      itemWidth: 10,
      itemHeight: 10,
    },
    series: [
      {
        type: "pie",
        radius: ["52%", "72%"],
        center: ["50%", "43%"],
        avoidLabelOverlap: true,
        label: { show: false },
        data,
      },
    ],
  };
  return (
    <Card className="posture-metric-card posture-coverage-card p-5">
      <div className="posture-card-heading"><div><p>Policy execution</p><h3>Coverage disposition</h3></div><span><b>{coverage.applicable_count}</b> applicable</span></div>
      <Chart
        label={`Coverage chart: ${data.map((item) => `${item.name} ${item.value}`).join(", ")}`}
        option={option}
        test_id="coverage-chart"
        className="h-52"
      />
    </Card>
  );
}

export function InventoryChart({
  title,
  label,
  test_id,
  counts,
}: {
  title: string;
  label: string;
  test_id: string;
  counts: Record<string, number>;
}) {
  return (
    <Card className="p-4">
      <InventoryPanel counts={counts} label={label} test_id={test_id} title={title} />
    </Card>
  );
}

export function TransportProfileCard({ report }: { report: CanonicalReport }) {
  return (
    <Card className="posture-metric-card posture-transport-card p-5">
      <div className="posture-card-heading">
        <div><p>Observed transport</p><h3>Protocol and encryption profile</h3></div>
        <span><b>{report.evidence.sessions?.length ?? 0}</b> mail sessions</span>
      </div>
      <div className="transport-profile-grid">
        <InventoryPanel counts={select_protocol_counts(report)} label="Protocol inventory" test_id="protocol-chart" title="Mail protocol surface" />
        <InventoryPanel counts={select_tls_versions(report)} label="TLS versions" test_id="tls-chart" title="Negotiated TLS" />
        <InventoryPanel counts={select_starttls_states(report)} label="STARTTLS states" test_id="starttls-chart" title="Upgrade outcomes" />
      </div>
    </Card>
  );
}

function InventoryPanel({
  title,
  label,
  test_id,
  counts,
}: {
  title: string;
  label: string;
  test_id: string;
  counts: Record<string, number>;
}) {
  const entries = Object.entries(counts);
  const labels = entries.map(([name]) => name.replaceAll("_", " "));
  const values = entries.map(([, value]) => value);
  const palette = ["#5CB3C7", "#64A77C", "#E0A64A", "#8173B5", "#C95A70", "#7B8798"];
  const option: EChartsCoreOption = {
    aria: { enabled: true, decal: { show: true } },
    grid: { left: 8, right: 24, top: 18, bottom: 8, containLabel: true },
    xAxis: {
      type: "value",
      minInterval: 1,
      axisLine: { show: false },
      axisLabel: { show: false },
      axisTick: { show: false },
      splitLine: { show: false },
    },
    yAxis: {
      type: "category",
      data: labels,
      inverse: true,
      axisLabel: { color: "#94a3b8", fontSize: 11 },
      axisLine: { show: false },
      axisTick: { show: false },
    },
    series: [
      {
        type: "bar",
        data: values.map((value, index) => ({
          value,
          itemStyle: { color: palette[index % palette.length], borderRadius: 5 },
        })),
        barMaxWidth: 11,
        showBackground: true,
        backgroundStyle: { color: "rgba(100,116,139,.10)", borderRadius: 5 },
        label: { show: true, position: "right", color: "#cbd5e1", fontSize: 11 },
      },
    ],
  };
  return (
    <section className="transport-profile-panel">
      <p>{title}</p>
      {entries.length === 0 ? (
        <p className="transport-profile-empty">No observations in this capture.</p>
      ) : (
        <Chart
          label={`${label}: ${labels.map((name, index) => `${name} ${values[index]}`).join(", ")}`}
          option={option}
          test_id={test_id}
          className="h-44"
        />
      )}
    </section>
  );
}
