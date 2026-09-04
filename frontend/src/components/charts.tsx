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
import { select_coverage, select_severity_counts } from "../core/selectors";
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
  high: "#ef4444",
  medium: "#f59e0b",
  low: "#06b6d4",
  informational: "#64748b",
  passed: "#10b981",
  failed: "#ef4444",
  unknown: "#8b5cf6",
  not_observable: "#64748b",
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
  const option: EChartsCoreOption = {
    aria: { enabled: true, decal: { show: true } },
    grid: { left: 6, right: 12, top: 18, bottom: 4, containLabel: true },
    xAxis: {
      type: "category",
      data: labels,
      axisLine: { lineStyle: { color: "#475569" } },
      axisLabel: { color: "#94a3b8", fontSize: 11 },
      axisTick: { show: false },
    },
    yAxis: {
      type: "value",
      minInterval: 1,
      axisLabel: { color: "#94a3b8" },
      splitLine: { lineStyle: { color: "rgba(100,116,139,.16)" } },
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
            borderRadius: [5, 5, 0, 0],
          },
        })),
        barMaxWidth: 36,
      },
    ],
  };
  return (
    <Card className="p-4">
      <p className="text-xs font-semibold uppercase tracking-[0.12em] text-[var(--muted)]">
        Findings by severity
      </p>
      <Chart
        label={`Severity chart: ${labels.map((label, i) => `${label} ${values[i]}`).join(", ")}`}
        option={option}
        test_id="severity-chart"
      />
    </Card>
  );
}

export function CoverageChart({ report }: { report: CanonicalReport }) {
  const coverage = select_coverage(report);
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
    legend: {
      bottom: 0,
      textStyle: { color: "#94a3b8", fontSize: 11 },
      itemWidth: 10,
      itemHeight: 10,
    },
    series: [
      {
        type: "pie",
        radius: ["48%", "70%"],
        center: ["50%", "43%"],
        avoidLabelOverlap: true,
        label: { show: false },
        data,
      },
    ],
  };
  return (
    <Card className="p-4">
      <p className="text-xs font-semibold uppercase tracking-[0.12em] text-[var(--muted)]">
        Coverage disposition
      </p>
      <Chart
        label={`Coverage chart: ${data.map((item) => `${item.name} ${item.value}`).join(", ")}`}
        option={option}
        test_id="coverage-chart"
      />
    </Card>
  );
}
