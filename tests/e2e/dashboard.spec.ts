import { expect, test, type Page } from "@playwright/test";
import { readFile } from "node:fs/promises";
import path from "node:path";

const golden_report = path.resolve(
  process.cwd(),
  "../tests/fixtures/reports/golden_report.json",
);

async function upload_golden_report(page: Page): Promise<void> {
  await page.goto("/");
  await page.getByLabel("Select a case").waitFor();
  await page.locator('input[type="file"]').setInputFiles(golden_report);
  await expect(page.getByRole("heading", { name: "reports_golden" })).toBeVisible();
}

test("uploads a report and preserves all four authority regions", async ({ page }) => {
  await upload_golden_report(page);

  await expect(page.getByRole("region", { name: "Observed Facts" })).toBeVisible();
  await expect(
    page.getByRole("region", { name: "Deterministic Conclusions" }),
  ).toBeVisible();
  await expect(page.getByRole("region", { name: "Advisory / ML" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Analyst Notes" })).toBeVisible();
  await expect(page.getByText("No advisory analysis is present")).toBeVisible();
  await expect(page.getByText("No analyst notes were published")).toBeVisible();
});

test("filters portfolio summaries and selects a catalog case", async ({ page }) => {
  await page.goto("/");
  const selector = page.getByLabel("Select a case");
  await selector.waitFor();
  const options = await selector.locator("option").allTextContents();
  expect(options.length).toBeGreaterThan(1);

  await page.getByRole("button", { name: "Portfolio" }).click();
  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();
  const cards = page.getByTestId("portfolio-case");
  await expect(cards.first()).toBeVisible();

  const first_case = (await cards.first().locator("p.forensic-text").textContent())?.trim();
  expect(first_case).toBeTruthy();
  await page.getByLabel("Filter portfolio").fill(first_case as string);
  await expect(cards).toHaveCount(1);
  await cards.first().getByRole("button", { name: "Open case" }).click();
  await expect(page.getByRole("heading", { name: first_case as string })).toBeVisible();
});

test("drills from a finding to the exact evidence frame", async ({ page }) => {
  await upload_golden_report(page);
  await page.getByRole("button", { name: /TLS 1\.0 negotiated/ }).click();

  const dialog = page.getByRole("dialog", { name: "TLS 1.0 negotiated" });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText("version.selected", { exact: true })).toBeVisible();
  await expect(dialog.getByText("6", { exact: true })).toBeVisible();
  await expect(dialog.getByText(/TLS client_hello|Frame 6/)).toBeVisible();
  await expect(dialog.getByText("TLSv10", { exact: true })).toBeVisible();
});

test("renders hostile strings as visible inert forensic text", async ({ page }) => {
  await upload_golden_report(page);
  const facts = page.getByRole("region", { name: "Observed Facts" });

  await expect(facts.getByText(/<script>alert\(1\)<\/script>/)).toBeVisible();
  await expect(facts.getByText(/U\+0007 BELL/)).toBeVisible();
  await expect(facts.getByText(/U\+0000 NULL/)).toBeVisible();
  await expect(facts.getByText(/U\+202E RIGHT-TO-LEFT OVERRIDE/)).toBeVisible();
  await expect(facts.locator("script")).toHaveCount(0);
  await expect(page.locator("body")).not.toHaveAttribute("onerror");
});

test("clears and switches cases without stale evidence", async ({ page }) => {
  const report_a = JSON.parse(await readFile(golden_report, "utf8"));
  const report_b = structuredClone(report_a);
  report_a.manifest.case_id = "case-a";
  report_b.manifest.case_id = "case-b";
  report_a.evidence.posture.prioritized_findings[0].title = "Alpha-only finding";
  report_b.evidence.posture.prioritized_findings[0].title = "Bravo-only finding";

  await page.route("**/api/v1/cases", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        cases: [
          { case_id: "case-a", generated_at: "2026-09-04T12:00:00Z", assessment_state: "limited", risk_score: 90, finding_count: 7, unknown_count: 2, not_observable_count: 1 },
          { case_id: "case-b", generated_at: "2026-09-04T12:00:00Z", assessment_state: "limited", risk_score: 50, finding_count: 7, unknown_count: 2, not_observable_count: 1 },
        ],
      }),
    });
  });
  await page.route("**/api/v1/cases/case-a/report", async (route) => {
    await route.fulfill({ contentType: "application/json", body: JSON.stringify(report_a) });
  });
  await page.route("**/api/v1/cases/case-b/report", async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 150));
    await route.fulfill({ contentType: "application/json", body: JSON.stringify(report_b) });
  });

  await page.goto("/");
  await page.getByLabel("Select a case").selectOption("case-a");
  await expect(page.getByText("Alpha-only finding")).toBeVisible();
  await page.getByLabel("Select a case").selectOption("case-b");
  await expect(page.getByText("Alpha-only finding")).toHaveCount(0);
  await expect(page.getByText("Bravo-only finding")).toBeVisible();
  await page.getByRole("button", { name: "Clear case" }).click();
  await expect(page.getByTestId("no-case-selected")).toBeVisible();
  await expect(page.getByText("Bravo-only finding")).toHaveCount(0);
});

test("honors reduced motion and keeps charts accessible", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce", colorScheme: "dark" });
  await upload_golden_report(page);

  const severity_chart = page.getByTestId("severity-chart");
  const coverage_chart = page.getByTestId("coverage-chart");
  await expect(severity_chart).toHaveAttribute("role", "img");
  await expect(severity_chart).toHaveAttribute("aria-label", /chart/i);
  await expect(coverage_chart).toHaveAttribute("role", "img");
  await expect(coverage_chart).toHaveAttribute("aria-label", /chart/i);
  const motion_duration = await page.locator("main").evaluate((element) => {
    const probe = element.querySelector("div");
    return probe ? getComputedStyle(probe).animationDuration : "";
  });
  expect(motion_duration === "" || Number.parseFloat(motion_duration) <= 0.001).toBe(true);
  const screenshot = await page.screenshot({ animations: "disabled", fullPage: true });
  expect(screenshot.byteLength).toBeGreaterThan(10_000);
});
