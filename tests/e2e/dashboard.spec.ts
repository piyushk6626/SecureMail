import { expect, test, type Page } from "@playwright/test";
import { readFile } from "node:fs/promises";
import path from "node:path";

const golden_report = path.resolve(
  process.cwd(),
  "../tests/fixtures/reports/golden_report.json",
);

async function open_catalog_case(page: Page, case_id = "dashboard_critical"): Promise<void> {
  await page.goto(`/cases/${case_id}`);
  await expect(page.getByRole("heading", { name: case_id })).toBeVisible();
}

test("switches between all four authority workspaces for a catalog case", async ({ page }) => {
  test.setTimeout(60_000);
  await open_catalog_case(page);

  await expect(page.getByRole("region", { name: "Assessment trust" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Endpoint-first risk tree" })).toBeVisible();
  await page.getByRole("tab", { name: /Findings/ }).click();
  await expect(page.getByRole("region", { name: "Deterministic Conclusions" })).toBeVisible();
  await page.getByRole("tab", { name: /Evidence/ }).click();
  await expect(page.getByRole("region", { name: "Observed Facts" })).toBeVisible();
  await page.getByRole("tab", { name: /Analysis context/ }).click();
  await expect(page.getByRole("region", { name: "Advisory / ML" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Analyst Conclusions" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Download HTML" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Download PDF" })).toBeVisible();
});

test("filters catalog summaries and selects a catalog case", async ({ page }) => {
  await page.goto("/cases");
  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();
  const cards = page.getByTestId("catalog-case");
  await expect(cards.first()).toBeVisible();

  const first_case = (await cards.first().locator("p.forensic-text").textContent())?.trim();
  expect(first_case).toBeTruthy();
  await page.getByLabel("Filter catalog").fill(first_case as string);
  await expect(cards).toHaveCount(1);
  await cards.first().getByRole("button", { name: "Open case" }).click();
  await expect(page.getByRole("heading", { name: first_case as string })).toBeVisible();
});

test("drills from a finding to the exact evidence frame", async ({ page }) => {
  await open_catalog_case(page);
  await page.getByRole("tab", { name: /Findings/ }).click();
  await page.locator(".risk-leaf").filter({ hasText: "TLS 1.0 negotiated" }).click();

  const dialog = page.getByRole("dialog", { name: "TLS 1.0 negotiated" });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText("version.selected", { exact: true })).toBeVisible();
  await expect(dialog.getByText("6", { exact: true })).toBeVisible();
  await expect(dialog.getByText(/TLS client_hello|Frame 6/)).toBeVisible();
  await expect(dialog.getByText("TLSv10", { exact: true })).toBeVisible();
});

test("renders hostile strings as visible inert forensic text", async ({ page }) => {
  await open_catalog_case(page, "dashboard_attention");
  await page.getByRole("tab", { name: /Evidence/ }).click();
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

  await page.goto("/cases");
  await page.getByTestId("catalog-case").filter({ hasText: "case-a" }).getByRole("button", { name: "Open case" }).click();
  await expect(page.getByText("Alpha-only finding", { exact: true }).first()).toBeVisible();
  await page.getByRole("link", { name: "Back to catalog" }).click();
  await page.getByTestId("catalog-case").filter({ hasText: "case-b" }).getByRole("button", { name: "Open case" }).click();
  await expect(page.getByText("Alpha-only finding")).toHaveCount(0);
  await expect(page.getByText("Bravo-only finding", { exact: true }).first()).toBeVisible();
  await page.getByRole("link", { name: "Back to catalog" }).click();
  await expect(page.getByTestId("no-case-selected")).toBeVisible();
  await expect(page.getByText("Bravo-only finding")).toHaveCount(0);
});

test("honors reduced motion and keeps coverage accessible", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce", colorScheme: "dark" });
  await open_catalog_case(page);

  const coverage = page.getByRole("region", { name: "Coverage matrix" });
  await expect(coverage).toBeVisible();
  await expect(coverage.getByRole("img", { name: /Coverage donut/ })).toBeVisible();
  await expect(coverage.getByRole("button", { name: /smtp transport/ })).toBeVisible();
  const motion_duration = await page.locator("main").evaluate((element) => {
    const probe = element.querySelector("div");
    return probe ? getComputedStyle(probe).animationDuration : "";
  });
  expect(motion_duration === "" || Number.parseFloat(motion_duration) <= 0.001).toBe(true);
  const screenshot = await page.screenshot({ animations: "disabled", fullPage: true });
  expect(screenshot.byteLength).toBeGreaterThan(10_000);
});

test("uploads a pcapng capture and can download reports", async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto("/upload");
  await page.getByLabel("Upload capture").waitFor();
  await page.locator('input[type="file"]').setInputFiles({
    name: "empty.pcapng",
    mimeType: "application/octet-stream",
    buffer: Buffer.from([0x0a, 0x0d, 0x0d, 0x0a, 0x1a, 0x2b, 0x3c, 0x4d]),
  });
  await expect(page.getByRole("link", { name: "Download HTML" })).toBeVisible({ timeout: 120_000 });
  await expect(page.getByRole("link", { name: "Download PDF" })).toBeVisible();
  const html = page.getByRole("link", { name: "Download HTML" });
  await expect(html).toHaveAttribute("href", /\/api\/v1\/analyses\/.+\/report\.html/);
});

test("keeps download actions keyboard-focusable", async ({ page }) => {
  await open_catalog_case(page);
  const html = page.getByRole("link", { name: "Download HTML" });
  await html.focus();
  await expect(html).toBeFocused();
  const overview = page.getByRole("tab", { name: "Overview" });
  await overview.focus();
  await page.keyboard.press("ArrowRight");
  await expect(page.getByRole("tab", { name: /Findings/ })).toHaveAttribute("aria-selected", "true");
  await page.keyboard.press("End");
  await expect(page.getByRole("tab", { name: /Analysis context/ })).toHaveAttribute("aria-selected", "true");
});

test("opens a catalog case on a mobile viewport without leaking cases", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/cases");
  await expect(page.getByTestId("no-case-selected")).toBeVisible();
  await page.getByTestId("catalog-case").filter({ hasText: "dashboard_clear" }).getByRole("button", { name: "Open case" }).click();
  await expect(page.getByRole("heading", { name: "dashboard_clear" })).toBeVisible();
  await page.getByRole("link", { name: "Back to catalog" }).click();
  await expect(page.getByTestId("no-case-selected")).toBeVisible();
});

test("stays dark-only with a logo and without removed header controls", async ({ page }) => {
  await page.goto("/cases");
  await expect(page.getByRole("img", { name: "SecureMail" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Upload capture" })).toBeVisible();
  await expect(page.getByText("API online")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Portfolio", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Case", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /theme/i })).toHaveCount(0);
  const color_scheme = await page.locator(":root").evaluate((element) => getComputedStyle(element).colorScheme);
  expect(color_scheme).toContain("dark");
});
