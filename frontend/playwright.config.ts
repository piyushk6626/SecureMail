import { defineConfig, devices } from "@playwright/test";

const repositoryRoot = "..";

export default defineConfig({
  testDir: "../tests/e2e",
  testMatch: "dashboard.spec.ts",
  fullyParallel: false,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: process.env.CI ? [["html", { open: "never" }], ["line"]] : "list",
  use: {
    baseURL: "http://127.0.0.1:5173",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  expect: {
    toHaveScreenshot: { animations: "disabled" },
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: [
    {
      command:
        "SECUREMAIL_REPORT_ROOT=tests/fixtures/dashboard uv run --extra api uvicorn securemail.api.main:app --host 127.0.0.1 --port 8011",
      cwd: repositoryRoot,
      url: "http://127.0.0.1:8011/api/v1/health",
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
    },
    {
      command:
        "VITE_API_TARGET=http://127.0.0.1:8011 npm run dev -- --host 127.0.0.1 --port 5173",
      cwd: ".",
      url: "http://127.0.0.1:5173",
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
    },
  ],
});
