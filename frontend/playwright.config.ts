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
        "mkdir -p out/e2e-data && cp tests/fixtures/dashboard/*.json out/e2e-data/ && .venv/bin/uvicorn securemail.api.main:app --host 127.0.0.1 --port 8011",
      cwd: repositoryRoot,
      url: "http://127.0.0.1:8011/api/v1/health",
      reuseExistingServer: false,
      timeout: 120_000,
      env: {
        ...process.env,
        DYLD_FALLBACK_LIBRARY_PATH: [
          "/opt/homebrew/lib",
          process.env.DYLD_FALLBACK_LIBRARY_PATH ?? "",
        ]
          .filter((item) => item.length > 0)
          .join(":"),
        SECUREMAIL_REPORT_ROOT: "out/e2e-data",
        SECUREMAIL_DATA_ROOT: "out/e2e-data",
        SECUREMAIL_START_WORKER: "1",
        SECUREMAIL_ANALYSIS_STUB: "1",
      },
    },
    {
      command:
        "VITE_API_TARGET=http://127.0.0.1:8011 npm run dev -- --host 127.0.0.1 --port 5173",
      cwd: ".",
      url: "http://127.0.0.1:5173",
      reuseExistingServer: false,
      timeout: 120_000,
    },
  ],
});
