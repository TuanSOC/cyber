import { defineConfig, devices } from "@playwright/test";

// Runs inside the `e2e` compose service against the real stack behind the gateway.
export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  expect: { timeout: 15_000 },
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://gateway:8080",
    trace: "retain-on-failure",
    // The prod-like stack uses Caddy's internal CA (`pnpm e2e --prod`).
    ignoreHTTPSErrors: process.env.E2E_IGNORE_HTTPS_ERRORS === "1",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
