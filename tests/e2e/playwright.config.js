// Playwright configuration. BASE_URL and the seeded accounts come from the
// throwaway stack (scripts/test-stack.sh writes them to stack.env, which
// scripts/test-frontend.sh passes as environment variables).
// @ts-check
const { defineConfig, devices } = require("@playwright/test");

const out = process.env.PLAYWRIGHT_OUT || "out";

module.exports = defineConfig({
  testDir: "./specs",
  fullyParallel: true,
  workers: process.env.PW_WORKERS ? Number(process.env.PW_WORKERS) : 2,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  outputDir: `${out}/artifacts`,
  reporter: [
    ["list"],
    ["html", { outputFolder: `${out}/html`, open: "never" }],
    ["json", { outputFile: `${out}/results.json` }],
  ],
  use: {
    baseURL: process.env.BASE_URL || "http://localhost:8080",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "off",
  },
  // Browsers offer WebAuthn only in a secure context, and a *.localhost name
  // is one. The throwaway stack is told that WEBAUTHN_URL is its address;
  // here that name is pointed at the application's container.
  projects: [{
    name: "chromium",
    use: {
      ...devices["Desktop Chrome"],
      launchOptions: { args: process.env.WEBAUTHN_URL ? [`--host-resolver-rules=MAP ${new URL(process.env.WEBAUTHN_URL).hostname} ${new URL(process.env.BASE_URL).hostname}`] : [] },
    },
  }],
});
