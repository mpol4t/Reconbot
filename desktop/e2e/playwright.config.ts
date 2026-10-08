import { defineConfig } from "@playwright/test";
import path from "node:path";

export default defineConfig({
  testDir: path.resolve(__dirname),
  testMatch: /.*\.spec\.ts/,
  outputDir: path.resolve(__dirname, "../test-results/artifacts"),
  fullyParallel: false,
  workers: 1,
  timeout: 90_000,
  expect: { timeout: 8_000 },
  reporter: [
    ["line"],
    ["junit", { outputFile: path.resolve(__dirname, "../test-results/junit.xml") }]
  ],
  use: {
    screenshot: "only-on-failure",
    trace: "retain-on-failure"
  }
});
