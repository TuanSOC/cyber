import { randomBytes } from "node:crypto";

import { expect, test } from "@playwright/test";

/**
 * M2 golden path: upload a synthetic capture -> automatic analysis by the isolated worker
 * (real Zeek / Suricata with the ET Open snapshot) -> trusted ingest -> results in the UI.
 * The capture comes from the synthetic dataset (scripts/e2e.mjs generates it into /data).
 */
test("a capture upload is analyzed automatically and its findings are shown", async ({ page }) => {
  test.setTimeout(6 * 60_000);
  const errors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });

  const email = `e2e-pcap-${Date.now()}-${randomBytes(3).toString("hex")}@example.com`;
  await page.goto("/register");
  await page.waitForLoadState("networkidle");
  await page.getByLabel("Your name").fill("PCAP Analyst");
  await page.getByLabel("Organization").fill("E2E PCAP Team");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();

  await page.getByRole("link", { name: "Investigations" }).first().click();
  await page.getByRole("button", { name: "New investigation" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Title", { exact: true }).fill("Synthetic capture review");
  await dialog.getByRole("button", { name: "Create" }).click();
  await expect(page.getByRole("heading", { name: "Synthetic capture review" })).toBeVisible();

  // M6: the uploader lives in the case workspace's Evidence tab.
  await page.getByRole("tablist", { name: "Case sections" }).getByRole("tab", { name: "Evidence", exact: true }).click();
  await page.locator('input[type="file"]').setInputFiles("/data/mixed.pcap");
  await expect(page.getByText("Uploaded and hashed").first()).toBeVisible();

  // The upload queued an analysis automatically; wait for the pipeline to finish.
  await page.getByRole("link", { name: "PCAP Analyzer" }).first().click();
  const row = page.getByRole("row", { name: /mixed\.pcap/ }).first();
  await expect(row).toBeVisible();
  await expect(row.getByText("Succeeded")).toBeVisible({ timeout: 5 * 60_000 });
  await row.getByRole("link", { name: "Details" }).click();

  await page.getByRole("tab", { name: "Findings" }).click();
  await expect(page.getByText("Periodic connections (beacon-like)")).toBeVisible();
  await expect(page.getByText("Port scan (vertical)")).toBeVisible();
  await expect(page.getByText(/not verdicts/)).toBeVisible();

  await page.getByRole("tab", { name: "Flows" }).click();
  await expect(page.getByText("203.0.113.50").first()).toBeVisible();

  expect(errors).toEqual([]);
});
