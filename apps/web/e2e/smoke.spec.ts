import { createHash, randomBytes } from "node:crypto";

import { expect, test } from "@playwright/test";

/**
 * M1 golden path against the real stack: register -> create case -> upload evidence ->
 * hashes shown match locally computed ones -> verify -> custody chain.
 */
test("register, open a case, upload evidence, verify integrity", async ({ page }) => {
  const errors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });

  const email = `e2e-${Date.now()}-${randomBytes(3).toString("hex")}@example.com`;
  const evidence = randomBytes(64 * 1024);
  const sha256 = createHash("sha256").update(evidence).digest("hex");

  // Register -> lands on the new organization's overview.
  await page.goto("/register");
  // Wait for hydration (first dev-mode load compiles the route) before typing.
  await page.waitForLoadState("networkidle");
  await page.getByLabel("Your name").fill("E2E Analyst");
  await page.getByLabel("Organization").fill("E2E Blue Team");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(page.getByText("E2E Blue Team").first()).toBeVisible();

  // Create an investigation.
  await page.getByRole("link", { name: "Investigations" }).first().click();
  await page.getByRole("button", { name: "New investigation" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Title", { exact: true }).fill("E2E beaconing case");
  await dialog.getByRole("button", { name: "Create" }).click();
  await expect(page.getByRole("heading", { name: "E2E beaconing case" })).toBeVisible();
  await expect(page.getByText(/CASE-00001/).first()).toBeVisible();

  // Upload evidence through the real file input.
  // M6: the uploader lives in the case workspace's Evidence tab.
  await page.getByRole("tablist", { name: "Case sections" }).getByRole("tab", { name: "Evidence", exact: true }).click();
  await page.locator('input[type="file"]').setInputFiles({
    name: "capture.pcap",
    mimeType: "application/octet-stream",
    buffer: evidence,
  });
  await expect(page.getByText("Uploaded and hashed").first()).toBeVisible();
  const row = page.getByRole("row", { name: /capture\.pcap/ });
  await expect(row).toContainText(sha256.slice(0, 12));

  // Evidence detail: full SHA-256, verify, custody chain.
  await row.getByRole("link", { name: "capture.pcap" }).click();
  await expect(page.getByText(sha256, { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByText(/Integrity verified/).first()).toBeVisible();
  // Uploads are also queued for an automatic analysis (AV scan), which adds custody events
  // asynchronously: assert the events this flow produced rather than an exact count.
  await expect(page.locator("p", { hasText: /^Uploaded$/ })).toBeVisible(); // custody entry
  await expect(page.getByText("Verified: hashes match")).toBeVisible();

  // Sign out -> protected pages redirect to login.
  await page.getByRole("button", { name: /E2E Analyst/ }).click();
  await page.getByRole("menuitem", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login/);

  expect(errors).toEqual([]);
});
