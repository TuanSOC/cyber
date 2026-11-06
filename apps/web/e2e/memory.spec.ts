import { randomBytes } from "node:crypto";

import { expect, test } from "@playwright/test";

/**
 * M8 golden path (phase 11). The image is the phase-4 synthetic Linux image (LiME), generated
 * by scripts/e2e.mjs into /data/memory; its ISF (our own, for a fictional kernel) is in the
 * stack's symbol store, so the real Volatility 2.28.2 runs offline in the isolated worker.
 *
 * 1. A `kind=memory` upload is restricted at once (TLP:RED badge) and gets no automatic job.
 * 2. Triage from the evidence page: the job page shows the restricted banner, the plugin
 *    strip with the plugins the synthetic kernel cannot satisfy marked "Failed", and the
 *    process tree.
 * 3. While restricted the IOC tab offers no "Enrich"; an admin releases the image (the
 *    acknowledgement and a reason), then clears the AI / TI flags in the evidence share
 *    policy (two audited steps); only then does "Enrich IOCs" appear (RT16).
 *
 * The replay-engine Windows job (hidden process, memory regions) is covered end to end by
 * the API pipeline test (`MEMORY_E2E=replay`), not here: e2e never runs the replay engine.
 * On the prod-like stack (E2E_PROD) the store holds no synthetic ISF: the spec is skipped.
 */
test("a memory image is restricted, analysed offline and released in two steps", async ({ page }) => {
  test.skip(!!process.env.E2E_PROD, "the prod-like stack has no synthetic ISF in its symbol store");
  test.setTimeout(10 * 60_000);
  const errors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });

  const email = `e2e-memory-${Date.now()}-${randomBytes(3).toString("hex")}@example.com`;
  await page.goto("/register");
  await page.waitForLoadState("networkidle");
  await page.getByLabel("Your name").fill("Memory Analyst");
  await page.getByLabel("Organization").fill("E2E Memory Team");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();

  await page.getByRole("link", { name: "Investigations" }).first().click();
  await page.getByRole("button", { name: "New investigation" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Title", { exact: true }).fill("Server memory triage");
  await dialog.getByRole("button", { name: "Create" }).click();
  await expect(page.getByRole("heading", { name: "Server memory triage" })).toBeVisible();

  // 1. Upload as a memory image: restricted from the upload, never analysed automatically.
  await page.getByRole("tablist", { name: "Case sections" }).getByRole("tab", { name: "Evidence", exact: true }).click();
  await page.getByLabel("This is a memory image").check();
  await page.locator('input[type="file"]').setInputFiles("/data/memory/synthetic.lime");
  await expect(page.getByText("Uploaded and hashed").first()).toBeVisible();
  await page.getByRole("link", { name: "synthetic.lime" }).first().click();
  await expect(page.getByText("Memory image · restricted (TLP:RED)")).toBeVisible();
  await expect(page.getByText(/^Not analyzed\./)).toBeVisible();

  // 2. Triage, then the job page.
  await page.getByRole("button", { name: "Run memory analysis" }).click();
  const run = page.getByRole("dialog");
  await run.getByRole("button", { name: "Run memory analysis" }).click();
  await expect(page.getByText("Succeeded").first()).toBeVisible({ timeout: 8 * 60_000 });
  await page.getByRole("link", { name: "Details" }).first().click();

  await expect(page.getByTestId("sensitivity-banner")).toBeVisible();
  await expect(page.getByText("Restricted memory image")).toBeVisible();
  const steps = page.getByRole("list", { name: "Analysis steps" });
  await expect(steps.getByText("linux.pslist")).toBeVisible();
  const bash = steps.getByRole("listitem").filter({ hasText: "linux.bash" });
  await expect(bash.getByText("Failed")).toBeVisible();
  await expect(steps.getByRole("listitem").filter({ hasText: "linux.psaux" }).getByText("OK")).toBeVisible();

  const tabs = page.getByRole("tablist", { name: "Memory analysis results" });
  await tabs.getByRole("tab", { name: "Processes" }).click();
  await page.getByRole("group", { name: "Process view" }).getByRole("button", { name: /tree/i }).click();
  const tree = page.getByRole("treegrid", { name: "Process tree" });
  // Tree rows are "<pid> <name>" toggles; init_task (pid 0) is the list head, never listed.
  await expect(tree.getByRole("button", { name: "1 systemd" })).toBeVisible();
  await expect(tree.getByRole("button", { name: "2 kthreadd" })).toBeVisible();

  // 3. Restricted: no Enrich on the IOC tab.
  await tabs.getByRole("tab", { name: "IOCs" }).click();
  await expect(page.getByText(/Threat-intel enrichment is off: this memory image is restricted/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Enrich IOCs" })).toHaveCount(0);

  // The admin's release (acknowledged, with a reason) ...
  await page.getByTestId("sensitivity-banner").getByRole("button", { name: "Release…" }).click();
  const release = page.getByRole("dialog");
  await release.getByRole("checkbox").check();
  await release.getByLabel(/^Reason/).fill("E2E: synthetic image, nothing personal in it");
  await release.getByRole("button", { name: "Release", exact: true }).click();
  await expect(page.getByText("Memory image released by an admin")).toBeVisible();

  // ... then the share policy (the second, separate step).
  const jobUrl = page.url();
  await page.getByRole("link", { name: "evidence share policy" }).click();
  for (const label of ["Do not send to AI", "Do not send to threat-intel providers"]) {
    const toggle = page.getByRole("switch", { name: new RegExp(label) });
    // Controlled by the saved policy: it flips once the PUT succeeded.
    await toggle.click();
    await expect(toggle).not.toBeChecked();
  }
  await page.goto(jobUrl);
  await page.getByRole("tablist", { name: "Memory analysis results" }).getByRole("tab", { name: "IOCs" }).click();
  await expect(page.getByText("updates.example.com").first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Enrich IOCs" })).toBeVisible();

  expect(errors).toEqual([]);
});
