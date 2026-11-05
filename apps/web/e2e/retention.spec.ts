import { randomBytes } from "node:crypto";

import { type Page, expect, test } from "@playwright/test";

/**
 * M7 retention, legal hold and operations, dev and prod alike. Nothing is purged here:
 * enforcement is never turned on (its typed acknowledgement is checked, then cancelled), and
 * the lowered value is far above anything this run creates and only pending (the delay).
 *
 *  1. As the owner (registered here): Settings -> Retention; the platform floor is enforced in
 *     the form; a lowered value asks for confirmation and shows as pending with its date.
 *  2. Preview (with the pending value) shows per-category counts; a manual dry run completes and
 *     its detail says nothing was deleted; the enforce dialog keeps its button disabled until
 *     the organization name is typed.
 *  3. A case legal hold -> the badge and the hold on the case and in the org list; the preview
 *     counts the active hold.
 *  4. The seeded purged evidence shows the purged strip; Download is disabled.
 *  5. The viewer sees the policy, the hold and the badge, but no action.
 *  6. The owner releases the hold (protected for the delay); Operations lists the e2e job.
 *  No console errors on the owner's page.
 *
 * Seed contract (scripts/e2e.mjs, the e2e-only owner step; never a production API path):
 *  - E2E_SEED_EMAIL / E2E_SEED_PASSWORD: an active user that can sign in. The owner adds it to
 *    this run's organization as a viewer, so this spec needs only one registration (the
 *    register limit is 5 per 10 minutes per IP).
 *  - E2E_SEED_PURGED_EVIDENCE: `<orgId>/<evidenceId>`, an evidence of an organization the seed
 *    user belongs to whose bytes are recorded as purged (`purged_at` set, custody `purged`).
 */
const CASE_TITLE = "Retention e2e case";
const CAPTURE = "/data/dns_traffic.pcap";
const LOWERED_DAYS = 3650;
const ANALYSIS_TIMEOUT = 6 * 60_000;
const RUN_TIMEOUT = 3 * 60_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

type Seed = { email: string; password: string; orgId: string; evidenceId: string };

function seedFromEnv(): Seed | null {
  const email = process.env.E2E_SEED_EMAIL ?? "";
  const password = process.env.E2E_SEED_PASSWORD ?? "";
  const [orgId = "", evidenceId = ""] = (process.env.E2E_SEED_PURGED_EVIDENCE ?? "").split("/");
  if (!email || !password || !UUID.test(orgId) || !UUID.test(evidenceId)) return null;
  return { email, password, orgId, evidenceId };
}

function collectConsoleErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  return errors;
}

async function register(page: Page, orgName: string): Promise<string> {
  const email = `e2e-retention-${Date.now()}-${randomBytes(3).toString("hex")}@example.com`;
  await page.goto("/register");
  await page.waitForLoadState("networkidle");
  await page.getByLabel("Your name").fill("Retention Owner");
  await page.getByLabel("Organization").fill(orgName);
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  const orgId = /\/o\/([0-9a-f-]{36})/.exec(page.url())?.[1];
  expect(orgId, "the overview URL carries the org id").toBeTruthy();
  return orgId as string;
}

async function login(page: Page, email: string, password: string): Promise<void> {
  await page.goto("/login");
  await page.waitForLoadState("networkidle");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  // The app replaces /login with the user's first organization.
  await expect(page).toHaveURL(/\/o\/[0-9a-f-]{36}/);
}

async function csrfHeaders(page: Page): Promise<Record<string, string>> {
  const csrf = (await page.context().cookies()).find((c) => c.name === "cl_csrf")?.value ?? "";
  expect(csrf).not.toBe("");
  return { "X-CSRF-Token": csrf };
}

async function openRetention(page: Page, orgId: string): Promise<void> {
  await page.goto(`/o/${orgId}/settings/retention`);
  await expect(page.getByRole("navigation", { name: "Settings sections" })).toBeVisible();
  await expect(page.getByText("Retention policy", { exact: true })).toBeVisible();
}

function card(page: Page, title: string) {
  return page.locator('[data-slot="card"]').filter({ has: page.getByText(title, { exact: true }) });
}

test("retention policy, preview, dry run, legal hold, purged evidence, viewer and operations", async ({
  page,
  browser,
  baseURL,
}) => {
  test.setTimeout(14 * 60_000);
  const seed = seedFromEnv();
  expect(
    seed,
    "scripts/e2e.mjs passes E2E_SEED_EMAIL, E2E_SEED_PASSWORD and E2E_SEED_PURGED_EVIDENCE (the purged-evidence seed step)",
  ).not.toBeNull();
  const { email: viewerEmail, password: viewerPassword, orgId: seedOrgId, evidenceId: purgedId } = seed as Seed;
  const errors = collectConsoleErrors(page);
  const orgName = `E2E Retention Team ${randomBytes(3).toString("hex")}`;
  const orgId = await register(page, orgName);

  // A case with a small capture: its analysis runs meanwhile (Operations, step 6).
  await page.getByRole("link", { name: "Investigations" }).first().click();
  await page.getByRole("button", { name: "New investigation" }).click();
  const newCase = page.getByRole("dialog");
  await newCase.getByLabel("Title", { exact: true }).fill(CASE_TITLE);
  await newCase.getByRole("button", { name: "Create" }).click();
  await expect(page.getByRole("heading", { name: CASE_TITLE })).toBeVisible();
  await page.waitForURL(/\/investigations\/[0-9a-f-]{36}/);
  const caseUrl = page.url().split("?")[0];
  await page.getByRole("tablist", { name: "Case sections" }).getByRole("tab", { name: "Evidence", exact: true }).click();
  await page.locator('input[type="file"]').setInputFiles(CAPTURE);
  await expect(page.getByRole("row").filter({ hasText: "dns_traffic.pcap" }).first()).toBeVisible();

  // 1. Settings -> Retention. By default everything is kept forever and enforcement is off.
  await page.getByRole("link", { name: "Settings" }).first().click();
  await page.getByRole("navigation", { name: "Settings sections" }).getByRole("link", { name: "Retention" }).click();
  await expect(page.getByText("Retention policy", { exact: true })).toBeVisible();
  const enforce = page.getByRole("switch", { name: /Enforce retention/ });
  await expect(enforce).not.toBeChecked();
  await expect(page.getByText("off (dry run)")).toBeVisible();
  const closed = page.getByRole("group", { name: "Closed cases" });
  await expect(closed.getByText("Keep forever").first()).toBeVisible();

  // The floor is enforced in the form (the API re-checks it: 422 policy_floor).
  const save = page.getByRole("button", { name: "Save values" });
  await closed.getByLabel("Keep forever").uncheck();
  const days = closed.getByLabel("Closed cases: days");
  await days.fill("10");
  await expect(closed.getByText(/^At least \d+ days \(the platform minimum\)\.$/)).toBeVisible();
  await expect(save).toBeDisabled();

  // A lowered value (keep forever -> days) waits for the delay: confirm, then it shows as pending.
  await days.fill(String(LOWERED_DAYS));
  await expect(save).toBeEnabled();
  await save.click();
  const lower = page.getByRole("dialog", { name: "Lower the retention period?" });
  await expect(lower.getByText(/^Lowering Closed cases takes effect after the \d+-day delay, on .+\./)).toBeVisible();
  await lower.getByRole("button", { name: "Save lowered values" }).click();
  await expect(lower).toBeHidden();
  await expect(page.getByText("Retention policy saved")).toBeVisible();
  await expect(closed.getByText("Pending", { exact: true })).toBeVisible();
  await expect(closed.getByText(/^3,650 days/)).toBeVisible();
  await expect(closed.getByText(/\(takes effect on .+\)/)).toBeVisible();

  // 2. Preview with the pending value: counts per category, nothing deleted.
  const previewCard = card(page, "Preview");
  await previewCard.getByLabel("Include pending values").check();
  await previewCard.getByRole("button", { name: "Preview" }).click();
  const preview = page.locator('[data-slot="retention-preview"]');
  await expect(preview.getByText(/includes pending values · 0 legal holds active/)).toBeVisible();
  for (const category of ["Threat-intel history", "AI runs", "Closed cases", "Total"]) {
    await expect(preview.getByRole("row", { name: new RegExp(`^${category}`) }).first()).toBeVisible();
  }
  await expect(preview.getByRole("columnheader", { name: "Candidates" })).toBeVisible();
  await expect(preview.getByText("A preview deletes nothing.", { exact: false })).toBeVisible();

  // A manual dry run completes; its detail says nothing was deleted.
  const runs = card(page, "Runs");
  await runs.getByRole("button", { name: "Start a dry run" }).click();
  await expect(page.getByText("Dry run queued")).toBeVisible();
  const runRow = runs.getByRole("row").filter({ hasText: "Manual" }).first();
  await expect(runRow.getByRole("link", { name: "Dry run" })).toBeVisible();
  await expect(runRow.getByText("Completed")).toBeVisible({ timeout: RUN_TIMEOUT });
  await runRow.getByRole("link", { name: "Dry run" }).click();
  await page.waitForURL(/\/settings\/retention\/runs\/[0-9a-f-]{36}/);
  await expect(page.getByText("A dry run: nothing was deleted.")).toBeVisible();
  await expect(page.getByText(/^Dry run · Manual/)).toBeVisible();
  await page.getByRole("link", { name: "Retention" }).last().click();
  await expect(page.getByText("Retention policy", { exact: true })).toBeVisible();

  // The enforce dialog: the destructive button stays disabled until the organization name is
  // typed. It is cancelled, never confirmed: this spec turns no enforcement on.
  // A controlled switch: the click opens the dialog, the box stays unchecked until confirmed.
  await enforce.click();
  const ack = page.getByRole("dialog", { name: "Turn on retention enforcement?" });
  await expect(ack.getByText(/Enforcement begins on .+, after the delay/)).toBeVisible();
  await expect(ack.getByText("Never purged by policy:")).toBeVisible();
  const turnOn = ack.getByRole("button", { name: "Turn on enforcement" });
  await expect(turnOn).toBeDisabled();
  const typed = ack.getByLabel(/Type the organization name/);
  await typed.fill(`${orgName} (not it)`);
  await expect(turnOn).toBeDisabled();
  await typed.fill(orgName);
  await expect(turnOn).toBeEnabled();
  await ack.getByRole("button", { name: "Cancel" }).click();
  await expect(ack).toBeHidden();
  await expect(enforce).not.toBeChecked();
  await expect(page.getByText("off (dry run)")).toBeVisible();

  // 3. A case legal hold: the badge on the case, the hold in the case card and the org list.
  const holdReason = `E2E preservation request ${randomBytes(3).toString("hex")}`;
  await page.goto(caseUrl);
  await expect(page.getByRole("heading", { name: CASE_TITLE })).toBeVisible();
  const holdCard = page.locator('[data-slot="case-hold-card"]');
  await expect(holdCard.getByText("No legal hold covers this case.")).toBeVisible();
  await holdCard.getByRole("button", { name: "Place hold" }).click();
  const place = page.getByRole("dialog", { name: "Place a hold on this case?" });
  await expect(place.getByText(/not a legal determination/)).toBeVisible();
  const placeButton = place.getByRole("button", { name: "Place hold" });
  await expect(placeButton).toBeDisabled();
  await place.getByLabel("Reason").fill(holdReason);
  await placeButton.click();
  await expect(place).toBeHidden();
  await expect(page.getByText("Case hold placed")).toBeVisible();
  const badge = page.getByTitle("A legal hold protects this case's data from retention purges.");
  await expect(badge).toBeVisible();
  await expect(holdCard.getByText("This case is under legal hold: retention purges nothing from it.")).toBeVisible();
  await expect(holdCard.getByText(holdReason)).toBeVisible();
  await expect(holdCard.locator('[data-hold-state="active"]')).toBeVisible();

  await openRetention(page, orgId);
  const orgHolds = card(page, "Legal holds");
  const orgHold = orgHolds.locator('[data-hold-state="active"]').filter({ hasText: holdReason });
  await expect(orgHold).toBeVisible();
  await expect(orgHold.getByRole("button", { name: "Release" })).toBeVisible();
  await card(page, "Preview").getByRole("button", { name: "Preview" }).click();
  await expect(page.locator('[data-slot="retention-preview"]').getByText(/1 legal hold active/)).toBeVisible();

  // 4 + 5. The seed user: a viewer of this organization (added through the members API).
  const added = await page.request.post(`/api/v1/orgs/${orgId}/members`, {
    headers: await csrfHeaders(page),
    data: { email: viewerEmail, role: "viewer" },
  });
  expect(added.status(), await added.text()).toBe(201);
  const viewerContext = await browser.newContext({
    baseURL,
    ignoreHTTPSErrors: process.env.E2E_IGNORE_HTTPS_ERRORS === "1",
  });
  try {
    const viewer = await viewerContext.newPage();
    await login(viewer, viewerEmail, viewerPassword);

    // 4. The seeded purged evidence: the strip, Download disabled, the hashes page still there.
    await viewer.goto(`/o/${seedOrgId}/evidence/${purgedId}`);
    const strip = viewer.locator('[data-slot="evidence-integrity-strip"]');
    await expect(strip.getByText(/^Bytes purged on .+ by a retention run; hashes and custody retained\.$/)).toBeVisible();
    await expect(strip.getByText(/Download, verification and new analyses are unavailable\./)).toBeVisible();
    await expect(viewer.getByRole("button", { name: "Download" })).toBeDisabled();
    await expect(viewer.getByText("Bytes purged by the retention policy").first()).toBeVisible();

    // 5. The viewer: the hold and the badge are visible, no action is offered.
    await viewer.goto(caseUrl);
    await expect(viewer.getByRole("heading", { name: CASE_TITLE })).toBeVisible();
    await expect(viewer.getByTitle("A legal hold protects this case's data from retention purges.")).toBeVisible();
    const viewerHoldCard = viewer.locator('[data-slot="case-hold-card"]');
    await expect(viewerHoldCard.getByText(holdReason)).toBeVisible();
    await expect(viewerHoldCard.getByRole("button")).toHaveCount(0);

    await openRetention(viewer, orgId);
    await expect(viewer.getByText("Only owners and admins can change the retention policy.")).toBeVisible();
    await expect(viewer.getByRole("group", { name: "Closed cases" }).getByText(/^3,650 days/)).toBeVisible();
    await expect(viewer.getByRole("switch", { name: /Enforce retention/ })).toBeDisabled();
    await expect(card(viewer, "Legal holds").getByText(holdReason)).toBeVisible();
    for (const action of ["Save values", "Preview", "Start a dry run", "Place organization hold", "Release"]) {
      await expect(viewer.getByRole("button", { name: action })).toHaveCount(0);
    }
    await expect(viewer.getByRole("spinbutton")).toHaveCount(0);
    const viewerTabs = viewer.getByRole("navigation", { name: "Settings sections" });
    await expect(viewerTabs.getByRole("link", { name: "Retention" })).toBeVisible();
    await expect(viewerTabs.getByRole("link", { name: "Operations" })).toHaveCount(0);
    await viewer.goto(`/o/${orgId}/settings/operations`);
    await expect(viewer.getByText("Only owners and admins can view operations metrics.")).toBeVisible();
  } finally {
    await viewerContext.close();
  }

  // 6. The owner releases the hold: the data stays protected for the delay.
  await openRetention(page, orgId);
  await orgHold.getByRole("button", { name: "Release" }).click();
  const release = page.getByRole("dialog", { name: "Release this case hold?" });
  await expect(release.getByText(/^The data stays protected for \d+ more days after the release, until .+\./)).toBeVisible();
  const releaseButton = release.getByRole("button", { name: "Release hold" });
  await expect(releaseButton).toBeDisabled();
  await release.getByLabel("Reason for the release").fill("E2E: preservation request withdrawn");
  await releaseButton.click();
  await expect(release).toBeHidden();
  await expect(page.getByText(/^Hold released/)).toBeVisible();
  const released = orgHolds.locator("li").filter({ hasText: holdReason });
  await expect(released).toHaveAttribute("data-hold-state", "protecting");
  await expect(released.getByText("Released (still protecting)")).toBeVisible();
  await expect(released.getByText("Release reason: E2E: preservation request withdrawn")).toBeVisible();
  await expect(released.getByRole("button", { name: "Release" })).toHaveCount(0);

  // Operations lists the e2e job once its analysis has finished.
  await page.getByRole("link", { name: "PCAP Analyzer" }).first().click();
  const jobRow = page.getByRole("row", { name: /dns_traffic\.pcap/ }).first();
  await expect(jobRow.getByText("Succeeded")).toBeVisible({ timeout: ANALYSIS_TIMEOUT });
  await page.goto(`/o/${orgId}/settings/operations`);
  const metrics = card(page, "Job metrics");
  await expect(metrics.getByText(/Computed .+\./)).toBeVisible();
  const pcapRow = metrics.getByRole("row", { name: /^PCAP analysis/ });
  await expect(pcapRow).toBeVisible({ timeout: 90_000 });
  await expect(pcapRow.getByRole("cell").nth(1)).not.toHaveText("0");
  await metrics.getByRole("button", { name: "Last 7 days" }).click();
  await expect(metrics.getByRole("button", { name: "Last 7 days" })).toHaveAttribute("aria-pressed", "true");
  await expect(metrics.getByRole("row", { name: /^PCAP analysis/ })).toBeVisible();
  await expect(card(page, "Recent failures")).toBeVisible();
  await expect(page.getByText("Platform-wide metrics are served to operators at /internal/metrics.")).toBeVisible();

  expect(errors).toEqual([]);
});
