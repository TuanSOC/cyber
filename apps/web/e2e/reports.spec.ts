import { createHash, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";

import { type Download, type Page, expect, test } from "@playwright/test";

/**
 * M6 golden path (case management -> signed report -> real renders), dev and prod alike:
 * the report-worker has no mock, so the prod-like stack renders the same PDF through the
 * same isolated renderer.
 *
 *  1. Register -> case -> upload the synthetic capture (scripts/e2e.mjs writes /data/mixed.pcap
 *     into the cyberlab_e2e_samples volume) -> its analysis succeeds.
 *  2. Close without a reason is refused (UI and API); with a reason it lands in the history;
 *     reopen with a reason.
 *  3. A note (included in reports) -> an IOC collection from the case IOCs -> CSV (TLP header
 *     and file name) and STIX exports -> an ATT&CK technique confirmed -> the matrix.
 *  4. New report on the case -> sections, the note, the collection and a cited finding ->
 *     finalize v1 (internal) -> the viewer: TLP banners, "Signature valid", the SHA-256, the
 *     citation appendix; no anchor outside the app.
 *  5. The PDF render succeeds -> download (`%PDF-`, its SHA-256 equals the render's) ->
 *     render and download HTML and Markdown.
 *  6. v2 with the `external` profile: the note, the analyst's name and base_url are gone from
 *     the signed snapshot, and v1 is still viewable with a valid signature.
 *  No console errors throughout.
 */
const PROD = process.env.E2E_PROD === "1" || (process.env.E2E_BASE_URL ?? "").startsWith("https:");
const RENDER_TIMEOUT = 90_000;

function collectConsoleErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  return errors;
}

async function register(page: Page, name: string): Promise<string> {
  const email = `e2e-reports-${Date.now()}-${randomBytes(3).toString("hex")}@example.com`;
  await page.goto("/register");
  await page.waitForLoadState("networkidle");
  await page.getByLabel("Your name").fill(name);
  await page.getByLabel("Organization").fill("E2E Reports Team");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  const orgId = /\/o\/([0-9a-f-]{36})/.exec(page.url())?.[1];
  expect(orgId, "the overview URL carries the org id").toBeTruthy();
  return orgId as string;
}

async function csrfHeaders(page: Page): Promise<Record<string, string>> {
  const csrf = (await page.context().cookies()).find((c) => c.name === "cl_csrf")?.value ?? "";
  expect(csrf).not.toBe("");
  return { "X-CSRF-Token": csrf };
}

async function api<T>(page: Page, method: "GET" | "POST" | "PATCH", path: string, data?: unknown): Promise<T> {
  const response = await page.request.fetch(`/api/v1${path}`, {
    method,
    headers: method === "GET" ? {} : await csrfHeaders(page),
    data,
  });
  expect(response.ok(), `${method} ${path}: ${response.status()} ${await response.text()}`).toBe(true);
  return (await response.json()) as T;
}

async function downloadOf(page: Page, click: () => Promise<void>): Promise<{ download: Download; data: Buffer }> {
  const [download] = await Promise.all([page.waitForEvent("download"), click()]);
  const path = await download.path();
  expect(path, "the download was saved").toBeTruthy();
  return { download, data: await readFile(path as string) };
}

async function openTab(page: Page, name: string): Promise<void> {
  await page.getByRole("tablist", { name: "Case sections" }).getByRole("tab", { name, exact: true }).click();
}

type ReportDetail = { report: { id: string; revision: number } };
type Finding = { id: string };

test("case management to a signed, rendered and verified report", async ({ page }) => {
  test.setTimeout(12 * 60_000);
  const errors = collectConsoleErrors(page);
  const analyst = `Reports Analyst ${randomBytes(3).toString("hex")}`;
  const orgId = await register(page, analyst);

  // 1. Case and capture.
  await page.getByRole("link", { name: "Investigations" }).first().click();
  await page.getByRole("button", { name: "New investigation" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Title", { exact: true }).fill("Report e2e case");
  await dialog.getByRole("button", { name: "Create" }).click();
  await expect(page.getByRole("heading", { name: "Report e2e case" })).toBeVisible();
  await page.waitForURL(/\/investigations\/[0-9a-f-]{36}/);
  const caseUrl = page.url().split("?")[0];
  const caseId = /\/investigations\/([0-9a-f-]{36})/.exec(caseUrl)?.[1] as string;
  // M6: the uploader lives in the case workspace's Evidence tab.
  await page.getByRole("tablist", { name: "Case sections" }).getByRole("tab", { name: "Evidence", exact: true }).click();
  await page.locator('input[type="file"]').setInputFiles("/data/mixed.pcap");
  await expect(page.getByRole("row").filter({ hasText: "mixed.pcap" }).first()).toBeVisible();

  await page.getByRole("link", { name: "PCAP Analyzer" }).first().click();
  const jobRow = page.getByRole("row", { name: /mixed\.pcap/ }).first();
  await expect(jobRow.getByText("Succeeded")).toBeVisible({ timeout: 5 * 60_000 });
  await jobRow.getByRole("link", { name: "Details" }).click();
  await page.waitForURL(/\/pcap\/[0-9a-f-]{36}/);
  const jobId = /\/pcap\/([0-9a-f-]{36})/.exec(page.url())?.[1] as string;
  await page.goto(caseUrl);
  await expect(page.getByRole("heading", { name: "Report e2e case" })).toBeVisible();

  // 2. Close needs a reason (the dialog's button stays disabled; the API answers 422).
  const refused = await page.request.patch(`/api/v1/orgs/${orgId}/investigations/${caseId}`, {
    headers: await csrfHeaders(page),
    data: { status: "closed" },
  });
  expect(refused.status()).toBe(422);
  expect(((await refused.json()) as { error: { code: string } }).error.code).toBe("status_reason_required");
  const reason = `Contained: beacon host isolated ${randomBytes(2).toString("hex")}`;
  await page.getByRole("combobox", { name: "Investigation status" }).click();
  await page.getByRole("option", { name: "Closed" }).click();
  const closeDialog = page.getByRole("dialog", { name: "Close this investigation?" });
  // The submit button (the dialog's X is also named "Close").
  const closeButton = closeDialog.locator('button[type="submit"]');
  await expect(closeButton).toHaveText("Close");
  await expect(closeButton).toBeDisabled();
  await closeDialog.getByLabel("Reason (required)").fill(reason);
  await closeButton.click();
  await expect(page.getByRole("combobox", { name: "Investigation status" })).toHaveText("Closed");
  await expect(page.getByText(reason).first()).toBeVisible();
  await page.getByRole("combobox", { name: "Investigation status" }).click();
  await page.getByRole("option", { name: "In progress" }).click();
  const reopen = page.getByRole("dialog", { name: "Reopen this investigation?" });
  await reopen.getByLabel("Reason (required)").fill("Reopened for the report");
  await reopen.locator('button[type="submit"]').click();
  await expect(page.getByRole("combobox", { name: "Investigation status" })).toHaveText("In progress");

  // 3a. A note included in reports.
  const noteText = `E2E note ${randomBytes(4).toString("hex")}: the interval matches the loader.`;
  await openTab(page, "Notes");
  await page.getByLabel("Note text").fill(noteText);
  await page.getByLabel("Include in reports and the timeline").check();
  await page.getByRole("button", { name: "Add note" }).click();
  await expect(page.getByText(noteText)).toBeVisible();
  // The text can show before the POST has answered: poll the list until the note is there.
  let noteId = "";
  await expect
    .poll(async () => {
      const notes = await api<{ items: { id: string; body: string | null }[] }>(
        page,
        "GET",
        `/orgs/${orgId}/investigations/${caseId}/notes`,
      );
      noteId = notes.items.find((n) => n.body === noteText)?.id ?? "";
      return noteId;
    })
    .not.toBe("");

  // 3b. An IOC collection from the case IOCs, exported as CSV and STIX.
  await openTab(page, "IOCs");
  await page.getByRole("button", { name: "New collection" }).click();
  const newCollection = page.getByRole("dialog", { name: "New IOC collection" });
  await newCollection.getByLabel("Name").fill("E2E blocklist");
  await newCollection.getByRole("button", { name: "Create" }).click();
  await expect(page.getByRole("heading", { name: "E2E blocklist" })).toBeVisible();
  await page.getByLabel("IOC type filter").selectOption("ip");
  const pick = page.getByRole("checkbox", { name: "Select IOC" });
  await expect(pick.first()).toBeVisible();
  await pick.first().check();
  await page.getByRole("button", { name: /^Add to collection \(1\)/ }).click();
  // The title counts the selection, which is cleared once the items are added.
  await expect(page.getByRole("dialog", { name: /Add 1 IOCs to a collection/ })).toBeVisible();
  const addDialog = page.getByRole("dialog");
  await addDialog.getByRole("button", { name: "Add", exact: true }).click();
  await expect(addDialog.getByRole("status")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByText(/^1 items/).first()).toBeVisible();
  const collections = await api<{ items: { id: string; name: string }[] }>(
    page,
    "GET",
    `/orgs/${orgId}/investigations/${caseId}/ioc-collections`,
  );
  const collectionId = collections.items.find((c) => c.name === "E2E blocklist")?.id as string;
  expect(collectionId).toBeTruthy();

  const csv = await downloadOf(page, async () => {
    await page.getByRole("button", { name: "Export", exact: true }).click();
    await page.getByRole("menuitem", { name: "CSV" }).click();
  });
  expect(csv.download.suggestedFilename()).toMatch(/TLP-AMBER.*\.csv$/);
  // The header comment is one quoted cell (it holds the collection name in quotes).
  expect(csv.data.toString("utf8").split("\r\n")[0]).toMatch(/^"?# TLP:AMBER CASE-\d+/);
  const stix = await downloadOf(page, async () => {
    await page.getByRole("button", { name: "Export", exact: true }).click();
    await page.getByRole("menuitem", { name: "STIX 2.1 bundle" }).click();
  });
  const bundle = JSON.parse(stix.data.toString("utf8")) as { type: string; objects: { type: string }[] };
  expect(bundle.type).toBe("bundle");
  expect(bundle.objects.some((o) => o.type === "marking-definition")).toBe(true);

  // 3c. An ATT&CK technique confirmed -> the matrix.
  await openTab(page, "ATT&CK");
  await page.getByLabel("Technique id").fill("T1071.001");
  await page.getByLabel("Status", { exact: true }).selectOption("confirmed");
  await page.getByRole("button", { name: "Add mapping" }).click();
  await expect(page.getByRole("list", { name: "ATT&CK matrix" }).getByText("T1071.001").first()).toBeVisible();

  // 4. A report on the case: the draft cites the note, the collection and one finding.
  await openTab(page, "Reports");
  await page.getByRole("button", { name: "New report" }).click();
  const newReport = page.getByRole("dialog", { name: "New report" });
  await newReport.getByLabel("Title").fill("E2E incident report");
  await newReport.getByRole("button", { name: "Create draft" }).click();
  await page.waitForURL(/\/reports\/[0-9a-f-]{36}$/);
  const reportId = /\/reports\/([0-9a-f-]{36})/.exec(page.url())?.[1] as string;
  await expect(page.getByRole("heading", { name: "E2E incident report" })).toBeVisible();

  const findings = await api<{ items: Finding[] }>(page, "GET", `/orgs/${orgId}/analyses/${jobId}/findings?limit=5`);
  expect(findings.items.length).toBeGreaterThan(0);
  const detail = await api<ReportDetail>(page, "GET", `/orgs/${orgId}/reports/${reportId}`);
  await api(page, "PATCH", `/orgs/${orgId}/reports/${reportId}`, {
    revision: detail.report.revision,
    draft: {
      sections: {
        executive_summary: "Beacon-like traffic from one workstation; contained.",
        recommendations: "Block the destination and re-image the host.",
      },
      include: {
        iocs: { case_iocs: true, collections: [collectionId] },
        notes: [noteId],
        cited_rows: [{ kind: "finding", ref_id: findings.items[0].id, job_id: jobId }],
      },
    },
  });
  await page.reload();
  await expect(page.getByLabel("Executive summary")).toHaveValue(/Beacon-like traffic/);

  await page.getByRole("button", { name: "Finalize…" }).click();
  const finalize = page.getByRole("dialog", { name: "Finalize version 1" });
  await finalize.getByRole("button", { name: "Finalize v1" }).click();
  await page.waitForURL(/\/reports\/[0-9a-f-]{36}\/v\/1/);

  // The viewer: banners, integrity, citations, internal links only.
  await expect(page.getByLabel("Marking (top): TLP:AMBER")).toBeVisible();
  await expect(page.getByLabel("Marking (bottom): TLP:AMBER")).toBeVisible();
  const integrity = page.getByRole("status", { name: "Integrity" });
  await expect(integrity).toHaveAttribute("data-integrity", "ok");
  await expect(integrity.getByText(/^Signature valid \(Ed25519, key /)).toBeVisible();
  await expect(integrity.getByText(/^Snapshot intact/)).toBeVisible();
  await expect(integrity.locator("code")).toHaveText(/^[0-9a-f]{64}$/);
  if (PROD) await expect(integrity.getByText(/key dev-/)).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Appendix: citations" })).toBeVisible();
  // The appendix entry of the first citation (its fields fold out of a <details>).
  await expect(page.locator("summary").filter({ hasText: /^\[C1\]/ })).toBeVisible();
  await expect(page.getByText(noteText).first()).toBeVisible();
  const hrefs = await page
    .locator('article[data-report-view="version"] a[href]')
    .evaluateAll((anchors) => anchors.map((a) => a.getAttribute("href") ?? ""));
  expect(hrefs.length).toBeGreaterThan(0);
  expect(hrefs.filter((href) => !(href.startsWith("/o/") || href.startsWith("#")))).toEqual([]);

  // 5. The PDF queued at finalize: succeeded -> download -> the SHA-256 shown matches.
  const pdfRow = page.locator('li[data-format="pdf"]');
  const pdfDownload = pdfRow.getByRole("button", { name: "Download" });
  await expect(pdfDownload).toBeVisible({ timeout: RENDER_TIMEOUT });
  const pdf = await downloadOf(page, () => pdfDownload.click());
  expect(pdf.data.subarray(0, 5).toString("latin1")).toBe("%PDF-");
  const pdfSha = createHash("sha256").update(pdf.data).digest("hex");
  await expect(pdfRow.getByText(`SHA-256 ${pdfSha}`)).toBeVisible();

  for (const [format, check] of [
    ["html", (text: string) => expect(text).not.toMatch(/<script|<img|@import/i)],
    // The Markdown escaper escapes `:` (`**TLP\:AMBER**`).
    ["md", (text: string) => expect(text).toMatch(/TLP\\?:AMBER/)],
  ] as const) {
    const row = page.locator(`li[data-format="${format}"]`);
    await row.getByRole("button", { name: "Render", exact: true }).click();
    const button = row.getByRole("button", { name: "Download" });
    await expect(button).toBeVisible({ timeout: RENDER_TIMEOUT });
    const file = await downloadOf(page, () => button.click());
    expect(file.data.length).toBeGreaterThan(0);
    check(file.data.toString("utf8"));
  }

  // 6. v2 with the external profile: redacted, signed; v1 unchanged and still valid.
  const current = await api<ReportDetail>(page, "GET", `/orgs/${orgId}/reports/${reportId}`);
  const patched = await api<ReportDetail>(page, "PATCH", `/orgs/${orgId}/reports/${reportId}`, {
    revision: current.report.revision,
    profile: "external",
    distribution: "E2E partner CERT",
  });
  const v2 = await api<{ version: number }>(page, "POST", `/orgs/${orgId}/reports/${reportId}/finalize`, {
    revision: patched.report.revision,
    change_note: "External edition",
    acknowledge_external_review: true,
  });
  expect(v2.version).toBe(2);
  const external = await page.request.get(`/api/v1/orgs/${orgId}/reports/${reportId}/versions/2/content`);
  expect(external.ok()).toBe(true);
  const externalText = await external.text();
  const snapshot = JSON.parse(externalText) as {
    report: { profile: string; base_url: string | null };
    notes: { items: unknown[] };
  };
  expect(snapshot.report.profile).toBe("external");
  expect(snapshot.report.base_url).toBeNull();
  expect(snapshot.notes.items).toEqual([]);
  expect(externalText).not.toContain(noteText);
  expect(externalText).not.toContain(analyst);

  await page.goto(`/o/${orgId}/reports/${reportId}/v/2`);
  await expect(page.getByRole("status", { name: "Integrity" })).toHaveAttribute("data-integrity", "ok");
  await page.goto(`/o/${orgId}/reports/${reportId}/v/1`);
  await expect(page.getByRole("status", { name: "Integrity" })).toHaveAttribute("data-integrity", "ok");
  await expect(page.getByText(noteText).first()).toBeVisible();

  expect(errors).toEqual([]);
});
