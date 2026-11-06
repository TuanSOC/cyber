import { randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { type APIResponse, type Locator, type Page, expect, test } from "@playwright/test";

/**
 * M9 golden path (phase 13): a multi-segment EWF disk image through the real disk worker (TSK,
 * libewf and Plaso, offline) and back to the Forensics UI.
 *
 *  1. Upload the `ewf_multi` segments as disk images (in reverse order): each is restricted at
 *     once (TLP:RED, AI / TI excluded) and never analyzed automatically. The run dialog lists
 *     them in natural order (this evidence pinned first); run `triage`.
 *  2. The job page: the stage strip, the worker-reported media hash `matched`, the EWF facts, the
 *     partitions, the file browser (hide known files, an alternate data stream and a deleted
 *     entry when the image has them), the merged timeline with both sources, a finding deep link.
 *  3. Download the TSK body file and the timeline CSV (TLP:RED while restricted); both downloads
 *     are in the audit log.
 *  4. Export `tool.exe`, add it to the case: the derived-evidence badge, its own restriction and
 *     its automatic static analysis.
 *  5. As the org owner (admin): release the image with the acknowledgement, then clear the AI /
 *     TI exclusions (two audited steps); only then does the IOC tab offer "Enrich IOCs".
 *
 * The images come from the disk worker's generator (`python -m samples.diskgen`), written by
 * scripts/e2e.mjs into the samples volume under /data/disk/ (our own synthetic content, never a
 * real disk). Assertions that depend on what the generator could build (the libntfs route's
 * named streams, a deleted entry, hivex-merged hives) follow its `ground_truth.json`.
 */

const IMAGE_DIR = "/data/disk/ewf_multi";
const JOB_TIMEOUT = 15 * 60_000;
const EXPORT_TIMEOUT = 8 * 60_000;
const STATIC_TIMEOUT = 7 * 60_000;
const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/;
const CASE_TITLE = "Laptop disk triage";
const TOOL_PATH = "/Users/alice/AppData/Local/Temp/tool.exe";

type TruthFile = {
  path: string;
  type: "dir" | "reg";
  deleted?: boolean;
  stream?: string;
  size?: number;
  sha256?: string;
};
type Truth = {
  id: string;
  format: string;
  segments: string[];
  media_hash_status?: string;
  ntfs_route?: string;
  hive_outcome?: Record<string, string>;
  partitions: { index: number; fs_type: string | null; fs_status: string; os: string }[];
  files: TruthFile[];
  expected_findings?: { type: string; path: string; requires?: string[] }[];
};
type Finding = { id: string; type: string; title: string };

function groundTruth(): Truth {
  const path = join(IMAGE_DIR, "ground_truth.json");
  expect(existsSync(path), `${path}: scripts/e2e.mjs generates ewf_multi into the samples volume`).toBe(true);
  const truth = JSON.parse(readFileSync(path, "utf8")) as Truth;
  expect(truth.format).toBe("ewf");
  expect(truth.segments.length, "ewf_multi has several segments").toBeGreaterThan(1);
  return truth;
}

function collectConsoleErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  return errors;
}

async function register(page: Page): Promise<string> {
  const email = `e2e-disk-${Date.now()}-${randomBytes(3).toString("hex")}@example.com`;
  await page.goto("/register");
  await page.waitForLoadState("networkidle");
  await page.getByLabel("Your name").fill("Disk Examiner");
  await page.getByLabel("Organization").fill(`E2E Forensics Team ${randomBytes(3).toString("hex")}`);
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  const orgId = /\/o\/([0-9a-f-]{36})/.exec(page.url())?.[1];
  expect(orgId, "the overview URL carries the org id").toBeTruthy();
  return orgId as string;
}

async function json<T>(response: APIResponse): Promise<T> {
  expect(response.ok(), `${response.url()}: HTTP ${response.status()}`).toBe(true);
  return (await response.json()) as T;
}

async function auditActions(page: Page, orgId: string, action: string): Promise<{ details: Record<string, unknown> }[]> {
  const page1 = await json<{ items: { details: Record<string, unknown> }[] }>(
    await page.request.get(`/api/v1/orgs/${orgId}/audit-logs?action=${encodeURIComponent(action)}&limit=100`),
  );
  return page1.items;
}

function resultTab(page: Page, name: string): Locator {
  return page.getByRole("tablist", { name: "Disk analysis results" }).getByRole("tab", { name, exact: true });
}

/** A Radix select of the result filters (`FilterSelect`): open it by its label, pick an option. */
async function pick(page: Page, label: string, option: string): Promise<void> {
  await page.getByRole("combobox", { name: label }).click();
  await page.getByRole("option", { name: option, exact: true }).click();
}

test("a multi-segment disk image is analyzed offline, browsed, exported and released", async ({ page }) => {
  test.setTimeout(35 * 60_000);
  const truth = groundTruth();
  const segments = truth.segments;
  const n = segments.length;
  const errors = collectConsoleErrors(page);
  const orgId = await register(page);

  await page.getByRole("link", { name: "Investigations" }).first().click();
  await page.getByRole("button", { name: "New investigation" }).click();
  const newCase = page.getByRole("dialog");
  await newCase.getByLabel("Title", { exact: true }).fill(CASE_TITLE);
  await newCase.getByRole("button", { name: "Create" }).click();
  await expect(page.getByRole("heading", { name: CASE_TITLE })).toBeVisible();
  await page.waitForURL(/\/investigations\/[0-9a-f-]{36}/);

  // ---------------------------------------------------------------------------------------------
  // 1. Upload as disk image segments (reverse order: the run dialog sorts them), run triage.
  await test.step("upload the segments as disk images", async () => {
    await page.getByRole("tablist", { name: "Case sections" }).getByRole("tab", { name: "Evidence", exact: true }).click();
    await page.getByLabel("Disk image (segment)").check();
    await expect(page.getByTestId("disk-upload-hint")).toContainText("TLP:RED material from the upload");
    await page.locator('input[type="file"]').setInputFiles([...segments].reverse().map((name) => join(IMAGE_DIR, name)));
    await expect(page.getByText("Uploaded and hashed")).toHaveCount(n, { timeout: 5 * 60_000 });
    // Restricted from the upload: the share policy excludes AI and TI on every segment.
    for (const name of segments) {
      const row = page.getByRole("row").filter({ has: page.getByRole("link", { name, exact: true }) });
      await expect(row.getByText("No AI")).toBeVisible();
      await expect(row.getByText("No TI")).toBeVisible();
    }
  });

  await page.getByRole("link", { name: segments[0], exact: true }).click();
  await page.waitForURL(/\/evidence\/[0-9a-f-]{36}/);
  const firstEvidenceUrl = page.url().split("?")[0];
  await expect(page.getByRole("heading", { name: segments[0] })).toBeVisible();

  await test.step("restricted at once, never analyzed automatically", async () => {
    await expect(page.getByText("Disk image · restricted (TLP:RED)")).toBeVisible();
    await expect(page.getByText("0 runs")).toBeVisible();
  });

  await test.step("the run dialog orders the segments naturally; run triage", async () => {
    await page.getByRole("button", { name: "Run disk analysis" }).click();
    const dialog = page.getByRole("dialog", { name: "Run disk analysis" });
    const selected = dialog.getByRole("list", { name: "Selected segments" }).getByRole("listitem");
    await expect(selected).toHaveCount(n);
    for (const [index, name] of segments.entries()) {
      await expect(selected.nth(index)).toContainText(`${index + 1}.`);
      await expect(selected.nth(index)).toContainText(name);
    }
    await expect(selected.first()).toContainText("this evidence");
    await expect(dialog.getByTestId("not-first")).toHaveCount(0);
    await expect(dialog.getByTestId("disk-run-notices")).toContainText("never analyzed automatically");
    await expect(dialog.getByRole("radio", { name: /^Triage/ })).toBeChecked();
    await dialog.getByRole("button", { name: "Run disk analysis" }).click();
    await expect(page.getByText("Disk analysis queued")).toBeVisible();
    await expect(dialog).toBeHidden();
  });

  const jobRow = page.getByRole("listitem").filter({ hasText: "Disk (triage)" }).first();
  await expect(jobRow).toBeVisible();
  await expect(jobRow.getByText(/^(Succeeded|Failed)$/)).toBeVisible({ timeout: JOB_TIMEOUT });
  await expect(jobRow.getByText("Succeeded"), await jobRow.innerText()).toBeVisible();
  await jobRow.getByRole("link", { name: "Details" }).click();
  await page.waitForURL(/\/forensics\/[0-9a-f-]{36}/);
  const jobUrl = page.url().split("?")[0];
  const jobId = UUID.exec(jobUrl.split("/forensics/")[1] ?? "")?.[0] as string;
  expect(jobId).toBeTruthy();

  // ---------------------------------------------------------------------------------------------
  // 2. The job page.
  await test.step("overview: restricted, stages, media hash, EWF facts, segments", async () => {
    await expect(page.getByRole("heading", { name: segments[0] })).toBeVisible();
    await expect(page.getByText("Restricted (TLP:RED)", { exact: true })).toBeVisible();
    await expect(page.getByTestId("disk-sensitivity-banner")).toContainText("Restricted disk image");
    const overview = page.getByTestId("disk-overview");
    await expect(overview.getByText("EWF (E01)")).toBeVisible();
    // Worker-reported, worded "consistent with", never "verified" (RT17).
    expect(truth.media_hash_status).toBe("matched");
    await expect(overview.getByTestId("media-hash-status")).toContainText("Consistent with the hash stored at acquisition");
    await expect(overview.getByTestId("ewf-meta")).toBeVisible();
    const strip = overview.getByTestId("stage-strip");
    const stages = strip.getByRole("list", { name: "Analysis stages" }).getByRole("listitem");
    for (const label of ["Download", "Verify", "Layout", "File listing", "Timeline"]) {
      await expect(stages.filter({ hasText: label }).first()).toBeVisible();
    }
    await expect(stages.filter({ hasText: "Failed" })).toHaveCount(0);
    const segmentRows = overview
      .locator('[data-slot="card"]')
      .filter({ has: page.getByText("Segments", { exact: true }) })
      .getByRole("row");
    await expect(segmentRows).toHaveCount(n + 1);
  });

  await test.step("partitions", async () => {
    await resultTab(page, "Partitions").click();
    const opened = page.getByRole("row").filter({ hasText: "Opened" });
    await expect(opened.first()).toBeVisible();
    await expect(opened.first()).toContainText("Windows");
  });

  await test.step("file browser: hide known files, streams, deleted entries", async () => {
    await resultTab(page, "Files").click();
    const files = page.getByRole("table", { name: "Files" });
    await expect(files.getByRole("row").nth(1)).toBeVisible();
    // Known files are hidden by default (RT18); the toggle shows them.
    const hideKnown = page.getByLabel(/^Hide known files \(reference sets\)/);
    await expect(hideKnown).toBeChecked();
    await hideKnown.uncheck();
    await expect(hideKnown).not.toBeChecked();
    await expect(files.getByRole("row").nth(1)).toBeVisible();
    await hideKnown.check();

    const stream = truth.files.find((f) => f.stream && f.path.endsWith("/report.txt"));
    if (truth.ntfs_route === "libntfs" && stream) {
      await pick(page, "Flag filter", "Alternate data streams");
      const row = files.getByRole("row").filter({ hasText: `report.txt:${stream.stream}` }).first();
      await expect(row).toBeVisible();
      await expect(row.getByText("stream", { exact: true })).toBeVisible();
      await pick(page, "Flag filter", "Any flag");
    } else {
      test.info().annotations.push({ type: "gap", description: `no NTFS named stream (ntfs_route ${truth.ntfs_route})` });
    }

    const deleted = truth.files.find((f) => f.deleted);
    if (deleted) {
      await pick(page, "Flag filter", "Deleted");
      await expect(files.getByRole("row").filter({ hasText: "Deleted" }).first()).toBeVisible();
      await pick(page, "Flag filter", "Any flag");
    } else {
      test.info().annotations.push({ type: "gap", description: "the generated image has no deleted entry" });
    }

    // The directory tree lists the partition root lazily.
    await expect(page.getByRole("tree", { name: "Partitions and directories" }).getByRole("treeitem").first()).toBeVisible();
  });

  const summary = await json<{ artifacts: { artifact: string; events_stored: number }[] }>(
    await page.request.get(`/api/v1/orgs/${orgId}/analyses/${jobId}/disk`),
  );
  const eventsStored = summary.artifacts.reduce((sum, a) => sum + a.events_stored, 0);

  await test.step("merged timeline: file-system times and parsed events", async () => {
    await resultTab(page, "Timeline").click();
    const table = page.getByRole("table", { name: "Merged timeline" });
    const fileSource = page.getByRole("checkbox", { name: "File system" });
    const eventSource = page.getByRole("checkbox", { name: "Events" });
    await expect(fileSource).toBeChecked();
    await expect(eventSource).toBeChecked();
    await expect(table.getByRole("row").nth(1)).toBeVisible();
    await expect(page.getByTestId("hour-histogram")).toBeVisible();

    await eventSource.uncheck();
    await expect(table.getByText("File system", { exact: true }).first()).toBeVisible();
    await eventSource.check();

    const hivesMerged = Object.values(truth.hive_outcome ?? {}).includes("merged");
    if (hivesMerged) expect(eventsStored, "hivex-merged hives give Plaso registry events").toBeGreaterThan(0);
    if (eventsStored > 0) {
      await fileSource.uncheck();
      await expect(table.getByText("Events", { exact: true }).first()).toBeVisible();
      await fileSource.check();
    } else {
      test.info().annotations.push({ type: "gap", description: "Plaso stored no event for this image (no merged hive)" });
    }
  });

  await test.step("findings and a finding deep link", async () => {
    const findings = (
      await json<{ items: Finding[] }>(await page.request.get(`/api/v1/orgs/${orgId}/analyses/${jobId}/findings?limit=100`))
    ).items;
    const fileFindings = (truth.expected_findings ?? []).filter((f) => !f.requires?.length);
    expect(fileFindings.length).toBeGreaterThan(0);
    for (const expected of fileFindings) {
      expect(findings.map((f) => f.type), `expected finding ${expected.type} (${expected.path})`).toContain(expected.type);
    }
    const target = findings.find((f) => f.type === "disk_exec_user_writable") ?? findings[0];
    await resultTab(page, "Findings").click();
    await expect(page.getByText(target.title).first()).toBeVisible();

    await page.goto(`${jobUrl}?tab=findings&ref=${target.id}`);
    await expect(page.getByText("Showing 1 cited record")).toBeVisible();
    await expect(page.getByText(target.title).first()).toBeVisible();
  });

  // ---------------------------------------------------------------------------------------------
  // 3. Interop downloads (audited, TLP:RED while restricted).
  await test.step("download the body file and the timeline CSV", async () => {
    await page.goto(`${jobUrl}?tab=exports`);
    await expect(page.getByTestId("interop-tlp")).toBeVisible();
    const [body] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Body file" }).click()]);
    expect(body.suggestedFilename()).toMatch(/\.body$/);
    const [csv] = await Promise.all([
      page.waitForEvent("download"),
      page.getByRole("button", { name: "Timeline (CSV)" }).click(),
    ]);
    expect(csv.suggestedFilename()).toMatch(/\.csv$/);
    const kinds = (await auditActions(page, orgId, "disk.interop_exported")).map((a) => a.details.kind);
    expect(kinds).toContain("bodyfile");
    expect(kinds).toContain("timeline.csv");
  });

  // ---------------------------------------------------------------------------------------------
  // 4. Export tool.exe and add it to the case as derived evidence.
  await test.step("export a file and add it to the case", async () => {
    await page.goto(`${jobUrl}?tab=files`);
    await page.getByLabel("Search in paths").fill("tool.exe");
    const row = page.getByRole("table", { name: "Files" }).getByRole("row").filter({ hasText: TOOL_PATH }).first();
    await expect(row).toBeVisible();
    await row.click();
    const drawer = page.getByRole("dialog");
    await expect(drawer.getByText("From the disk image: names and paths are shown as text.")).toBeVisible();
    await drawer.getByRole("button", { name: "Export this file" }).click();
    await expect(page.getByText("1 file export requested: see the Exports tab")).toBeVisible();
    await page.keyboard.press("Escape");

    await resultTab(page, "Exports").click();
    const item = page.getByTestId("file-export").filter({ hasText: TOOL_PATH });
    await expect(item).toBeVisible();
    await expect(item.getByText(/^(Ready|Failed)$/)).toBeVisible({ timeout: EXPORT_TIMEOUT });
    await expect(item.getByText("Ready", { exact: true }), await item.innerText()).toBeVisible();
    const sha = truth.files.find((f) => f.path === TOOL_PATH && !f.stream)?.sha256;
    await expect(item).toContainText("sha256 reported by the worker (unverified)");
    await item.getByRole("button", { name: "Add to case as evidence" }).click();
    await expect(page.getByText("Added to the case as evidence")).toBeVisible();
    await expect(item.getByText("Added to the case", { exact: true })).toBeVisible();

    await item.getByRole("link", { name: "open the evidence" }).click();
    await page.waitForURL(/\/evidence\/[0-9a-f-]{36}/);
    await expect(page.getByRole("heading", { name: "tool.exe" })).toBeVisible();
    // The trusted hash the platform computed equals the generator's (and so the worker's).
    if (sha) await expect(page.getByText(sha).first()).toBeVisible();
    await expect(page.getByTestId("derived-badge")).toContainText("Exported from disk job");
    await expect(page.getByText("File from a disk image · restricted (TLP:RED)")).toBeVisible();
    await expect(page.getByText("No AI").first()).toBeVisible();
    await expect(page.getByText("No TI").first()).toBeVisible();
    // Its own automatic static analysis (a tiny benign PE written by the generator).
    const staticRow = page.getByRole("listitem").filter({ hasText: "automatic" }).first();
    await expect(staticRow).toBeVisible();
    await expect(staticRow.getByText(/^(Succeeded|Failed)$/)).toBeVisible({ timeout: STATIC_TIMEOUT });
    await expect(staticRow.getByText("Succeeded"), await staticRow.innerText()).toBeVisible();
    // Custody on the derived side (`derived_from`): the timeline renders it.
    await expect(page.getByText("Chain of custody")).toBeVisible();
    await expect(page.getByText("No custody events.")).toHaveCount(0);
  });

  await test.step("the source segment's custody records the export", async () => {
    await page.goto(firstEvidenceUrl);
    await expect(page.getByRole("heading", { name: segments[0] })).toBeVisible();
    await expect(page.getByText("Chain of custody")).toBeVisible();
    await expect(page.getByText("Disk image · restricted (TLP:RED)")).toBeVisible();
  });

  // ---------------------------------------------------------------------------------------------
  // 5. Release (admin, acknowledged), then clear the AI / TI exclusions; only then Enrich.
  await test.step("release the image, clear the exclusions, then Enrich is offered", async () => {
    await page.goto(`${jobUrl}?tab=iocs`);
    await expect(page.getByTestId("enrich-disabled")).toContainText("this disk image is restricted");
    await expect(page.getByRole("button", { name: "Enrich IOCs" })).toHaveCount(0);

    await page.getByTestId("disk-sensitivity-banner").getByRole("button", { name: "Release…" }).click();
    const dialog = page.getByRole("dialog", { name: "Release this disk image" });
    const submit = dialog.getByRole("button", { name: n === 1 ? "Release the segment" : `Release all ${n} segments` });
    await expect(submit).toBeDisabled();
    await dialog.getByRole("checkbox").check();
    await expect(submit).toBeDisabled(); // a reason is required too
    await dialog.getByLabel(/^Reason/).fill("E2E: synthetic image, cleared for threat-intel enrichment");
    await submit.click();

    // Step two, a separate audited choice per segment.
    await expect(dialog.getByText("Released. AI and threat-intel stay excluded until the flags are cleared.")).toBeVisible();
    await expect(page.getByTestId("enrich-disabled")).toBeVisible();
    for (let cleared = 1; cleared <= n; cleared += 1) {
      await dialog.getByRole("button", { name: "Clear AI / TI exclusions" }).first().click();
      await expect(dialog.getByText("Exclusions cleared")).toHaveCount(cleared);
    }
    await dialog.getByRole("button", { name: "Close" }).click();

    await page.reload();
    await expect(page.getByText("Disk image released by an admin")).toBeVisible();
    await expect(page.getByText("Restricted (TLP:RED)", { exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Enrich IOCs" })).toBeVisible();
    await expect(page.getByTestId("enrich-disabled")).toHaveCount(0);

    expect((await auditActions(page, orgId, "disk.sensitivity_released")).length).toBe(n);
    expect((await auditActions(page, orgId, "evidence.share_policy_updated")).length).toBeGreaterThanOrEqual(n);
  });

  expect(errors).toEqual([]);
});
