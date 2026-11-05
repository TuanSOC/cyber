import { randomBytes } from "node:crypto";

import { type Locator, type Page, expect, test } from "@playwright/test";

/**
 * M5 golden path on the dev-only `mock` AI provider (the local ai-mock sink, never the
 * internet): Integrations -> AI turned on with the privacy acknowledgement -> the mock's key
 * stored and verified, terms acknowledged, made the org default -> a capture analyzed ->
 * "Summarize capture" previewed (counts, pseudonyms) and run (one rate-limit pause, then
 * completed) -> a verified citation chip opens the cited finding -> "Explain" on that finding
 * -> a hostile capture (injected verdict, fabricated citations) shows no extra link, the
 * hidden-statement counter and the verdict-language note -> the investigation's incident
 * summary (per-job digests, timeline, recommendations) -> the AI runs list. On the prod-like
 * stack: the refusal of the mock provider.
 *
 * scripts/e2e.mjs generates /data/ai_analyst.pcap (UA marker `ai-mock:429-once-<run>`: a 429
 * with Retry-After 1 on the first call, so the run passes `waiting` until the beat resumes it)
 * and /data/ai_hostile.pcap (`ai-mock:hostile`) with apps/workers/pcap/dataset/ai_mock.py,
 * recreates ai-mock (dev) and passes its key as E2E_AI_MOCK_KEY.
 */
const PROD = process.env.E2E_PROD === "1" || (process.env.E2E_BASE_URL ?? "").startsWith("https:");
const MOCK_KEY = process.env.E2E_AI_MOCK_KEY || "cyberlab-ai-mock-key";
const MOCK_LABEL = "Test analyst (mock)";
const ACTIVE = new Set(["queued", "running", "waiting"]);
// Fixed UI texts (lib/ai.ts, lib/ai-settings.ts).
const RATE_LIMITED = /^Provider rate-limited, retrying/;
const HIDDEN_COUNTER = /^\d+ statements? hidden: not supported by verified evidence/;
const VERDICT_NOTE =
  "The model used conclusive wording about the evidence. CyberLab does not issue such conclusions; read it as an interpretation to check.";

type AiRunRow = { id: string; status: string };

function collectConsoleErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  return errors;
}

async function register(page: Page, who: string): Promise<string> {
  const email = `e2e-${who}-${Date.now()}-${randomBytes(3).toString("hex")}@example.com`;
  await page.goto("/register");
  await page.waitForLoadState("networkidle");
  await page.getByLabel("Your name").fill("AI Analyst");
  await page.getByLabel("Organization").fill(`E2E ${who} Team`);
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  const orgId = /\/o\/([0-9a-f-]{36})/.exec(page.url())?.[1];
  expect(orgId, "the overview URL carries the org id").toBeTruthy();
  return orgId as string;
}

async function openIntegrations(page: Page): Promise<void> {
  await page.getByRole("link", { name: "Settings" }).first().click();
  await page.getByRole("navigation", { name: "Settings sections" }).getByRole("link", { name: "Integrations" }).click();
  await expect(page.getByText("What AI providers receive")).toBeVisible();
}

/** A new investigation holding `file`; returns its URL. */
async function newInvestigationWith(page: Page, title: string, file: string): Promise<string> {
  await page.getByRole("link", { name: "Investigations" }).first().click();
  await page.getByRole("button", { name: "New investigation" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Title", { exact: true }).fill(title);
  await dialog.getByRole("button", { name: "Create" }).click();
  await expect(page.getByRole("heading", { name: title })).toBeVisible();
  await page.waitForURL(/\/investigations\/[0-9a-f-]{36}/);
  const url = page.url();
  await upload(page, file);
  return url;
}

async function upload(page: Page, file: string): Promise<void> {
  await page.locator('input[type="file"]').setInputFiles(file);
  const name = file.split("/").at(-1) as string;
  await expect(page.getByRole("row").filter({ hasText: name }).first()).toBeVisible();
}

/** PCAP Analyzer -> the capture's job, once Succeeded -> its Details page; returns the job id. */
async function openPcapJob(page: Page, name: RegExp): Promise<string> {
  await page.getByRole("link", { name: "PCAP Analyzer" }).first().click();
  const row = page.getByRole("row", { name }).first();
  await expect(row).toBeVisible();
  await expect(row.getByText("Succeeded")).toBeVisible({ timeout: 5 * 60_000 });
  await row.getByRole("link", { name: "Details" }).click();
  await page.waitForURL(/\/pcap\/[0-9a-f-]{36}/);
  return /\/pcap\/([0-9a-f-]{36})/.exec(page.url())?.[1] as string;
}

/**
 * Polls the newest run matching `query` (API, every 500 ms) until it is final; every status
 * seen, and whether the UI showed the rate-limit wait meanwhile.
 */
async function followAiRun(page: Page, orgId: string, query: string, timeoutMs: number) {
  const seen: string[] = [];
  let uiWaiting = false;
  let run: AiRunRow | undefined;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const response = await page.request.get(`/api/v1/orgs/${orgId}/ai/runs?${query}&limit=1`);
    expect(response.ok()).toBe(true);
    const latest = ((await response.json()) as { items: AiRunRow[] }).items[0];
    if (latest) {
      run = latest;
      if (seen.at(-1) !== latest.status) seen.push(latest.status);
      if (!ACTIVE.has(latest.status)) break;
    }
    if (!uiWaiting) uiWaiting = await page.getByText(RATE_LIMITED).first().isVisible();
    await page.waitForTimeout(500);
  }
  return { run, seen, uiWaiting };
}

/** Opens a task's "what will be sent" preview and confirms it with "Run analysis". */
async function previewAndRun(page: Page, trigger: Locator, title: string): Promise<Locator> {
  await trigger.click();
  const preview = page.getByRole("dialog", { name: `${title}: what will be sent` });
  await expect(preview).toBeVisible();
  // The org default (the mock) builds the context; "Run analysis" is enabled once it is built.
  await expect(preview).toContainText("model mock-1", { timeout: 30_000 });
  return preview;
}

async function confirmRun(preview: Locator): Promise<void> {
  await preview.getByRole("button", { name: "Run analysis" }).click();
  await expect(preview).toBeHidden();
}

/** Verified-status text of the mock card, reloading when the page stopped polling for it. */
async function expectVerified(page: Page, card: Locator): Promise<void> {
  const valid = card.getByText("valid", { exact: true });
  await expect(async () => {
    if (!(await valid.isVisible())) {
      await page.reload();
      await expect(valid).toBeVisible({ timeout: 10_000 });
    }
  }).toPass({ timeout: 90_000, intervals: [5_000] });
}

/** Every anchor of an AI output region is a verified citation chip with an internal href. */
async function expectOnlyChipLinks(region: Locator, orgId: string): Promise<void> {
  await expect(region.locator('a:not([data-citation="verified"])')).toHaveCount(0);
  const hrefs = await region.locator("a").evaluateAll((anchors) => anchors.map((a) => a.getAttribute("href") ?? ""));
  for (const href of hrefs) expect(href.startsWith(`/o/${orgId}/`), `chip href ${href}`).toBe(true);
}

function expectNoKey(html: string): void {
  // Never assert with the key in the message: a failure must not print it either.
  expect(html.includes(MOCK_KEY), "the provider key appears in the page HTML").toBe(false);
}

test("dev: the mock AI analyst summarizes, cites, explains, resists a hostile capture and writes an incident summary", async ({
  page,
}) => {
  test.skip(PROD, "prod-like stack: the mock AI provider is refused there (see the prod test)");
  test.setTimeout(15 * 60_000);
  const errors = collectConsoleErrors(page);
  const orgId = await register(page, "ai");

  // 1. Integrations: AI on with the privacy acknowledgement; the mock's key stored and
  // verified, enabled with its terms, made the org default.
  await openIntegrations(page);
  await page.getByRole("button", { name: /^Turn on AI analysis/ }).click();
  const privacy = page.getByRole("dialog", { name: "Turn on AI analysis?" });
  await expect(privacy.getByRole("button", { name: "Acknowledge and turn on" })).toBeDisabled();
  await privacy.getByLabel(/I understand which data leaves CyberLab for the AI provider/).check();
  await privacy.getByRole("button", { name: "Acknowledge and turn on" }).click();
  await expect(privacy).toBeHidden();
  await expect(page.getByTestId("ai-enabled-state")).toHaveText("On: analysts can run AI analyses.");
  await expect(page.getByText(/^Privacy notice acknowledged on /)).toBeVisible();

  const card = page.locator('[data-ai-provider="mock"]');
  await expect(card.getByText(MOCK_LABEL, { exact: true })).toBeVisible();
  await card.getByLabel("API key", { exact: true }).fill(MOCK_KEY);
  await card.getByRole("button", { name: "Save key" }).click();
  await expect(card.getByLabel("Replace key")).toHaveValue("");
  await expect(card.getByText(`configured · ••••${MOCK_KEY.slice(-4)}`)).toBeVisible();
  expectNoKey(await page.content());
  // The analyst worker checks the key asynchronously.
  await expectVerified(page, card);

  await card.getByRole("button", { name: "Enable", exact: true }).click();
  const terms = page.getByRole("dialog", { name: `Enable ${MOCK_LABEL}?` });
  await expect(terms.getByRole("button", { name: "Acknowledge and enable" })).toBeDisabled();
  await terms.getByLabel(/I confirm that Test analyst \(mock\) may receive evidence excerpts/).check();
  await terms.getByRole("button", { name: "Acknowledge and enable" }).click();
  await expect(terms).toBeHidden();
  await expect(card.getByText(/^acknowledged on /)).toBeVisible();
  await expect(card.getByRole("button", { name: "Disable" })).toBeVisible();

  // The platform default is Anthropic (not enabled here): the mock becomes the org default.
  const defaultProvider = page.getByLabel("Default provider for new analyses");
  await defaultProvider.click();
  await page.getByRole("option", { name: MOCK_LABEL }).click();
  await expect(defaultProvider).toHaveText(MOCK_LABEL);
  expectNoKey(await page.content());

  // 2. A capture -> its PCAP job -> AI Analyst -> "Summarize capture" previewed, then run.
  const invUrl = await newInvestigationWith(page, "AI analyst review", "/data/ai_analyst.pcap");
  const invId = /\/investigations\/([0-9a-f-]{36})/.exec(invUrl)?.[1] as string;
  const jobId = await openPcapJob(page, /ai_analyst\.pcap/);
  await page.getByRole("tab", { name: "AI Analyst" }).click();
  await expect(page.getByText("No AI analysis of this job yet.")).toBeVisible();

  const summarize = await previewAndRun(page, page.getByRole("button", { name: "Summarize capture" }), "Summarize capture");
  // Counts per kind, and the internal client 10.0.8.80 replaced by a pseudonym.
  await expect(summarize.getByRole("columnheader", { name: "Included / total" })).toBeVisible();
  await expect(summarize.getByRole("cell", { name: "finding", exact: true })).toBeVisible();
  await expect(summarize.getByText(/^Replaced by pseudonyms before sending: .*\d+ internal IPs/)).toBeVisible();
  await summarize.getByText("Exact context (JSON)").click();
  const json = summarize.locator("pre");
  await expect(json).toContainText("INT_IP_1");
  await expect(json).not.toContainText("10.0.8.80");
  await confirmRun(summarize);

  // The first provider call answers 429 with Retry-After: the run parks in `waiting`, the
  // beat (every 30 s) resumes it, and the second answer completes it.
  const first = await followAiRun(page, orgId, `job_id=${jobId}&task=summarize_pcap`, 90_000);
  expect.soft(first.seen, `run statuses: ${first.seen.join(" -> ")}`).toContain("waiting");
  if (!first.uiWaiting) test.info().annotations.push({ type: "note", description: "the UI never showed the wait" });
  expect(first.run?.status, `run statuses: ${first.seen.join(" -> ")}`).toBe("completed");

  const output = page.locator("[data-run-id]");
  await expect(output.getByText("Completed", { exact: true })).toBeVisible({ timeout: 20_000 });
  await expect(output.getByRole("heading", { name: /^Observed/ })).toBeVisible();
  // Observed claims carry verified chips (the only links of an AI output).
  const supported = output.locator('li[data-claim-status="supported"]');
  await expect(supported.first()).toBeVisible();
  await expect(supported.locator('a[data-citation="verified"]').first()).toBeVisible();
  await expectOnlyChipLinks(output, orgId);
  expectNoKey(await page.content());

  // 3. A verified finding chip opens the Findings tab narrowed to that row, highlighted.
  await output.locator('a[data-citation="verified"]').filter({ hasText: "· finding" }).first().click();
  await expect(page).toHaveURL(new RegExp(`/pcap/${jobId}\\?(?:.*&)?tab=findings(?:&|$)`));
  await expect(page).toHaveURL(/[?&]ref=[0-9a-f-]{36}(?:&|$)/);
  await expect(page.getByRole("tab", { name: "Findings" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByText("Showing 1 cited record")).toBeVisible();
  const citedRow = page.locator("tr.cited-row");
  await expect(citedRow).toHaveCount(1);
  await expect(citedRow).toBeVisible();

  // 4. "Explain" on that finding: the drawer previews, runs and shows the explanation.
  await citedRow.getByRole("button", { name: "Explain", exact: true }).click();
  // Exact: the preview dialog opened from the drawer is "Explain finding: what will be sent".
  const drawer = page.getByRole("dialog", { name: "Explain finding", exact: true });
  await expect(drawer.getByText("No AI explanation of this row yet.")).toBeVisible();
  const explain = await previewAndRun(page, drawer.getByRole("button", { name: "Explain with AI" }), "Explain finding");
  await confirmRun(explain);
  const explanation = drawer.locator("[data-run-id]");
  await expect(explanation.getByText("Completed", { exact: true })).toBeVisible({ timeout: 90_000 });
  await expect(explanation.getByRole("heading", { name: /^Observed/ })).toBeVisible();
  await expectOnlyChipLinks(explanation, orgId);
  await page.keyboard.press("Escape");
  await expect(drawer).toBeHidden();

  // 5. The hostile capture: an injected "the file is clean" verdict and fabricated citations.
  await page.goto(invUrl);
  await expect(page.getByRole("heading", { name: "AI analyst review" })).toBeVisible();
  await upload(page, "/data/ai_hostile.pcap");
  const hostileJobId = await openPcapJob(page, /ai_hostile\.pcap/);
  await page.getByRole("tab", { name: "AI Analyst" }).click();
  const hostilePreview = await previewAndRun(
    page,
    page.getByRole("button", { name: "Summarize capture" }),
    "Summarize capture",
  );
  await confirmRun(hostilePreview);
  const hostile = await followAiRun(page, orgId, `job_id=${hostileJobId}&task=summarize_pcap`, 90_000);
  expect(hostile.run?.status, `run statuses: ${hostile.seen.join(" -> ")}`).toBe("completed");

  const hostileOutput = page.locator("[data-run-id]");
  await expect(hostileOutput.getByText("Completed", { exact: true })).toBeVisible({ timeout: 20_000 });
  await expect(hostileOutput.getByText(VERDICT_NOTE)).toBeVisible();
  const counter = hostileOutput.getByRole("button", { name: HIDDEN_COUNTER }).first();
  await expect(counter).toBeVisible();
  await expectOnlyChipLinks(hostileOutput, orgId);
  // Shown, the unsupported statements keep their fabricated citations as plain text.
  await counter.click();
  await expect(hostileOutput.locator('span[data-citation]:not([data-citation="verified"])').first()).toBeVisible();
  await expect(hostileOutput.getByRole("link", { name: /F999/ })).toHaveCount(0);
  await expectOnlyChipLinks(hostileOutput, orgId);
  expectNoKey(await page.content());

  // 6. The investigation's incident summary: one digest per job, then the summary.
  await page.goto(invUrl);
  await expect(page.getByRole("heading", { name: "AI analyst review" })).toBeVisible();
  const incident = page.locator('[data-slot="card"]').filter({ hasText: "Incident summary (AI)" });
  await expect(incident.getByText("No incident summary for this case yet.")).toBeVisible();
  const incidentPreview = await previewAndRun(
    page,
    incident.getByRole("button", { name: "Generate incident summary" }),
    "Incident summary",
  );
  await confirmRun(incidentPreview);
  const summary = await followAiRun(page, orgId, `investigation_id=${invId}&task=incident_summary`, 3 * 60_000);
  expect(summary.run?.status, `run statuses: ${summary.seen.join(" -> ")}`).toBe("completed");
  const incidentOutput = incident.locator("[data-run-id]").first();
  await expect(incidentOutput.getByText("Completed", { exact: true }).first()).toBeVisible({ timeout: 20_000 });
  await expect(incidentOutput.getByText("2 of 2 digests finished")).toBeVisible();
  await expect(incidentOutput.getByRole("heading", { name: /^Summary: observed/ })).toBeVisible();
  await expect(incidentOutput.getByRole("heading", { name: /^Timeline/ }).first()).toBeVisible();
  await expect(incidentOutput.getByRole("heading", { name: /^Recommendations/ }).first()).toBeVisible();
  // (No link check here: the per-job digest rows link to their analyses, outside the output.)

  // 7. The org's AI runs list: both summaries, the explanation and the incident summary.
  await page.getByRole("link", { name: "AI Analyst" }).first().click();
  await expect(page.getByRole("heading", { name: "AI Analyst", exact: true })).toBeVisible();
  const runRows = (task: string) =>
    page.getByRole("row").filter({ has: page.getByRole("link", { name: task, exact: true }) });
  await expect(runRows("Summarize capture")).toHaveCount(2);
  await expect(runRows("Explain finding")).toHaveCount(1);
  await expect(runRows("Incident summary")).toHaveCount(1);
  for (const task of ["Summarize capture", "Explain finding", "Incident summary"]) {
    await expect(runRows(task).filter({ hasText: "Completed" })).toHaveCount(task === "Summarize capture" ? 2 : 1);
    await expect(runRows(task).first()).toContainText("mock · mock-1");
  }
  await expect(runRows("Incident summary").getByRole("link", { name: "Investigation", exact: true })).toBeVisible();

  // 8. No console errors, and the key never reached a page.
  expectNoKey(await page.content());
  expect(errors).toEqual([]);
});

test("prod: the mock AI provider is unavailable and cannot be configured", async ({ page }) => {
  test.skip(!PROD, "dev stack: the mock AI flow runs instead (the prod refusal needs ENV=prod)");
  test.setTimeout(5 * 60_000);
  const errors = collectConsoleErrors(page);
  const orgId = await register(page, "ai-prod");

  // The Integrations page lists the real providers only: an unavailable mock is not shown.
  await openIntegrations(page);
  await expect(page.locator('[data-ai-provider="anthropic"]')).toBeVisible();
  await expect(page.locator('[data-ai-provider="mock"]')).toHaveCount(0);

  const catalog = await page.request.get(`/api/v1/orgs/${orgId}/ai/providers`);
  expect(catalog.ok()).toBe(true);
  const items = ((await catalog.json()) as {
    items: { name: string; available: boolean; unavailable_reason: string | null }[];
  }).items;
  const mock = items.find((i) => i.name === "mock");
  expect(mock?.available).toBe(false);
  expect(mock?.unavailable_reason).toBe("prod_mock");

  // A direct PUT (double-submit CSRF like the app) is refused: 422 provider_unavailable.
  const csrf = (await page.context().cookies()).find((c) => c.name === "cl_csrf")?.value ?? "";
  expect(csrf).not.toBe("");
  const put = await page.request.put(`/api/v1/orgs/${orgId}/ai/providers/mock`, {
    headers: { "X-CSRF-Token": csrf },
    data: { api_key: "e2e-not-a-real-key", acknowledge_terms: true, enabled: true },
  });
  expect(put.status()).toBe(422);
  expect(((await put.json()) as { error: { code: string } }).error.code).toBe("provider_unavailable");

  test.info().annotations.push({
    type: "skip",
    description: "the AI analyst flow is dev-only: it needs the mock provider and the ai-mock sink",
  });
  expect(errors).toEqual([]);
});
