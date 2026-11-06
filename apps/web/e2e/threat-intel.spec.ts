import { randomBytes } from "node:crypto";

import { type Page, expect, test } from "@playwright/test";

/**
 * M4 golden path on the dev-only `mock` provider (the local ti-mock sink, never the internet):
 * Integrations -> key stored and verified -> terms acknowledged -> a capture's IOCs enriched
 * (one rate-limit pause, then completed) -> cached on the second run -> indicator history ->
 * manual lookup with its normalization report. Plus ATT&CK technique names on a Malware Lab
 * job (capa maps the synthetic UPX-like sample to T1027.002), and, on the prod-like stack,
 * the refusal of the mock provider.
 *
 * scripts/e2e.mjs generates /data/ti_iocs.pcap (apps/workers/pcap/dataset/ti_mock.py), copies
 * /data/static/packed_like.bin, starts ti-mock (dev) and passes its key as E2E_TI_MOCK_KEY.
 */
const PROD = process.env.E2E_PROD === "1" || (process.env.E2E_BASE_URL ?? "").startsWith("https:");
const MOCK_KEY = process.env.E2E_TI_MOCK_KEY ?? "";
const ACTIVE = new Set(["queued", "running", "waiting"]);

type Run = { id: string; status: string };

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
  await page.getByLabel("Your name").fill("TI Analyst");
  await page.getByLabel("Organization").fill(`E2E ${who} Team`);
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  const orgId = /\/o\/([0-9a-f-]{36})/.exec(page.url())?.[1];
  expect(orgId, "the overview URL carries the org id").toBeTruthy();
  return orgId as string;
}

async function newInvestigationWith(page: Page, title: string, files: string[]): Promise<void> {
  await page.getByRole("link", { name: "Investigations" }).first().click();
  await page.getByRole("button", { name: "New investigation" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Title", { exact: true }).fill(title);
  await dialog.getByRole("button", { name: "Create" }).click();
  await expect(page.getByRole("heading", { name: title })).toBeVisible();
  for (const file of files) {
    // M6: the uploader lives in the case workspace's Evidence tab.
    await page.getByRole("tablist", { name: "Case sections" }).getByRole("tab", { name: "Evidence", exact: true }).click();
    await page.locator('input[type="file"]').setInputFiles(file);
    const name = file.split("/").at(-1) as string;
    await expect(page.getByRole("row").filter({ hasText: name }).first()).toBeVisible();
  }
}

/**
 * Step 5: the Malware Lab job of packed_like.bin (uploaded earlier) lists capa's "packed with
 * UPX" with its ATT&CK technique named by the offline index ("T1027.002 · parent: name").
 */
async function expectAttackNames(page: Page): Promise<void> {
  await page.getByRole("link", { name: "Malware Lab" }).first().click();
  const row = page.getByRole("row", { name: /packed_like\.bin/ }).first();
  await expect(row.getByText("Succeeded")).toBeVisible({ timeout: 8 * 60_000 });
  await row.getByRole("link", { name: "Details" }).click();
  await page.getByRole("tab", { name: "Capabilities" }).click();
  await expect(page.getByText("packed with UPX")).toBeVisible();
  await expect(page.getByRole("link", { name: /^T1027\.002 · .+: Software Packing$/ })).toBeVisible();
  await expect(page.getByText(/MITRE ATT&CK® Enterprise v\d+/).first()).toBeVisible();
}

async function openIntegrations(page: Page): Promise<void> {
  await page.getByRole("link", { name: "Settings" }).first().click();
  await page.getByRole("navigation", { name: "Settings sections" }).getByRole("link", { name: "Integrations" }).click();
  await expect(page.getByText("What providers receive")).toBeVisible();
}

/** Polls the latest run of a job (API, every 500 ms) until it is final; every status seen. */
async function followRun(page: Page, orgId: string, jobId: string, after: string | null, timeoutMs: number) {
  const seen: string[] = [];
  const deadline = Date.now() + timeoutMs;
  let run: Run | undefined;
  while (Date.now() < deadline) {
    const response = await page.request.get(`/api/v1/orgs/${orgId}/ti/runs?job_id=${jobId}&limit=1`);
    expect(response.ok()).toBe(true);
    const latest = ((await response.json()) as { items: Run[] }).items[0];
    if (latest && latest.id !== after) {
      run = latest;
      if (seen.at(-1) !== latest.status) seen.push(latest.status);
      if (!ACTIVE.has(latest.status)) break;
    }
    await page.waitForTimeout(500);
  }
  return { run, seen };
}

function expectNoKey(html: string): void {
  // Never assert with the key in the message: a failure must not print it either.
  expect(MOCK_KEY.length > 0 && html.includes(MOCK_KEY), "the provider key appears in the page HTML").toBe(false);
}

test("dev: the mock provider enriches a capture's IOCs, caches them and answers lookups", async ({ page }) => {
  test.skip(PROD, "prod-like stack: the mock provider is refused there (see the prod test)");
  test.skip(!MOCK_KEY, "E2E_TI_MOCK_KEY is not set (run through scripts/e2e.mjs)");
  test.setTimeout(12 * 60_000);
  const errors = collectConsoleErrors(page);
  const orgId = await register(page, "ti");

  // 1. Integrations: store the key (write-only), it verifies as valid, then enable with the
  // terms acknowledgement.
  await openIntegrations(page);
  const card = page.locator('div[data-provider="mock"]');
  await expect(card.getByText("Test provider", { exact: true })).toBeVisible();
  await card.getByLabel("API key").fill(MOCK_KEY);
  await card.getByRole("button", { name: "Save key" }).click();
  await expect(card.getByLabel("Replace key")).toHaveValue("");
  await expect(card.getByText("valid", { exact: true })).toBeVisible({ timeout: 60_000 });
  await expect(card.getByText(`••••${MOCK_KEY.slice(-4)}`)).toBeVisible();
  expectNoKey(await page.content());
  await card.getByRole("button", { name: "Enable" }).click();
  const ack = page.getByRole("dialog");
  await expect(ack.getByRole("button", { name: "Acknowledge and enable" })).toBeDisabled();
  await ack.getByLabel(/I confirm that Test provider may receive/).check();
  await ack.getByRole("button", { name: "Acknowledge and enable" }).click();
  await expect(card.getByText("terms acknowledged on")).toBeVisible();
  await expect(card.getByRole("button", { name: "Disable" })).toBeVisible();

  // 2. A capture with names aimed at the mock -> its IOCs -> Enrich. The packed sample for
  // step 5 is analyzed meanwhile (one registration per test: the register rate limit is 5).
  await newInvestigationWith(page, "Threat intel enrichment", ["/data/ti_iocs.pcap", "/data/static/packed_like.bin"]);
  await page.getByRole("link", { name: "PCAP Analyzer" }).first().click();
  const row = page.getByRole("row", { name: /ti_iocs\.pcap/ }).first();
  await expect(row.getByText("Succeeded")).toBeVisible({ timeout: 5 * 60_000 });
  await row.getByRole("link", { name: "Details" }).click();
  await page.waitForURL(/\/pcap\/[0-9a-f-]{36}/);
  const jobId = /\/pcap\/([0-9a-f-]{36})/.exec(page.url())?.[1] as string;
  await page.getByRole("tab", { name: "IOCs" }).click();
  await expect(page.getByTitle("hit.example.com", { exact: true })).toBeVisible();
  await expect(page.getByTitle("http://hit.example.com/a?token=x", { exact: true })).toBeVisible();
  // Documentation addresses are never sent anywhere.
  await expect(page.getByText("private address — not sent").first()).toBeVisible();

  await page.getByRole("button", { name: "Enrich IOCs" }).click();
  const enrich = page.getByRole("dialog");
  await expect(enrich.getByLabel("Test provider")).toBeChecked();
  await enrich.getByRole("button", { name: "Start lookup" }).click();
  // The ratelimit-ra name gets a 429 with Retry-After first: the run parks in `waiting`, the
  // beat (every 30 s) resumes it, and the second answer is a hit: exactly `completed`.
  const first = await followRun(page, orgId, jobId, null, 90_000);
  expect(first.seen, "run statuses").toContain("waiting");
  expect(first.run?.status, `run statuses: ${first.seen.join(" -> ")}`).toBe("completed");
  const progress = page.getByRole("listitem").filter({ hasText: /^Test provider / });
  await expect(page.getByText("Completed", { exact: true })).toBeVisible({ timeout: 20_000 });
  // hit, http://hit.example.com/a and ratelimit-ra answered; notfound and the two file hashes
  // Zeek computed have no record.
  await expect(progress).toHaveText("Test provider 3 answered · 3 no record");
  // The IOCs tab: the mock's answers replace the "special-use name" skip note of these names.
  const iocRow = (value: string | RegExp) =>
    page.getByRole("row").filter({ has: page.getByTitle(value, { exact: true }) });
  const answeredChip = /^Test (?:\d+ hits|listed)$/;
  await expect(iocRow("hit.example.com").getByLabel(/^Reported by Test provider on /)).toBeVisible({
    timeout: 20_000,
  });
  await expect(iocRow("hit.example.com").getByText(answeredChip)).toBeVisible();
  await expect(iocRow("http://hit.example.com/a?token=x").getByText(answeredChip)).toBeVisible();
  await expect(iocRow("http://hit.example.com/a?token=x")).toContainText("query removed before lookup");
  await expect(iocRow(/^ratelimit-ra-[0-9a-f]+\.example\.com$/).getByText(answeredChip)).toBeVisible();
  await expect(iocRow("notfound.example.com").getByText("Test not found")).toBeVisible();
  await expect(page.getByText("special-use or internal name — not sent")).toHaveCount(0);

  // 3. Enrich again: every answer now comes from the org's cache.
  await page.getByRole("button", { name: "Enrich IOCs" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Start lookup" }).click();
  const second = await followRun(page, orgId, jobId, first.run?.id ?? null, 60_000);
  expect(second.run?.status, `run statuses: ${second.seen.join(" -> ")}`).toBe("completed");
  await expect(progress).toHaveText("Test provider 0 answered · 6 from cache", { timeout: 20_000 });
  expectNoKey(await page.content());

  // The run's answers, attributed ("Reported by Test provider on …"), on the Threat Intel page.
  await page.getByRole("link", { name: "Threat Intel" }).first().click();
  const recent = page.locator("section").filter({ has: page.getByRole("heading", { name: "Recent runs" }) });
  await recent.getByRole("row").filter({ hasText: "Analysis IOCs" }).first().getByRole("button", { name: "Show" }).click();
  const results = page.locator("section").filter({ has: page.getByRole("heading", { name: "Results" }) });
  const resultRow = (value: string | RegExp) =>
    results.getByRole("row").filter({ has: page.getByTitle(value, { exact: true }) });
  const answered = /^Test (?:\d+ hits|listed)$/;
  await expect(resultRow("hit.example.com").getByLabel(/^Reported by Test provider on /)).toBeVisible();
  await expect(resultRow("hit.example.com").getByText(answered)).toBeVisible();
  await expect(resultRow("hit.example.com")).toContainText("cached, fetched");
  // Looked up without its query string.
  await expect(resultRow("http://hit.example.com/a").getByText(answered)).toBeVisible();
  await expect(results.getByTitle("http://hit.example.com/a?token=x")).toHaveCount(0);
  await expect(resultRow(/^ratelimit-ra-[0-9a-f]+\.example\.com$/).getByText(answered)).toBeVisible();
  await expect(resultRow("notfound.example.com").getByText("Test not found")).toBeVisible();

  // The indicator history.
  // The indicator stays in the URL fragment and the POST body (M7 phase 11): no request URL
  // carries it, and the page URL has no query string.
  await resultRow("hit.example.com").getByRole("button", { name: "Show details" }).click();
  const requestUrls: string[] = [];
  const onRequest = (request: { url(): string }) => requestUrls.push(request.url());
  page.on("request", onRequest);
  await results.getByRole("link", { name: "View history" }).click();
  await expect(page.getByRole("heading", { name: "Indicator history" })).toBeVisible();
  await expect(page.getByText(/^\d+ answers?$/)).toBeVisible();
  await expect(page.getByText(/^Reported by Test provider on .+: listed$/).first()).toBeVisible();
  page.off("request", onRequest);
  await expect(page).toHaveURL(/\/intel\/ioc#(?:type=[a-z0-9]+&)?value=hit\.example\.com$/);
  expect(new URL(page.url()).search).toBe("");
  expect(requestUrls.some((url) => url.includes("/ti/results/lookup"))).toBe(true);
  expect(requestUrls.filter((url) => url.includes("hit.example.com"))).toEqual([]);

  // 4. Manual lookup: a private address (never sent), a URL (query removed), a name (answered).
  await page.getByRole("link", { name: "Threat Intel" }).first().click();
  await expect(page.getByRole("heading", { name: "Threat Intel" })).toBeVisible();
  await page.getByLabel(/^Indicators/).fill("10.0.0.1\nhttps://hit.example.com/a?token=x\nhit.example.com");
  await page.getByRole("button", { name: "Look up" }).click();
  const report = page.locator("section").filter({ has: page.getByRole("heading", { name: "Normalization" }) });
  const reportRow = (entered: string) =>
    report.getByRole("row").filter({ has: page.getByTitle(entered, { exact: true }) });
  await expect(reportRow("10.0.0.1")).toContainText("private address — not sent");
  const urlRow = reportRow("https://hit.example.com/a?token=x");
  await expect(urlRow.getByTitle("https://hit.example.com/a", { exact: true })).toBeVisible();
  await expect(urlRow).toContainText("query removed before lookup");
  await expect(urlRow).toContainText("Test provider");
  await expect(reportRow("hit.example.com")).toContainText("Test provider");

  // The lookup's own run (the https URL is only in it): a fresh answer, and a cached one.
  await expect(resultRow("https://hit.example.com/a").getByLabel(/^Reported by Test provider on /)).toBeVisible({
    timeout: 60_000,
  });
  await expect(results.getByText("Completed", { exact: true })).toBeVisible();
  await expect(resultRow("hit.example.com").getByText(answered)).toBeVisible();
  await expect(resultRow("hit.example.com")).toContainText("cached, fetched");
  await expect(results.getByTitle("10.0.0.1")).toHaveCount(0);

  expectNoKey(await page.content());

  // 5. ATT&CK technique names on the Malware Lab job.
  await expectAttackNames(page);

  // 6. No console errors, and the key never reached a page.
  expectNoKey(await page.content());
  expect(errors).toEqual([]);
});

test("prod: the mock provider is unavailable and cannot be configured; ATT&CK names are shown", async ({ page }) => {
  test.skip(!PROD, "dev stack: the mock flow runs instead (the prod refusal needs ENV=prod)");
  test.setTimeout(10 * 60_000);
  const errors = collectConsoleErrors(page);
  const orgId = await register(page, "ti-prod");

  await openIntegrations(page);
  await expect(page.getByText("VirusTotal", { exact: true })).toBeVisible();
  await expect(page.locator('div[data-provider="mock"]')).toHaveCount(0);

  const catalog = await page.request.get(`/api/v1/orgs/${orgId}/integrations`);
  expect(catalog.ok()).toBe(true);
  const items = ((await catalog.json()) as { items: { name: string; available: boolean }[] }).items;
  expect(items.find((i) => i.name === "mock")?.available).toBe(false);

  // A direct PUT (double-submit CSRF like the app) is refused: 422 provider_unavailable.
  const csrf = (await page.context().cookies()).find((c) => c.name === "cl_csrf")?.value ?? "";
  expect(csrf).not.toBe("");
  const put = await page.request.put(`/api/v1/orgs/${orgId}/integrations/mock`, {
    headers: { "X-CSRF-Token": csrf },
    data: { api_key: "e2e-not-a-real-key", acknowledge_terms: true, enabled: true },
  });
  expect(put.status()).toBe(422);
  expect(((await put.json()) as { error: { code: string } }).error.code).toBe("provider_unavailable");

  // The enrichment flow itself is dev-only (it needs the mock); ATT&CK labels are not.
  await newInvestigationWith(page, "Packed sample triage", ["/data/static/packed_like.bin"]);
  await expectAttackNames(page);
  expect(errors).toEqual([]);
});
