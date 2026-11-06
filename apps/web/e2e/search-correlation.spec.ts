import { randomBytes } from "node:crypto";

import { type Page, type Request, expect, test } from "@playwright/test";

/**
 * M7 search and correlation, dev and prod alike (no mock is involved):
 *
 *  1. Register -> case A with the synthetic mixed capture, case B with the small TLS capture
 *     (scripts/e2e.mjs writes both into the cyberlab_e2e_samples volume, mounted at /data).
 *     The two captures share observables, among them the domain `selfsigned.example.org`
 *     (its self-signed TLS session).
 *  2. Both analyses succeed; the correlation indexer (a beat task every 60 s) indexes them.
 *  3. The header search box for the shared domain -> the search page with the query only in
 *     its URL fragment: no request URL (or Referer) carries it, the API gets it in a POST
 *     body. Observable and finding hits from both cases; a finding deep link works and Back
 *     restores the results from the fragment; the observable pivot lists both cases.
 *  4. The IOC tab of job B shows "seen in 1 other case" for the domain; the drawer lists case
 *     A; the case B overview's "Related cases" card shows case A.
 *  5. A hostile query renders inert (no element, no script, no dialog) and stays out of URLs.
 *  No console errors throughout.
 */
const SHARED_DOMAIN = "selfsigned.example.org";
// The tls_self_signed finding names the server: "selfsigned.example.org (203.0.113.30) presented …".
const SHARED_FINDING = "TLS server presented a self-signed certificate";
const CASE_A = "Correlation case A";
const CASE_B = "Correlation case B";
const ANALYSIS_TIMEOUT = 6 * 60_000;
const INDEX_TIMEOUT = 4 * 60_000;
// IocValue shows domains defanged ("selfsigned[.]example[.]org").
const DEFANGED_DOMAIN = /selfsigned(\[\.\]|\.)example(\[\.\]|\.)org/;

function collectConsoleErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  return errors;
}

async function register(page: Page): Promise<string> {
  const email = `e2e-search-${Date.now()}-${randomBytes(3).toString("hex")}@example.com`;
  await page.goto("/register");
  await page.waitForLoadState("networkidle");
  await page.getByLabel("Your name").fill("Search Analyst");
  await page.getByLabel("Organization").fill(`E2E Search Team ${randomBytes(2).toString("hex")}`);
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  const orgId = /\/o\/([0-9a-f-]{36})/.exec(page.url())?.[1];
  expect(orgId, "the overview URL carries the org id").toBeTruthy();
  return orgId as string;
}

/** A new case with one capture uploaded; returns the case URL (without a query string). */
async function newCaseWith(page: Page, title: string, file: string): Promise<string> {
  await page.getByRole("link", { name: "Investigations" }).first().click();
  await page.getByRole("button", { name: "New investigation" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Title", { exact: true }).fill(title);
  await dialog.getByRole("button", { name: "Create" }).click();
  await expect(page.getByRole("heading", { name: title })).toBeVisible();
  await page.waitForURL(/\/investigations\/[0-9a-f-]{36}/);
  const caseUrl = page.url().split("?")[0];
  await page.getByRole("tablist", { name: "Case sections" }).getByRole("tab", { name: "Evidence", exact: true }).click();
  await page.locator('input[type="file"]').setInputFiles(file);
  const name = file.split("/").at(-1) as string;
  await expect(page.getByRole("row").filter({ hasText: name }).first()).toBeVisible();
  return caseUrl;
}

/** Waits for the capture's PCAP analysis to succeed; returns its job id. */
async function succeededPcapJob(page: Page, filename: string): Promise<string> {
  await page.getByRole("link", { name: "PCAP Analyzer" }).first().click();
  const row = page.getByRole("row", { name: new RegExp(filename.replace(/\./g, "\\.")) }).first();
  await expect(row.getByText("Succeeded")).toBeVisible({ timeout: ANALYSIS_TIMEOUT });
  await row.getByRole("link", { name: "Details" }).click();
  await page.waitForURL(/\/pcap\/[0-9a-f-]{36}/);
  return /\/pcap\/([0-9a-f-]{36})/.exec(page.url())?.[1] as string;
}

type SeenIn = { kind: string; value: string; other_cases: number };
type JobCorrelations = { indexed: boolean; items: SeenIn[] };

/** Polls the API (not the UI) until the indexer has linked job B's domain to the other case. */
async function waitForCorrelation(page: Page, orgId: string, jobId: string): Promise<void> {
  await expect
    .poll(
      async () => {
        const response = await page.request.get(`/api/v1/orgs/${orgId}/analyses/${jobId}/correlations?kind=domain`);
        if (!response.ok()) return `HTTP ${response.status()}`;
        const body = (await response.json()) as JobCorrelations;
        if (!body.indexed) return "not indexed";
        return body.items.find((item) => item.value === SHARED_DOMAIN)?.other_cases ?? 0;
      },
      { timeout: INDEX_TIMEOUT, intervals: [5_000, 10_000, 15_000] },
    )
    .toBe(1);
}

/**
 * Records every request of the page until `stop()`. RT13: the search query must never appear
 * in a request URL or a Referer. Playwright appends the URL fragment to navigation request
 * URLs although browsers never send it, so the fragment is stripped before the check.
 */
function recordRequests(page: Page): { stop: () => Request[] } {
  const requests: Request[] = [];
  const onRequest = (request: Request) => requests.push(request);
  page.on("request", onRequest);
  return {
    stop: () => {
      page.off("request", onRequest);
      return requests;
    },
  };
}

function encodings(q: string): string[] {
  const form = new URLSearchParams({ q }).toString().slice("q=".length);
  return [...new Set([q, encodeURIComponent(q), encodeURI(q), form])];
}

async function expectQueryOnlyInPostBody(requests: Request[], orgId: string, q: string): Promise<void> {
  const forms = encodings(q);
  const leaks: string[] = [];
  for (const request of requests) {
    const url = request.url().split("#")[0];
    const referer = ((await request.allHeaders())["referer"] ?? "").split("#")[0];
    if (forms.some((form) => url.includes(form) || referer.includes(form))) leaks.push(`${request.method()} ${url}`);
  }
  expect(leaks, "the query never appears in a request URL or Referer").toEqual([]);
  const searches = requests.filter((r) => r.url().split("?")[0].endsWith(`/api/v1/orgs/${orgId}/search`));
  expect(searches.length, "the page searched through the API").toBeGreaterThan(0);
  for (const search of searches) {
    expect(search.method()).toBe("POST");
    expect(new URL(search.url()).search).toBe("");
    // lib/api.ts re-wraps every Request to add the CSRF header, so Chromium streams the body and
    // reports no post data: the URL and Referer checks above carry the proof (and the hits the
    // page shows prove the server received the query). A visible body must carry it.
    const body = search.postData();
    if (body !== null) expect((JSON.parse(body) as { q?: string }).q).toBe(q);
    expect(search.headers()["content-type"] ?? "").toContain("application/json");
  }
}

function expectFragmentOnly(page: Page, orgId: string, q: string): void {
  const url = new URL(page.url());
  expect(url.pathname).toBe(`/o/${orgId}/search`);
  expect(url.search, "no query string on the search page").toBe("");
  expect(new URLSearchParams(url.hash.slice(1)).get("q")).toBe(q);
}

function resultSection(page: Page, label: string) {
  return page.getByRole("region", { name: new RegExp(`^${label}`) });
}

test("header search, also seen in and related cases across two cases sharing observables", async ({ page }) => {
  test.setTimeout(14 * 60_000);
  const errors = collectConsoleErrors(page);
  const dialogs: string[] = [];
  page.on("dialog", (dialog) => {
    dialogs.push(dialog.message());
    void dialog.dismiss();
  });
  const orgId = await register(page);

  // 1. Two cases sharing observables; both analyses run in parallel.
  await newCaseWith(page, CASE_A, "/data/mixed.pcap");
  const caseB = await newCaseWith(page, CASE_B, "/data/tls_sessions.pcap");

  // 2. Both succeed, then the indexer links them.
  await succeededPcapJob(page, "mixed.pcap");
  const jobB = await succeededPcapJob(page, "tls_sessions.pcap");
  await waitForCorrelation(page, orgId, jobB);

  // 3. The header search box (from a case page): Enter opens the search page.
  await page.goto(caseB);
  await expect(page.getByRole("heading", { name: CASE_B })).toBeVisible();
  const recorder = recordRequests(page);
  const headerBox = page.locator("header").getByRole("searchbox", { name: "Search this organization" });
  await headerBox.fill(SHARED_DOMAIN);
  await headerBox.press("Enter");
  await page.waitForURL(/\/search#/);
  await expect(page.getByRole("heading", { name: "Search", exact: true })).toBeVisible();
  const observables = resultSection(page, "Observables");
  const findings = resultSection(page, "Findings");
  await expect(observables.getByText(SHARED_DOMAIN, { exact: true }).first()).toBeVisible();
  await expect(findings.getByRole("link", { name: SHARED_FINDING }).first()).toBeVisible();
  await expectQueryOnlyInPostBody(recorder.stop(), orgId, SHARED_DOMAIN);
  expectFragmentOnly(page, orgId, SHARED_DOMAIN);

  // Results across types: the observable once (grouped by key; similar domains may follow), the
  // finding in both cases.
  const domainHit = observables.getByRole("listitem").filter({ has: page.getByText(SHARED_DOMAIN, { exact: true }) });
  await expect(domainHit).toHaveCount(1);
  await expect(domainHit.getByText("domain, seen in 2 jobs")).toBeVisible();
  await expect(domainHit.getByText("exact match")).toBeVisible();
  await expect(findings.getByRole("link", { name: SHARED_FINDING })).toHaveCount(2);
  await expect(findings.getByText("CASE-00001", { exact: true }).first()).toBeVisible();
  await expect(findings.getByText("CASE-00002", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: /\d+\+? results?\./ })).toBeVisible();

  // A finding deep link opens the job's Findings tab; Back restores the search from the fragment.
  await findings.getByRole("link", { name: SHARED_FINDING }).first().click();
  await page.waitForURL(/\/pcap\/[0-9a-f-]{36}\?tab=findings/);
  await expect(page.getByText(SHARED_FINDING).first()).toBeVisible();
  await page.goBack();
  await page.waitForURL(/\/search#/);
  expectFragmentOnly(page, orgId, SHARED_DOMAIN);
  await expect(observables.getByText(SHARED_DOMAIN, { exact: true }).first()).toBeVisible();

  // The observable pivot: where else it was observed (both cases, linked).
  await domainHit.getByRole("button", { name: "Where else observed" }).click();
  const pivot = page.getByRole("dialog", { name: "Also observed in" });
  await expect(pivot.getByText(/Also observed in \d+ jobs across 2 cases\./)).toBeVisible();
  await expect(pivot.getByRole("link", { name: new RegExp(CASE_A) })).toBeVisible();
  await expect(pivot.getByRole("link", { name: new RegExp(CASE_B) })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(pivot).toBeHidden();

  // 4. The IOC tab of job B: "also seen in" with the domain seen in one other case.
  await page.goto(`/o/${orgId}/pcap/${jobB}?tab=iocs`);
  const seenIn = page.getByRole("region", { name: "Also seen in" });
  await expect(seenIn.getByText(/also observed in other jobs of this organization/)).toBeVisible();
  const showAll = seenIn.getByRole("button", { name: /^Show all \d+$/ });
  if (await showAll.isVisible()) await showAll.click();
  const domainRow = seenIn.getByRole("listitem").filter({ hasText: DEFANGED_DOMAIN });
  await expect(domainRow).toHaveCount(1);
  // Observable values are text, never links.
  await expect(domainRow.getByRole("link")).toHaveCount(0);
  const chip = domainRow.getByRole("button", { name: /^seen in 1 other case: show where domain value was also observed$/ });
  await expect(chip).toHaveText("seen in 1 other case");
  await chip.click();
  const drawer = page.getByRole("dialog", { name: "Also observed in" });
  await expect(drawer.getByText(/across 2 cases\./)).toBeVisible();
  await expect(drawer.getByRole("link", { name: new RegExp(CASE_A) })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(drawer).toBeHidden();

  // The case B overview: "Related cases" ranks case A.
  await page.goto(caseB);
  await expect(page.getByRole("heading", { name: CASE_B })).toBeVisible();
  const related = page.locator('[data-slot="card"]').filter({ has: page.getByText("Related cases", { exact: true }) });
  await expect(related.getByRole("link", { name: new RegExp(CASE_A) })).toBeVisible();
  await expect(related.getByText(/\d+ shared observables?/).first()).toBeVisible();
  await related.getByRole("link", { name: new RegExp(CASE_A) }).click();
  await expect(page.getByRole("heading", { name: CASE_A })).toBeVisible();

  // 5. A hostile query: inert text, and still only in the fragment and the POST body.
  const hostile = `<img src=x onerror=alert(1)>"'><svg/onload=alert(2)>`;
  await page.goto(`/o/${orgId}/search`);
  await expect(page.getByText("Enter at least two characters and press Enter.")).toBeVisible();
  const hostileRecorder = recordRequests(page);
  const pageBox = page.getByPlaceholder("Search cases, evidence, findings, alerts, notes, observables");
  await pageBox.fill(hostile);
  await pageBox.press("Enter");
  await expect(page.getByRole("status").filter({ hasText: /results?\./ })).toBeVisible();
  await expectQueryOnlyInPostBody(hostileRecorder.stop(), orgId, hostile);
  expectFragmentOnly(page, orgId, hostile);
  await expect(page.getByPlaceholder("Search cases, evidence, findings, alerts, notes, observables")).toHaveValue(hostile);
  await expect(page.locator('img[src="x"]')).toHaveCount(0);
  await expect(page.locator("svg[onload]")).toHaveCount(0);
  expect(dialogs, "no script ran").toEqual([]);

  expect(errors).toEqual([]);
});
