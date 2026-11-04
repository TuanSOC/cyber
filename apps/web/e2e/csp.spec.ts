import { randomBytes } from "node:crypto";

import { expect, test, type Page } from "@playwright/test";

/**
 * Nonce-based CSP (M3 6a, red-team RT1). The prod-like run (`pnpm e2e --prod`) is the one that
 * matters: under Cache Components a prerendered static shell would carry nonce-less scripts that
 * 'strict-dynamic' blocks, so these pages would render but never hydrate.
 */

// Chromium's wording varies by version ("Refused to execute inline script because it violates…",
// "Executing inline script violates…", "Executing inline event handler violates…").
const INLINE_BLOCKED = /inline (script|event handler).*violates the following Content Security Policy/i;

type Probe = { __cspViolations?: string[]; __injected?: boolean; __handler?: boolean; __sameDocument?: boolean };

function nonceOf(csp: string): string {
  const nonce = /'nonce-([^']+)'/.exec(csp)?.[1];
  expect(nonce, `no nonce in ${csp}`).toBeTruthy();
  return nonce!;
}

function directive(csp: string, name: string): string[] {
  const entry = csp.split(";").map((part) => part.trim().split(/\s+/)).find(([key]) => key === name);
  expect(entry, `${name} missing from ${csp}`).toBeTruthy();
  return entry!.slice(1);
}

/** Collects console errors and uncaught page errors. */
function watch(page: Page) {
  const errors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(`${message.text()} @ ${message.location().url}`);
  });
  page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
  return errors;
}

/** Records every CSP violation on each document from before its first script runs. */
async function recordViolations(page: Page) {
  await page.addInitScript(() => {
    const probe = window as unknown as Probe;
    probe.__cspViolations = [];
    document.addEventListener("securitypolicyviolation", (event) => {
      probe.__cspViolations!.push(`${event.effectiveDirective} ${event.blockedURI}`);
    });
  });
}

const violations = (page: Page) => page.evaluate(() => (window as unknown as Probe).__cspViolations);

/** True once React has hydrated the element (React tags hydrated DOM nodes with its fiber). */
const isHydrated = (page: Page, selector: string) =>
  page.locator(selector).first().evaluate((el) => Object.keys(el).some((key) => key.startsWith("__reactFiber$")));

test("HTML pages get a fresh nonce policy; the API keeps a strict one", async ({ request, baseURL }) => {
  const prod = baseURL?.startsWith("https://") ?? false;
  const csp = (await request.get("/login")).headers()["content-security-policy"] ?? "";
  const csp2 = (await request.get("/login")).headers()["content-security-policy"] ?? "";

  const nonce = nonceOf(csp);
  expect(Buffer.from(nonce, "base64").length).toBeGreaterThanOrEqual(16);
  expect(nonceOf(csp2)).not.toBe(nonce);

  const scriptSrc = directive(csp, "script-src");
  expect(scriptSrc).toEqual(expect.arrayContaining(["'self'", `'nonce-${nonce}'`, "'strict-dynamic'"]));
  expect(scriptSrc).not.toContain("'unsafe-inline'");
  expect(scriptSrc.includes("'unsafe-eval'")).toBe(!prod);
  expect(directive(csp, "style-src")).toEqual(["'self'", "'unsafe-inline'"]);
  expect(directive(csp, "default-src")).toEqual(["'self'"]);
  expect(directive(csp, "object-src")).toEqual(["'none'"]);
  expect(directive(csp, "frame-ancestors")).toEqual(["'none'"]);

  // Every script Next.js rendered carries this response's nonce (nothing came from a shell
  // prerendered without a request).
  for (const path of ["/login", "/register", "/no-such-page", "/o/00000000-0000-0000-0000-000000000000/investigations"]) {
    const response = await request.get(path);
    const pageNonce = nonceOf(response.headers()["content-security-policy"] ?? "");
    const scripts = [...(await response.text()).matchAll(/<script\b[^>]*>/g)].map((m) => m[0]);
    expect(scripts.length, path).toBeGreaterThan(0);
    expect(scripts.filter((tag) => !tag.includes(`nonce="${pageNonce}"`)), path).toEqual([]);
  }

  const api = await request.get("/api/v1/health");
  expect(api.headers()["content-security-policy"]).toContain("default-src 'none'");
});

test("public pages hydrate under the policy; markup injected without the nonce cannot run", async ({ page }) => {
  const errors = watch(page);
  await recordViolations(page);

  // /login: client-side validation only works once React is running.
  await page.goto("/login");
  await expect.poll(() => isHydrated(page, "form")).toBe(true);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("Enter a valid email")).toBeVisible();
  // Nothing on the page needs eval or inline script (e.g. zod's eval probe must stay off).
  expect(await violations(page)).toEqual([]);

  // "Create one" is a soft (client-side) navigation: the window survives it.
  await page.evaluate(() => ((window as unknown as Probe).__sameDocument = true));
  await page.getByRole("link", { name: "Create one" }).click();
  await expect(page).toHaveURL(/\/register$/);
  await expect(page.getByRole("button", { name: "Create account" })).toBeVisible();
  expect(await page.evaluate(() => (window as unknown as Probe).__sameDocument)).toBe(true);

  // /register loaded directly.
  await page.goto("/register");
  await expect.poll(() => isHydrated(page, "form")).toBe(true);
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByText("Enter a valid email")).toBeVisible();
  expect(await violations(page)).toEqual([]);

  // A not-found route renders through the same root layout and hydrates too.
  const notFound = await page.goto("/no-such-page");
  expect(notFound?.status()).toBe(404);
  await expect(page.getByText("404").first()).toBeVisible();
  await expect.poll(() => isHydrated(page, "h1")).toBe(true);
  expect(await violations(page)).toEqual([]);

  // Simulated XSS: markup that reaches the HTML parser (what a stored/reflected injection does)
  // with an inline script and an inline handler, under the page's real policy. Neither may run.
  // (page.addScriptTag is no probe for this: a script element created from JS is not
  // parser-inserted, and 'strict-dynamic' deliberately lets running code add scripts.)
  await page.goto("/login");
  await expect.poll(() => isHydrated(page, "form")).toBe(true);
  await page.evaluate(() => {
    const probe = window as unknown as Probe;
    document.open(); // keeps the window and its policy, drops document listeners
    document.addEventListener("securitypolicyviolation", (event) => {
      probe.__cspViolations!.push(`${event.effectiveDirective} ${event.blockedURI}`);
    });
    document.write(
      '<script>window.__injected = true;</script><img src="data:," onerror="window.__handler = true">',
    );
    document.close();
  });
  await expect
    .poll(() => violations(page))
    .toEqual(expect.arrayContaining(["script-src-elem inline", "script-src-attr inline"]));
  expect(await page.evaluate(() => [(window as unknown as Probe).__injected, (window as unknown as Probe).__handler])).toEqual([
    undefined,
    undefined,
  ]);

  // The only console errors: the deliberate not-found status and the two refused injections.
  const notFoundLoad = /^Failed to load resource: .*404.* @ \S+\/no-such-page$/;
  expect(errors.filter((text) => !INLINE_BLOCKED.test(text) && !notFoundLoad.test(text))).toEqual([]);
  expect(errors.filter((text) => INLINE_BLOCKED.test(text))).toHaveLength(2);
});

test("an authenticated page hydrates on a full load", async ({ page }) => {
  const errors = watch(page);
  await recordViolations(page);

  await page.goto("/register");
  await expect.poll(() => isHydrated(page, "form")).toBe(true);
  await page.getByLabel("Your name").fill("CSP Analyst");
  await page.getByLabel("Organization").fill("E2E CSP Team");
  await page.getByLabel("Email").fill(`e2e-csp-${Date.now()}-${randomBytes(3).toString("hex")}@example.com`);
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();

  // Hard-load a dynamic-param route and use it.
  await page.goto(page.url().replace(/\/?$/, "/investigations"));
  await page.getByRole("button", { name: "New investigation" }).click();
  await expect(page.getByRole("dialog")).toBeVisible();

  expect(await violations(page)).toEqual([]);
  expect(errors).toEqual([]);
});
