import { describe, expect, it } from "vitest";

import { buildCsp, generateNonce } from "./csp";

function directives(csp: string): Map<string, string[]> {
  return new Map(
    csp.split("; ").map((part) => {
      const [name, ...values] = part.split(" ");
      return [name, values] as const;
    }),
  );
}

describe("generateNonce", () => {
  it("is base64 of at least 16 random bytes", () => {
    const nonce = generateNonce();
    expect(nonce).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
    expect(Buffer.from(nonce, "base64").length).toBeGreaterThanOrEqual(16);
  });

  it("differs every call", () => {
    const nonces = new Set(Array.from({ length: 100 }, generateNonce));
    expect(nonces.size).toBe(100);
  });
});

describe("buildCsp", () => {
  const nonce = "AAAAAAAAAAAAAAAAAAAAAA==";

  it.each([true, false])("never allows inline scripts (dev=%s)", (dev) => {
    const scriptSrc = directives(buildCsp(nonce, { dev })).get("script-src");
    expect(scriptSrc).toEqual(expect.arrayContaining(["'self'", `'nonce-${nonce}'`, "'strict-dynamic'"]));
    expect(scriptSrc).not.toContain("'unsafe-inline'");
  });

  it("is strict in production", () => {
    expect(directives(buildCsp(nonce, { dev: false }))).toEqual(
      new Map([
        ["default-src", ["'self'"]],
        ["script-src", ["'self'", `'nonce-${nonce}'`, "'strict-dynamic'"]],
        ["style-src", ["'self'", "'unsafe-inline'"]],
        ["img-src", ["'self'", "data:", "blob:"]],
        ["font-src", ["'self'", "data:"]],
        ["connect-src", ["'self'"]],
        ["object-src", ["'none'"]],
        ["frame-ancestors", ["'none'"]],
        ["base-uri", ["'self'"]],
        ["form-action", ["'self'"]],
      ]),
    );
  });

  it("adds eval and the HMR websocket in development only", () => {
    const dev = directives(buildCsp(nonce, { dev: true }));
    expect(dev.get("script-src")).toContain("'unsafe-eval'");
    expect(dev.get("connect-src")).toEqual(["'self'", "ws:"]);
  });

  it("keeps the nonce out of style-src ('unsafe-inline' would be ignored next to it)", () => {
    for (const dev of [true, false]) {
      expect(directives(buildCsp(nonce, { dev })).get("style-src")).toEqual(["'self'", "'unsafe-inline'"]);
    }
  });
});
