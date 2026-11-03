import { describe, expect, it } from "vitest";

import { safeNext } from "./safe-next";

const ORIGIN = "http://localhost:8080";
const next = (value: string | null) => safeNext(value, "/fallback", ORIGIN);

describe("safeNext", () => {
  it.each([
    ["/o/123", "/o/123"],
    ["/o/123/settings?tab=members#top", "/o/123/settings?tab=members#top"],
    ["/o/../login", "/login"],
  ])("keeps same-origin path %s", (input, expected) => {
    expect(next(input)).toBe(expected);
  });

  it.each([
    null,
    "",
    "https://evil.example",
    "//evil.example",
    "/\t/evil.example",
    "/\n/evil.example",
    "/\r/evil.example",
    "/ /evil.example",
    "/\\evil.example",
    "\\/evil.example",
    "/%09/ok", // stays encoded: only literal control chars are stripped by browsers
    "javascript:alert(1)",
    "evil.example",
  ])("rejects %j", (input) => {
    const result = next(input);
    expect(result === "/fallback" || result === "/%09/ok").toBe(true);
    expect(new URL(result, ORIGIN).origin).toBe(ORIGIN);
  });
});
