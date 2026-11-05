import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import type { paths } from "@cyberlab/contracts";
import createClient from "openapi-fetch";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "@/lib/api";
import {
  type SearchHit,
  type SearchOut,
  checkQuery,
  highlight,
  hitHref,
  markSegments,
  matchRanges,
  normalizeRanges,
  parseSearchFragment,
  searchBody,
  searchFragment,
  searchOrg,
  searchPageHref,
  searchSummaryText,
  sectionCountText,
  sectionStates,
  slowDownText,
  snippetSegments,
} from "@/lib/search";

const ORG = "11111111-1111-4111-8111-111111111111";
const INV = "22222222-2222-4222-8222-222222222222";
const EVI = "33333333-3333-4333-8333-333333333333";
const SECRET = "evil-c2.example";

function hit(over: Partial<SearchHit> = {}): SearchHit {
  return {
    type: "case",
    id: "h1",
    title: "Case title",
    snippet: null,
    match: "fts",
    investigation_id: INV,
    case_ref: "CASE-00012",
    job_id: null,
    evidence_id: null,
    kind: null,
    href: `/investigations/${INV}`,
    ...over,
  };
}

describe("query bounds", () => {
  it("trims and enforces 2..256 characters (code points)", () => {
    expect(checkQuery("  ab ")).toEqual({ ok: true, q: "ab" });
    expect(checkQuery(" a ").ok).toBe(false);
    expect(checkQuery("x".repeat(256)).ok).toBe(true);
    expect(checkQuery("x".repeat(257)).ok).toBe(false);
    // 256 astral characters are 512 UTF-16 units but 256 characters.
    expect(checkQuery("😀".repeat(256)).ok).toBe(true);
  });
});

describe("fragment", () => {
  it("round-trips the query and the types, in display order", () => {
    const fragment = searchFragment("a b&c=#d", ["note", "case", "note"]);
    expect(parseSearchFragment(`#${fragment}`)).toEqual({ q: "a b&c=#d", types: ["case", "note"] });
  });

  it("drops unknown types and omits the list when every type is selected", () => {
    expect(parseSearchFragment("#q=x&types=case,bogus").types).toEqual(["case"]);
    expect(searchFragment("ab", ["observable", "case", "evidence", "finding", "alert", "note"])).toBe("q=ab");
  });

  it("puts the query after # and never in a query string", () => {
    const href = searchPageHref(ORG, SECRET);
    expect(href.split("#")[0]).toBe(`/o/${ORG}/search`);
    expect(href.split("#")[0]).not.toContain("?");
  });
});

describe("request (RT13)", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("POSTs the query in the JSON body only, never in the URL or storage", async () => {
    const requests: Request[] = [];
    const out: SearchOut = { groups: [], partial: false };
    const client = createClient<paths>({
      baseUrl: "http://web.test",
      fetch: async (request: Request) => {
        requests.push(request.clone());
        return new Response(JSON.stringify(out), { status: 200, headers: { "Content-Type": "application/json" } });
      },
    });
    const storage = () => ({ getItem: vi.fn(), setItem: vi.fn(), removeItem: vi.fn(), clear: vi.fn(), key: vi.fn(), length: 0 });
    const local = storage();
    const session = storage();
    vi.stubGlobal("localStorage", local);
    vi.stubGlobal("sessionStorage", session);
    const logs = (["log", "info", "warn", "error", "debug"] as const).map((m) => vi.spyOn(console, m));

    await searchOrg(ORG, searchBody(SECRET, ["observable"]), client);
    await searchOrg(ORG, searchBody(SECRET, ["case"], "cur_1"), client);
    parseSearchFragment(`#${searchFragment(SECRET, ["case"])}`);

    expect(requests).toHaveLength(2);
    for (const request of requests) {
      expect(request.method).toBe("POST");
      const url = new URL(request.url);
      expect(url.pathname).toBe(`/api/v1/orgs/${ORG}/search`);
      expect(url.search).toBe("");
      expect(decodeURIComponent(request.url)).not.toContain(SECRET);
    }
    expect(JSON.parse(await requests[0].text())).toEqual({ q: SECRET, types: ["observable"] });
    expect(JSON.parse(await requests[1].text())).toEqual({ q: SECRET, types: ["case"], cursor: "cur_1" });
    for (const s of [local, session]) {
      expect(s.setItem).not.toHaveBeenCalled();
      expect(s.getItem).not.toHaveBeenCalled();
    }
    for (const spy of logs) {
      expect(spy).not.toHaveBeenCalled();
      spy.mockRestore();
    }
  });

  it("omits types when every type is wanted", () => {
    expect(searchBody("ab", [])).toEqual({ q: "ab" });
  });
});

describe("no query leak in the search sources", () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const entries = ["lib/search.ts", "lib/use-search.ts", "components/search", "app/(app)/o/[orgId]/search"];
  const files = (entry: string): string[] => {
    const full = path.join(root, entry);
    if (statSync(full).isFile()) return [full];
    return readdirSync(full).flatMap((name) => files(path.join(entry, name)));
  };
  const sources = entries.flatMap(files).filter((f) => /\.tsx?$/.test(f) && !/\.test\.tsx?$/.test(f));

  it("scans the search box, page and hooks", () => {
    expect(sources.length).toBeGreaterThanOrEqual(5);
  });

  it.each(sources.map((f) => [path.relative(root, f), f]))("%s uses no storage, console, beacon or ?q=", (_n, file) => {
    const code = readFileSync(file, "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
    expect(code).not.toMatch(/localStorage|sessionStorage|indexedDB|document\.cookie|sendBeacon|console\.|[?&]q=|useSearchParams/);
  });
});

describe("sections", () => {
  it("isolates a timed-out type: missing from a partial answer", () => {
    const out: SearchOut = {
      partial: true,
      groups: [
        { type: "case", hits: [hit()], next_cursor: null },
        { type: "note", hits: [], next_cursor: null },
      ],
    };
    const sections = sectionStates(out, []);
    expect(sections.map((s) => s.type)).toEqual(["observable", "case", "evidence", "finding", "alert", "note"]);
    const byType = Object.fromEntries(sections.map((s) => [s.type, s]));
    expect(byType.case.status).toBe("ok");
    expect(byType.case.hits).toHaveLength(1);
    expect(byType.note.status).toBe("ok");
    expect(byType.observable.status).toBe("timeout");
    expect(sectionCountText(byType.observable)).toBe("timed out");
    expect(searchSummaryText(sections)).toBe("1 result. Timed out: observables, evidence, findings, alerts.");
  });

  it("honours a group flagged error: timeout and requested types only", () => {
    const out = {
      partial: true,
      groups: [
        { type: "alert", hits: [], next_cursor: null, error: "timeout" },
        { type: "case", hits: [hit(), hit({ id: "h2" })], next_cursor: "c2" },
      ],
    } as SearchOut;
    const sections = sectionStates(out, ["case", "alert"]);
    expect(sections.map((s) => [s.type, s.status])).toEqual([
      ["case", "ok"],
      ["alert", "timeout"],
    ]);
    expect(sectionCountText(sections[0])).toBe("2+ results");
  });

  it("treats a missing type of a complete answer as empty", () => {
    const [section] = sectionStates({ partial: false, groups: [] }, ["finding"]);
    expect(section).toEqual({ type: "finding", status: "ok", hits: [], nextCursor: null });
    expect(searchSummaryText([section])).toBe("No results.");
  });
});

describe("ranges to marks", () => {
  it("marks at the start and the end of the text", () => {
    expect(markSegments("abcdef", [[0, 2], [4, 6]])).toEqual([
      { text: "ab", mark: true },
      { text: "cd", mark: false },
      { text: "ef", mark: true },
    ]);
  });

  it("clamps, merges, sorts and drops empty ranges", () => {
    expect(normalizeRanges("abcdef", [[4, 99], [-3, 1], [2, 2], [3, 5], [0, 1]])).toEqual([
      [0, 1],
      [3, 6],
    ]);
    expect(markSegments("abc", [[0, 3]])).toEqual([{ text: "abc", mark: true }]);
    expect(markSegments("abc", [])).toEqual([{ text: "abc", mark: false }]);
    expect(markSegments("", [[0, 1]])).toEqual([]);
  });

  it("never splits a surrogate pair", () => {
    const text = "a😀b";
    expect(normalizeRanges(text, [[2, 3]])).toEqual([[1, 3]]);
    expect(normalizeRanges(text, [[0, 2]])).toEqual([[0, 3]]);
  });

  it("finds every query term case-insensitively", () => {
    expect(matchRanges("Evil-C2 and evil-c2.example", "evil-c2")).toEqual([
      [0, 7],
      [12, 19],
    ]);
    expect(matchRanges("İstanbul beacon", "BEACON")).toEqual([[9, 15]]);
    // Single-character terms are not highlighted.
    expect(matchRanges("a b c", "a")).toEqual([]);
  });

  it("applies the vis rule to every segment (hostile text stays visible text)", () => {
    const segments = highlight("x‮txt.exe <img src=x>", "img");
    expect(segments.map((s) => s.text).join("")).toBe("x⟨U+202E⟩txt.exe <img src=x>");
    expect(segments.find((s) => s.mark)?.text).toBe("img");
  });
});

describe("deep links", () => {
  it("accepts app paths with or without the org prefix", () => {
    expect(hitHref(ORG, hit())).toBe(`/o/${ORG}/investigations/${INV}`);
    expect(hitHref(ORG, hit({ href: `/o/${ORG}/pcap/${INV}?tab=alerts&ref=a1` }))).toBe(`/o/${ORG}/pcap/${INV}?tab=alerts&ref=a1`);
  });

  it("refuses external, scheme, other-org and unknown paths (falls back to the case)", () => {
    for (const href of ["javascript:alert(1)", "//evil.example/x", "https://evil.example", "/o/other/investigations/x", "/admin", "/evidence\\x", "/evidence/a b"]) {
      expect(hitHref(ORG, hit({ href }))).toBe(`/o/${ORG}/investigations/${INV}`);
    }
    expect(hitHref(ORG, hit({ type: "evidence", href: "javascript:x", evidence_id: EVI }))).toBe(`/o/${ORG}/evidence/${EVI}`);
    expect(hitHref(ORG, hit({ href: "javascript:x", investigation_id: null }))).toBeNull();
    expect(hitHref("not-a-uuid", hit())).toBeNull();
  });
});

describe("rate limit", () => {
  it("says slow down with Retry-After", () => {
    expect(slowDownText(new ApiError(429, "rate_limited", "x", undefined, 12))).toBe(
      "Slow down: too many searches. Try again in 12 s.",
    );
    expect(slowDownText(new ApiError(429, "rate_limited", "x"))).toMatch(/^Slow down/);
    expect(slowDownText(new ApiError(500, "x", "x"))).toBeNull();
  });
});

describe("server snippet ranges (M7 follow-up)", () => {
  it("marks the server's UTF-16 ranges, also after an astral character", () => {
    const snippet = "\u{1F600} Quokka quokka";
    const ranges = [
      { start: 3, end: 9 },
      { start: 10, end: 16 },
    ];
    const segments = snippetSegments({ snippet, snippet_ranges: ranges }, "zzz");
    expect(segments.filter((s) => s.mark).map((s) => s.text)).toEqual(["Quokka", "quokka"]);
    expect(segments.map((s) => s.text).join("")).toBe(snippet);
  });

  it("falls back to client matching without ranges, and builds marks from ranges only", () => {
    expect(snippetSegments({ snippet: "a quokka b", snippet_ranges: [] }, "quokka").filter((s) => s.mark)).toEqual([
      { text: "quokka", mark: true },
    ]);
    expect(snippetSegments({ snippet: null }, "quokka")).toEqual([]);
    // Hostile text inside a range stays text, and the vis rule still applies.
    const hostile = "<img src=x>‮";
    const marked = snippetSegments({ snippet: hostile, snippet_ranges: [{ start: 0, end: hostile.length }] }, "x");
    expect(marked).toHaveLength(1);
    expect(marked[0].mark).toBe(true);
    expect(marked[0].text).toContain("<img src=x>");
    expect(marked[0].text).not.toContain("‮");
  });

  it("clamps out-of-range server offsets", () => {
    const segments = snippetSegments({ snippet: "quokka", snippet_ranges: [{ start: -5, end: 99 }] }, "x");
    expect(segments).toEqual([{ text: "quokka", mark: true }]);
  });
});
