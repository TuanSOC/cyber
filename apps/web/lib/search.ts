/**
 * Org search (M7 phase 8): the typed client for `POST /orgs/{org}/search`, the URL fragment
 * that keeps the query on the page, the per-type sections, snippet highlighting and the
 * deep-link guard. Pure functions only; the hooks live in `lib/use-search.ts`.
 *
 * RT13: the query travels only in the POST body. The page keeps it in the URL fragment, which
 * never reaches a server or a request log. Nothing here writes it to storage, analytics or the
 * console.
 */
import type { Schemas } from "@cyberlab/contracts";

import { isUuid } from "@/lib/ai";
import { ApiError, api, unwrap } from "@/lib/api";
import { caseTabHref, visText } from "@/lib/case";

export type SearchHit = Schemas["SearchHit"];
export type SearchGroup = Schemas["SearchGroup"];
export type SearchOut = Schemas["SearchOut"];
export type SearchIn = Schemas["SearchIn"];
export type SearchType = SearchHit["type"];

/** Display order of the sections and filter chips. */
export const SEARCH_TYPES: readonly SearchType[] = ["observable", "case", "evidence", "finding", "alert", "note"];

export const SEARCH_TYPE_LABELS: Readonly<Record<SearchType, string>> = {
  observable: "Observables",
  case: "Cases",
  evidence: "Evidence",
  finding: "Findings",
  alert: "Alerts",
  note: "Notes",
};

const TYPE_SET: ReadonlySet<string> = new Set(SEARCH_TYPES);

export function isSearchType(value: string): value is SearchType {
  return TYPE_SET.has(value);
}

// ---------------------------------------------------------------------------------------------
// Query bounds (the server re-checks: `422 search_query_invalid`)

export const MIN_QUERY_CHARS = 2;
export const MAX_QUERY_CHARS = 256;

export type QueryCheck = { ok: true; q: string } | { ok: false; q: string; message: string };

/** Trims and checks 2..256 characters (code points, like the API). */
export function checkQuery(raw: string): QueryCheck {
  const q = raw.trim();
  const length = [...q].length;
  if (length < MIN_QUERY_CHARS) return { ok: false, q, message: `Enter at least ${MIN_QUERY_CHARS} characters.` };
  if (length > MAX_QUERY_CHARS) return { ok: false, q, message: `Use at most ${MAX_QUERY_CHARS} characters.` };
  return { ok: true, q };
}

// ---------------------------------------------------------------------------------------------
// The URL fragment (`#q=…&types=…`): the only place the page keeps the query

export type SearchState = { q: string; types: SearchType[] };

/** Fragment text without the leading `#`. Types are kept in display order, duplicates dropped. */
export function searchFragment(q: string, types: readonly SearchType[] = []): string {
  const params = new URLSearchParams();
  params.set("q", q);
  const kept = SEARCH_TYPES.filter((t) => types.includes(t));
  if (kept.length > 0 && kept.length < SEARCH_TYPES.length) params.set("types", kept.join(","));
  return params.toString();
}

/** Reads `#q=…&types=…`; unknown types are ignored; an absent query is "". */
export function parseSearchFragment(hash: string): SearchState {
  const params = new URLSearchParams(hash.startsWith("#") ? hash.slice(1) : hash);
  const q = (params.get("q") ?? "").slice(0, 4 * MAX_QUERY_CHARS);
  const listed = (params.get("types") ?? "").split(",").filter(isSearchType);
  return { q, types: SEARCH_TYPES.filter((t) => listed.includes(t)) };
}

export function searchPagePath(orgId: string): string {
  return `/o/${encodeURIComponent(orgId)}/search`;
}

/** The search page with the query in the fragment, never in a query string. */
export function searchPageHref(orgId: string, q: string, types: readonly SearchType[] = []): string {
  return `${searchPagePath(orgId)}#${searchFragment(q, types)}`;
}

// ---------------------------------------------------------------------------------------------
// Client

type SearchClient = Pick<typeof api, "POST">;

/** `POST /orgs/{org}/search`: the query is in the JSON body only. `client` is for tests. */
export async function searchOrg(orgId: string, body: SearchIn, client: SearchClient = api): Promise<SearchOut> {
  return unwrap(
    await client.POST("/api/v1/orgs/{org_id}/search", {
      params: { path: { org_id: orgId } },
      body,
    }),
  );
}

/** The request body: every type is omitted (the API searches them all) rather than listed. */
export function searchBody(q: string, types: readonly SearchType[], cursor?: string | null): SearchIn {
  const body: SearchIn = { q };
  if (types.length > 0 && types.length < SEARCH_TYPES.length) body.types = SEARCH_TYPES.filter((t) => types.includes(t));
  if (cursor) body.cursor = cursor;
  return body;
}

// ---------------------------------------------------------------------------------------------
// Sections

export type SectionState = {
  type: SearchType;
  /** `timeout`: this type hit the statement timeout; the other types are unaffected. */
  status: "ok" | "timeout";
  hits: SearchHit[];
  nextCursor: string | null;
};

function groupTimedOut(group: SearchGroup): boolean {
  return group.error === "timeout";
}

/**
 * One section per requested type, in display order. A group flagged `error: "timeout"` timed
 * out (older servers: a requested type missing from a `partial` answer); a missing type of a
 * complete answer has no hits.
 */
export function sectionStates(out: SearchOut, requested: readonly SearchType[]): SectionState[] {
  const wanted = requested.length > 0 ? SEARCH_TYPES.filter((t) => requested.includes(t)) : SEARCH_TYPES;
  const byType = new Map<SearchType, SearchGroup>();
  for (const group of out.groups) if (!byType.has(group.type)) byType.set(group.type, group);
  return wanted.map((type) => {
    const group = byType.get(type);
    if (!group) return { type, status: out.partial ? "timeout" : "ok", hits: [], nextCursor: null };
    return {
      type,
      status: groupTimedOut(group) ? "timeout" : "ok",
      hits: group.hits,
      nextCursor: group.next_cursor,
    };
  });
}

/** "3 results", "20+ results" (more behind the cursor), "timed out". */
export function sectionCountText(section: Pick<SectionState, "status" | "hits" | "nextCursor">): string {
  if (section.status === "timeout") return "timed out";
  const n = section.hits.length;
  if (section.nextCursor) return `${n}+ results`;
  return n === 1 ? "1 result" : `${n} results`;
}

/** The ARIA live summary of a finished search. */
export function searchSummaryText(sections: readonly SectionState[]): string {
  const total = sections.reduce((sum, s) => sum + s.hits.length, 0);
  const more = sections.some((s) => s.nextCursor);
  const timedOut = sections.filter((s) => s.status === "timeout").map((s) => SEARCH_TYPE_LABELS[s.type].toLowerCase());
  const head = total === 0 ? "No results" : `${total}${more ? "+" : ""} result${total === 1 && !more ? "" : "s"}`;
  return timedOut.length ? `${head}. Timed out: ${timedOut.join(", ")}.` : `${head}.`;
}

// ---------------------------------------------------------------------------------------------
// Snippet highlighting: ranges first, then `<mark>` elements built from the ranges (never HTML)

export type Range = readonly [start: number, end: number];
export type Segment = { text: string; mark: boolean };

/** A same-length lower-casing (characters whose lower case changes length stay as they are). */
function foldSameLength(text: string): string {
  let out = "";
  for (const ch of text) {
    const lower = ch.toLowerCase();
    out += lower.length === ch.length ? lower : ch;
  }
  return out;
}

function isLowSurrogate(code: number): boolean {
  return code >= 0xdc00 && code <= 0xdfff;
}

/** Sorted, merged, clamped ranges; empty ones dropped; ends never split a surrogate pair. */
export function normalizeRanges(text: string, ranges: readonly Range[]): Range[] {
  const clamped = ranges
    .map(([s, e]): [number, number] => {
      let start = Math.max(0, Math.min(text.length, Math.trunc(s)));
      let end = Math.max(0, Math.min(text.length, Math.trunc(e)));
      if (start > 0 && start < text.length && isLowSurrogate(text.charCodeAt(start))) start -= 1;
      if (end > 0 && end < text.length && isLowSurrogate(text.charCodeAt(end))) end += 1;
      return [start, end];
    })
    .filter(([s, e]) => Number.isFinite(s) && Number.isFinite(e) && e > s)
    .sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const merged: [number, number][] = [];
  for (const [s, e] of clamped) {
    const last = merged.at(-1);
    if (last && s <= last[1]) last[1] = Math.max(last[1], e);
    else merged.push([s, e]);
  }
  return merged;
}

/** Case-insensitive occurrences of each query term (≥ 2 characters) in `text`. */
export function matchRanges(text: string, q: string): Range[] {
  const haystack = foldSameLength(text);
  const terms = [...new Set(foldSameLength(q).split(/\s+/).filter((t) => [...t].length >= MIN_QUERY_CHARS))];
  const ranges: Range[] = [];
  for (const term of terms) {
    let from = 0;
    while (from <= haystack.length - term.length) {
      const at = haystack.indexOf(term, from);
      if (at < 0) break;
      ranges.push([at, at + term.length]);
      from = at + term.length;
    }
  }
  return normalizeRanges(text, ranges);
}

/** Splits `text` at the ranges. Every segment's text then goes through the `vis` rule. */
export function markSegments(text: string, ranges: readonly Range[]): Segment[] {
  const out: Segment[] = [];
  let at = 0;
  for (const [s, e] of normalizeRanges(text, ranges)) {
    if (s > at) out.push({ text: visText(text.slice(at, s)), mark: false });
    out.push({ text: visText(text.slice(s, e)), mark: true });
    at = e;
  }
  if (at < text.length) out.push({ text: visText(text.slice(at)), mark: false });
  return out;
}

/** The segments of a snippet (or title) for a query: plain text with marked matches. */
export function highlight(text: string | null | undefined, q: string): Segment[] {
  if (!text) return [];
  return markSegments(text, matchRanges(text, q));
}

/**
 * The segments of a hit's snippet: the server's `snippet_ranges` (UTF-16 offsets, the JavaScript
 * string index) when it sent any, else the client-side matches of the query. Either way the
 * `<mark>` elements are built from ranges, never from HTML.
 */
export function snippetSegments(hit: Pick<SearchHit, "snippet" | "snippet_ranges">, q: string): Segment[] {
  const text = hit.snippet;
  if (!text) return [];
  const ranges = (hit.snippet_ranges ?? []).map((r): Range => [r.start, r.end]);
  return ranges.length > 0 ? markSegments(text, ranges) : highlight(text, q);
}

// ---------------------------------------------------------------------------------------------
// Deep links

const LINK_ROOTS: ReadonlySet<string> = new Set(["investigations", "evidence", "pcap", "malware", "intel"]);
// Path, query and fragment characters only: no scheme (`:`), no backslash, no space or control.
const SAFE_PATH = /^\/(?!\/)[A-Za-z0-9\-._~%/?=&#+,]*$/;

/**
 * Internal href of a hit, or null. `hit.href` is the API's app path under `/o/{org}` (with or
 * without that prefix). Only known app roots are accepted; anything else (an absolute or
 * protocol-relative URL, another org's path) falls back to the case or evidence page.
 */
export function hitHref(orgId: string, hit: Pick<SearchHit, "href" | "investigation_id" | "evidence_id" | "type">): string | null {
  if (!isUuid(orgId)) return null;
  const base = `/o/${orgId}`;
  let path = typeof hit.href === "string" ? hit.href : "";
  if (path.startsWith(`${base}/`)) path = path.slice(base.length);
  if (SAFE_PATH.test(path) && LINK_ROOTS.has(path.slice(1).split(/[/?#]/, 1)[0])) return `${base}${path}`;
  if (hit.type === "evidence" && isUuid(hit.evidence_id)) return `${base}/evidence/${hit.evidence_id}`;
  if (isUuid(hit.investigation_id)) return caseTabHref(orgId, hit.investigation_id);
  return null;
}

export const MATCH_LABELS: Readonly<Record<SearchHit["match"], string>> = {
  exact: "exact match",
  fts: "text match",
  trigram: "similar",
};

// ---------------------------------------------------------------------------------------------
// Errors

/** "Slow down" text of a `429`, else null. */
export function slowDownText(error: unknown): string | null {
  if (!(error instanceof ApiError) || error.status !== 429) return null;
  const wait = error.retryAfterSeconds;
  return wait
    ? `Slow down: too many searches. Try again in ${wait < 90 ? `${wait} s` : `${Math.ceil(wait / 60)} min`}.`
    : "Slow down: too many searches. Wait a moment and try again.";
}
