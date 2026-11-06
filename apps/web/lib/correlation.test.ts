import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import type { paths } from "@cyberlab/contracts";
import createClient from "openapi-fetch";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "@/lib/api";
import {
  type CorrelationLookup,
  type JobCorrelations,
  type SeenIn,
  collectionHref,
  collectionsText,
  commonBadgeText,
  excludedText,
  fetchJobCorrelations,
  fetchKeyLookup,
  isCorrelationKind,
  isUnnormalizableError,
  kindsText,
  lookupSummary,
  occurrenceJobHref,
  rowsFirst,
  seenInByRow,
  seenInChipText,
  seenInSummary,
  sharedKeysText,
  sortSeenIn,
  tiHistoryText,
  tiLookupType,
} from "@/lib/correlation";

const ORG = "11111111-1111-4111-8111-111111111111";
const JOB = "44444444-4444-4444-8444-444444444444";

function seen(over: Partial<SeenIn> = {}): SeenIn {
  return {
    kind: "domain",
    value: "a.example",
    key: "k".repeat(64),
    other_jobs: 1,
    other_cases: 1,
    first_seen: null,
    last_seen: null,
    common: false,
    top_cases: [],
    ...over,
  };
}

describe("also seen in", () => {
  it("chip text counts other cases, else other jobs of this case", () => {
    expect(seenInChipText({ other_cases: 3, other_jobs: 5 })).toBe("seen in 3 other cases");
    expect(seenInChipText({ other_cases: 1, other_jobs: 1 })).toBe("seen in 1 other case");
    expect(seenInChipText({ other_cases: 0, other_jobs: 2 })).toBe("seen in 2 other jobs of this case");
  });

  it("orders keys seen in other cases first and common keys last (stable ties)", () => {
    const items = [
      seen({ value: "common.example", common: true, other_cases: 40, other_jobs: 60 }),
      seen({ value: "b.example", other_cases: 1 }),
      seen({ value: "a.example", other_cases: 1 }),
      seen({ value: "top.example", other_cases: 4 }),
      seen({ kind: "ipv4", value: "192.0.2.1", other_cases: 0, other_jobs: 2 }),
    ];
    expect(sortSeenIn(items).map((i) => i.value)).toEqual(["top.example", "a.example", "b.example", "192.0.2.1", "common.example"]);
    // The input is not mutated.
    expect(items[0].value).toBe("common.example");
  });

  it("summarizes and labels common keys", () => {
    expect(seenInSummary({ items: [], total_keys: 10 })).toBe("No observable of this job was observed in another job.");
    expect(seenInSummary({ items: [seen(), seen()], total_keys: 10 })).toBe(
      "2 observables of 10 also observed in other jobs of this organization.",
    );
    expect(commonBadgeText(51)).toBe("common across 51 jobs; excluded from related cases");
  });
});

describe("key drawer", () => {
  it("links the IOC tab of the job by analyzer", () => {
    expect(occurrenceJobHref(ORG, { analyzer: "pcap", job_id: JOB })).toBe(`/o/${ORG}/pcap/${JOB}?tab=iocs`);
    expect(occurrenceJobHref(ORG, { analyzer: "static", job_id: JOB })).toBe(`/o/${ORG}/malware/${JOB}?tab=iocs`);
    expect(occurrenceJobHref(ORG, { analyzer: "pcap", job_id: "../x" })).toBeNull();
    // M8 RT1: memory occurrences link to the memory job page's IOC tab.
    expect(occurrenceJobHref(ORG, { analyzer: "memory", job_id: JOB })).toBe(`/o/${ORG}/memory/${JOB}?tab=iocs`);
  });

  it("maps kinds to threat intel lookup types (none for JA3 / certificates)", () => {
    expect(tiLookupType("sha256")).toBe("sha256");
    expect(tiLookupType("ja3")).toBeNull();
    expect(tiLookupType("cert_sha256")).toBeNull();
    expect(isCorrelationKind("ja3s")).toBe(true);
    expect(isCorrelationKind("toString")).toBe(false);
  });

  it("summarizes occurrences", () => {
    expect(lookupSummary({ jobs: 0, cases: 0 })).toBe("Not observed in any job of this organization.");
    expect(lookupSummary({ jobs: 3, cases: 1 })).toBe("Also observed in 3 jobs across 1 case.");
    expect(tiHistoryText(0)).toBe("No stored threat intel answers");
    expect(tiHistoryText(2)).toBe("2 stored threat intel answers");
  });
});

describe("requests (RT13: an observable value never goes in a URL)", () => {
  afterEach(() => vi.unstubAllGlobals());
  const VALUE = "secret-c2.example-corp.net";

  function recordingClient(answer: unknown): { client: ReturnType<typeof createClient<paths>>; requests: Request[] } {
    const requests: Request[] = [];
    const client = createClient<paths>({
      baseUrl: "http://web.test",
      fetch: async (request: Request) => {
        requests.push(request.clone());
        return new Response(JSON.stringify(answer), { status: 200, headers: { "Content-Type": "application/json" } });
      },
    });
    return { client, requests };
  }

  it("POSTs the key lookup with the value in the JSON body only", async () => {
    const answer: CorrelationLookup = {
      kind: "domain",
      value_norm: VALUE,
      key: "k".repeat(64),
      common: false,
      jobs: 0,
      cases: 0,
      first_seen: null,
      last_seen: null,
      items: [],
      ti_results: 0,
      collections: [],
      collections_total: 0,
    };
    const { client, requests } = recordingClient(answer);
    const storage = () => ({ getItem: vi.fn(), setItem: vi.fn(), removeItem: vi.fn(), clear: vi.fn(), key: vi.fn(), length: 0 });
    const local = storage();
    vi.stubGlobal("localStorage", local);
    const logs = (["log", "info", "warn", "error", "debug"] as const).map((m) => vi.spyOn(console, m));

    await expect(fetchKeyLookup(ORG, "domain", VALUE, client)).resolves.toEqual(answer);
    const [request] = requests;
    expect(request.method).toBe("POST");
    const url = new URL(request.url);
    expect(url.pathname).toBe(`/api/v1/orgs/${ORG}/correlations/lookup`);
    expect(url.search).toBe("");
    expect(decodeURIComponent(request.url)).not.toContain(VALUE);
    expect(JSON.parse(await request.text())).toEqual({ kind: "domain", value: VALUE });
    expect(local.setItem).not.toHaveBeenCalled();
    for (const spy of logs) {
      expect(spy).not.toHaveBeenCalled();
      spy.mockRestore();
    }
  });

  it("pages the job pivot with ids and filters only", async () => {
    const answer: JobCorrelations = { job_id: JOB, indexed: true, truncated: false, items: [], total_keys: 0, next_cursor: null };
    const { client, requests } = recordingClient(answer);
    await fetchJobCorrelations(ORG, JOB, {}, client);
    await fetchJobCorrelations(ORG, JOB, { kind: "ja3", cursor: "eyJvIjoyMDB9", includeUnique: true }, client);
    expect(requests.map((r) => r.method)).toEqual(["GET", "GET"]);
    expect(new URL(requests[0].url).search).toBe("");
    const params = new URL(requests[1].url).searchParams;
    expect(Object.fromEntries(params)).toEqual({ kind: "ja3", cursor: "eyJvIjoyMDB9", include_unique: "true" });
  });

  it("recognises the lookup's not-normalizable answer", () => {
    expect(isUnnormalizableError(new ApiError(422, "search_query_invalid", "x"))).toBe(true);
    expect(isUnnormalizableError(new ApiError(422, "validation_error", "x"))).toBe(false);
    expect(isUnnormalizableError(new Error("search_query_invalid"))).toBe(false);
  });

  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  it.each(["lib/correlation.ts", "components/correlation/key-drawer.tsx", "components/correlation/ioc-seen-in.tsx"])(
    "%s builds no request URL from a value",
    (file) => {
      const code = readFileSync(path.join(root, file), "utf8");
      expect(code).not.toMatch(/query:\s*\{[^}]*\bvalue\b/);
      // No `?value=`, no old `GET /orgs/{org}/correlations?…` lookup, no `GET /ti/results?value=`.
      expect(code).not.toMatch(/[?&]value=|\{org_id\}\/correlations"|ti\/results/);
    },
  );
});

describe("rows join by IOC row id (RT8)", () => {
  const a = seen({ value: "a.example", key: "a".repeat(64), source_ids: ["row-a"] });
  const b = seen({ value: "b.example", key: "b".repeat(64), source_ids: ["row-b"] });
  const hash = seen({ kind: "sha256", value: "f".repeat(64), key: "f".repeat(64), source_ids: [] });

  it("maps the visible rows to their keys, by id only", () => {
    const byRow = seenInByRow([a, b, hash], ["row-b", "row-x"]);
    expect([...byRow.keys()]).toEqual(["row-b"]);
    expect(byRow.get("row-b")?.value).toBe("b.example");
    // A key without source ids (a sample or evidence hash) joins no row.
    expect(seenInByRow([hash], ["row-a"]).size).toBe(0);
    // Older answers without source_ids join nothing rather than guessing by value.
    expect(seenInByRow([{ ...a, source_ids: undefined }], ["row-a"]).size).toBe(0);
  });

  it("puts the keys of the visible rows first, in row order", () => {
    const { onPage, others } = rowsFirst([a, b, hash], ["row-b", "row-a"]);
    expect(onPage.map((i) => i.value)).toEqual(["b.example", "a.example"]);
    expect(others).toEqual([hash]);
    expect(rowsFirst([a, b], []).others).toEqual([a, b]);
  });
});

describe("collections", () => {
  it("counts and links the collections holding the key", () => {
    expect(collectionsText(0, 0)).toBe("In no IOC collection");
    expect(collectionsText(1, 1)).toBe("In 1 IOC collection");
    expect(collectionsText(20, 25)).toBe("In 25 IOC collections (showing 20)");
    expect(collectionHref(ORG, { investigation_id: "22222222-2222-4222-8222-222222222222" })).toBe(
      `/o/${ORG}/investigations/22222222-2222-4222-8222-222222222222?tab=iocs`,
    );
    expect(collectionHref(ORG, { investigation_id: "../x" })).toBeNull();
  });
});

describe("related cases", () => {
  it("lists kinds largest first and the excluded common keys", () => {
    expect(kindsText({ ipv4: 1, domain: 3, url: 0 })).toBe("3 domain, 1 IPv4");
    expect(sharedKeysText(1)).toBe("1 shared observable");
    expect(excludedText(0)).toBeNull();
    expect(excludedText(2)).toMatch(/^2 common observables excluded/);
  });
});

/*
 * Wording rule (like the M4 `ti-wording.test.ts`): correlation and search UI text states facts
 * about the data ("also observed in"). It never says an observable or a case is malicious,
 * compromised or "linked", and never names an attacker or a verdict.
 */
const FORBIDDEN = /\b(malicious|benign|attacker|attackers|linked|verdict|compromised|threat actor|same actor)\b/i;

describe("correlation and search wording", () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const entries = [
    "lib/correlation.ts",
    "lib/search.ts",
    "lib/use-search.ts",
    "components/correlation",
    "components/search",
    "app/(app)/o/[orgId]/search",
  ];
  const files = (entry: string): string[] => {
    const full = path.join(root, entry);
    if (statSync(full).isFile()) return [full];
    return readdirSync(full).flatMap((name) => files(path.join(entry, name)));
  };
  const sources = entries.flatMap(files).filter((f) => /\.tsx?$/.test(f) && !/\.test\.tsx?$/.test(f));
  const userFacing = (source: string) =>
    source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");

  it("scans the correlation and search sources", () => {
    expect(sources.length).toBeGreaterThanOrEqual(10);
  });

  it.each(sources.map((f) => [path.relative(root, f), f]))("%s has no verdict words", (_n, file) => {
    const match = userFacing(readFileSync(file, "utf8")).match(FORBIDDEN);
    expect(match?.[0] ?? null, `forbidden word in ${file}`).toBeNull();
  });

  it("keeps generated texts neutral", () => {
    const texts = [
      seenInChipText({ other_cases: 2, other_jobs: 3 }),
      seenInChipText({ other_cases: 0, other_jobs: 3 }),
      commonBadgeText(60),
      seenInSummary({ items: [seen()], total_keys: 3 }),
      lookupSummary({ jobs: 2, cases: 2 }),
      excludedText(3) ?? "",
      sharedKeysText(4),
      tiHistoryText(5),
      collectionsText(2, 3),
    ];
    for (const text of texts) expect(text).not.toMatch(FORBIDDEN);
  });
});
