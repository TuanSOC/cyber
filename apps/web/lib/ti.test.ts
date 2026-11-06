import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  type AttackLabel,
  type IocEnrichment,
  type ProviderSummary,
  type TiResult,
  attackChip,
  attackIds,
  attackIdsFromAttributes,
  chipText,
  chipTitle,
  effectiveLimits,
  historyDeltas,
  historyHref,
  httpsPermalink,
  integrationState,
  lookupHistory,
  lookupTypeForIoc,
  mispUrlHint,
  noteText,
  parseHistoryFragment,
  parseLimit,
  parseLookupInput,
  parseSuffixes,
  refang,
  runOutcomeNotes,
  runPollMs,
  runProviderRows,
  skipReasonText,
  summaryFields,
  tlpBadges,
  urlQueryRemoved,
  visibleIntegrations,
  vtEnginesText,
  waitingText,
} from "@/lib/ti";

const AT = "2026-11-05T10:00:00Z";

function chip(over: Partial<IocEnrichment>): IocEnrichment {
  return {
    provider: "virustotal",
    status: "ok",
    found: true,
    score: null,
    score_scale: null,
    detections: null,
    tags: [],
    families: [],
    attack_ids: [],
    fetched_at: AT,
    expires_at: null,
    stale: false,
    permalink: null,
    result_id: "00000000-0000-0000-0000-000000000001",
    ...over,
  };
}

describe("chip text", () => {
  it("quotes provider numbers with their scale", () => {
    expect(chipText(chip({ detections: { malicious: 12, suspicious: 0, total: 71 } }))).toBe("VT 12/71 engines");
    expect(chipText(chip({ provider: "abuseipdb", score: 87, score_scale: "abuseipdb_confidence_0_100" }))).toBe(
      "AbuseIPDB confidence 87/100",
    );
    expect(chipText(chip({ provider: "urlhaus" }))).toBe("URLhaus listed");
    expect(chipText(chip({ provider: "malwarebazaar" }))).toBe("MalwareBazaar listed");
  });

  it("uses summary counts for OTX pulses and MISP events", () => {
    const otx = { provider: "otx", pulse_count: 3, pulses: [], validation: [] } as ProviderSummary;
    expect(chipText(chip({ provider: "otx" }), otx)).toBe("OTX 3 pulses");
    const misp = {
      provider: "misp",
      attribute_count: 3,
      tlp: [],
      attributes: [
        { type: "ip-dst", event_id: 1, tags: [], to_ids: false },
        { type: "ip-dst", event_id: 1, tags: [], to_ids: false },
        { type: "ip-dst", event_id: 2, tags: [], to_ids: false },
      ],
    } as ProviderSummary;
    expect(chipText(chip({ provider: "misp" }), misp)).toBe("MISP 2 events");
    expect(chipText(chip({ provider: "otx" }))).toBe("OTX listed");
  });

  it("states no record, errors and staleness", () => {
    expect(chipText(chip({ status: "not_found", found: false }))).toBe("VT not found");
    expect(chipText(chip({ provider: "abuseipdb", found: false, score: 0 }))).toBe("AbuseIPDB not found");
    expect(chipText(chip({ status: "error", found: false }))).toBe("VT lookup error");
    expect(chipText(chip({ status: "auth_failed", found: false }))).toBe("VT key rejected");
    expect(chipText(chip({ provider: "urlhaus", stale: true }))).toBe("URLhaus listed · stale");
  });

  it("titles every chip with its source and date", () => {
    const title = chipTitle(chip({ detections: { malicious: 12, suspicious: 1, total: 71 } }));
    expect(title).toMatch(/^Reported by VirusTotal on .+: 71 engines: 12 report malicious, 1 report suspicious$/);
    expect(chipTitle(chip({ provider: "urlhaus", stale: true }))).toMatch(/stale/);
  });

  it("keeps the single engine template", () => {
    expect(vtEnginesText({ malicious: 0, suspicious: 0, total: 70 })).toBe("70 engines: 0 report malicious");
  });
});

describe("permalinks", () => {
  it("links only https URLs without credentials", () => {
    expect(httpsPermalink("https://www.virustotal.com/gui/ip-address/1.1.1.1")).toBe(
      "https://www.virustotal.com/gui/ip-address/1.1.1.1",
    );
    expect(httpsPermalink("http://example.org/")).toBeNull();
    expect(httpsPermalink("javascript:alert(1)")).toBeNull();
    expect(httpsPermalink("data:text/html,x")).toBeNull();
    expect(httpsPermalink("https://user:pw@example.org/")).toBeNull();
    expect(httpsPermalink("//example.org")).toBeNull();
    expect(httpsPermalink(null)).toBeNull();
    expect(httpsPermalink("not a url")).toBeNull();
  });
});

describe("skip reasons and notes", () => {
  it("explains why a value was never sent", () => {
    expect(skipReasonText("not_global_ip")).toBe("private address — not sent");
    expect(skipReasonText("excluded_suffix")).toMatch(/suffix list/);
    expect(skipReasonText("unsupported_type")).toBe("type never sent to providers");
    expect(skipReasonText("something_new")).toBe("not sent (something_new)");
    expect(skipReasonText(null)).toBeNull();
    expect(noteText("query_removed")).toBe("query removed before lookup");
  });

  it("flags URLs whose query string is removed", () => {
    expect(urlQueryRemoved("url", "https://a.example.org/x?token=1")).toBe(true);
    expect(urlQueryRemoved("url", "https://a.example.org/x#frag")).toBe(true);
    expect(urlQueryRemoved("url", "https://a.example.org/x")).toBe(false);
    expect(urlQueryRemoved("domain", "a?b")).toBe(false);
  });

  it("maps IOC row types to lookup types", () => {
    expect(lookupTypeForIoc("file_sha256")).toBe("sha256");
    expect(lookupTypeForIoc("ip")).toBe("ip");
    expect(lookupTypeForIoc("ja3")).toBeNull();
    expect(lookupTypeForIoc("registry_key")).toBeNull();
    // The indicator rides in the fragment only (M7 phase 11): never a query string.
    expect(historyHref("o1", "url", "https://x.example.org/?a=b&c")).toBe(
      "/o/o1/intel/ioc#type=url&value=https%3A%2F%2Fx.example.org%2F%3Fa%3Db%26c",
    );
    expect(historyHref("o1", null, "evil.example")).toBe("/o/o1/intel/ioc#value=evil.example");
  });

  it("parses the history fragment", () => {
    expect(parseHistoryFragment("#type=url&value=https%3A%2F%2Fx.example.org%2F%3Fa%3Db%26c")).toEqual({
      type: "url",
      value: "https://x.example.org/?a=b&c",
    });
    expect(parseHistoryFragment("type=bogus&value=a.example")).toEqual({ type: undefined, value: "a.example" });
    expect(parseHistoryFragment("")).toEqual({ type: undefined, value: "" });
    expect(parseHistoryFragment(`#value=${"a".repeat(5000)}`).value).toHaveLength(2048);
  });

  it("sends the history lookup with the indicator in the body, never in the URL", async () => {
    const calls: { path: string; init: unknown }[] = [];
    const client = {
      POST: async (path: string, init: unknown) => {
        calls.push({ path, init });
        return { data: { items: [], total: 0 }, error: undefined, response: new Response() };
      },
    } as unknown as Parameters<typeof lookupHistory>[3];
    await lookupHistory("o1", { value: "evil.example", type: "domain" }, { limit: 25, offset: 0 }, client);
    expect(calls).toHaveLength(1);
    expect(calls[0].path).toBe("/api/v1/orgs/{org_id}/ti/results/lookup");
    expect(calls[0].init).toEqual({
      params: { path: { org_id: "o1" }, query: { limit: 25, offset: 0 } },
      body: { value: "evil.example", type: "domain" },
    });
    expect(JSON.stringify((calls[0].init as { params: unknown }).params)).not.toContain("evil.example");
  });
});

describe("lookup input", () => {
  it("refangs for display", () => {
    expect(refang("hxxps[:]//evil[.]example(.)org/a")).toBe("https://evil.example.org/a");
    expect(refang("user[@]example[dot]com")).toBe("user@example.com");
  });

  it("parses one value per line, de-duplicated, at most 20", () => {
    expect(parseLookupInput(" a \n\nb\na\r\n").values).toEqual(["a", "b"]);
    const many = Array.from({ length: 21 }, (_, i) => `v${i}`).join("\n");
    expect(parseLookupInput(many).error).toMatch(/At most 20/);
    expect(parseLookupInput("").values).toEqual([]);
  });
});

describe("integrations", () => {
  it("derives the status badge", () => {
    expect(integrationState({ configured: false, verify_status: null })).toBe("not_configured");
    expect(integrationState({ configured: true, verify_status: null })).toBe("unverified");
    expect(integrationState({ configured: true, verify_status: "invalid" })).toBe("invalid");
  });

  it("shows the test provider only when available", () => {
    const items = [
      { name: "virustotal", available: true },
      { name: "mock", available: false },
      { name: "mock", available: true },
    ] as unknown as Parameters<typeof visibleIntegrations>[0];
    expect(visibleIntegrations(items).map((i) => `${i.name}:${i.available}`)).toEqual(["virustotal:true", "mock:true"]);
  });

  it("validates limits against the ceiling", () => {
    expect(parseLimit("", 4)).toEqual({ value: null, error: null });
    expect(parseLimit("3", 4)).toEqual({ value: 3, error: null });
    expect(parseLimit("5", 4).error).toBe("At most 4");
    expect(parseLimit("0", 4).error).toBe("At least 1");
    expect(parseLimit("2.5", null).error).toBe("Whole numbers only");
    expect(
      effectiveLimits({ limits: { per_minute: 2, per_day: null }, default_limits: { per_minute: 4, per_day: 500 } }),
    ).toEqual({ per_minute: 2, per_day: 500 });
  });

  it("checks the MISP URL syntax", () => {
    expect(mispUrlHint("https://misp.example.org")).toBeNull();
    expect(mispUrlHint("http://misp.example.org")).toMatch(/https/);
    expect(mispUrlHint("https://u:p@misp.example.org")).toMatch(/user name/);
    expect(mispUrlHint("https://misp.example.org/?x=1")).toMatch(/query/);
    expect(mispUrlHint("nope")).toMatch(/valid URL/);
  });

  it("parses excluded suffixes", () => {
    expect(parseSuffixes(".Corp.Example.org\ninternal.example.com, corp.example.org\n")).toEqual([
      "corp.example.org",
      "internal.example.com",
    ]);
  });
});

describe("summaries", () => {
  it("labels provider fields with the provider's terms", () => {
    const fields = summaryFields({
      provider: "abuseipdb",
      abuse_confidence_score: 87,
      categories: [18, 99],
      total_reports: 4,
      is_tor: false,
    } as ProviderSummary);
    expect(fields.find((f) => f.key === "confidence")?.text).toBe("87/100");
    expect(fields.find((f) => f.key === "categories")?.list).toEqual(["Brute-Force", "category 99"]);
    expect(fields.find((f) => f.key === "tor")?.text).toBe("no");
  });

  it("renders VT stats only through the engine template", () => {
    const fields = summaryFields({
      provider: "virustotal",
      tags: [],
      last_analysis_stats: { malicious: 2, suspicious: 0, harmless: 60, undetected: 8, timeout: 0 },
    } as ProviderSummary);
    expect(fields[0].text).toBe("70 engines: 2 report malicious");
  });

  it("highlights TLP:RED and TLP:AMBER", () => {
    const summary = { provider: "misp", attributes: [], attribute_count: 0, tlp: ["tlp:red", "tlp:green", "tlp:amber+strict"] };
    expect(tlpBadges(summary as ProviderSummary)).toEqual([
      { label: "TLP:RED", highlight: true },
      { label: "TLP:GREEN", highlight: false },
      { label: "TLP:AMBER+STRICT", highlight: true },
    ]);
    expect(tlpBadges(null)).toEqual([]);
  });
});

describe("history deltas", () => {
  const row = (id: string, provider: TiResult["provider"], over: Partial<TiResult>) =>
    ({ id, provider, status: "ok", found: true, score: null, score_scale: null, detections: null, ...over }) as TiResult;

  it("compares consecutive ok answers of one provider (newest first)", () => {
    const items = [
      row("3", "virustotal", { detections: { malicious: 12, suspicious: 0, total: 70 } }),
      row("x", "abuseipdb", { score: 87 }),
      row("e", "virustotal", { status: "error", found: false }),
      row("2", "virustotal", { detections: { malicious: 3, suspicious: 0, total: 70 } }),
      row("y", "abuseipdb", { score: 20 }),
      row("1", "virustotal", { detections: { malicious: 3, suspicious: 0, total: 70 } }),
    ];
    const deltas = historyDeltas(items);
    expect(deltas.get("3")).toEqual(["detections 3 → 12"]);
    expect(deltas.get("x")).toEqual(["confidence 20 → 87"]);
    expect(deltas.has("2")).toBe(false);
    expect(deltas.has("e")).toBe(false);
  });
});

describe("runs", () => {
  it("backs off polling from 2 s to 10 s and stops when final", () => {
    expect(runPollMs("queued", 0)).toBe(2000);
    expect(runPollMs("running", 2)).toBe(3000);
    expect(runPollMs("waiting", 20)).toBe(10000);
    expect(runPollMs("completed", 1)).toBe(false);
    expect(runPollMs(undefined, 1)).toBe(false);
  });

  it("reads per-provider counts and explains partial runs", () => {
    const summary = {
      items: 6,
      providers: {
        otx: { planned: 2, ok: 2 },
        virustotal: { planned: 4, ok: 1, cached: 1, abandoned_quota_exhausted: 2, latency_p95_ms: 30 },
      },
    };
    const rows = runProviderRows(summary);
    expect(rows.map((r) => r.provider)).toEqual(["virustotal", "otx"]);
    expect(rows[0]).toMatchObject({ planned: 4, answered: 1, cached: 1, abandoned: [{ reason: "quota_exhausted", count: 2 }] });
    const notes = runOutcomeNotes({ status: "partial", summary });
    expect(notes[0]).toBe("VirusTotal: 2 not looked up (daily quota reached).");
    expect(runOutcomeNotes({ status: "completed", summary })).toEqual([]);
    expect(runProviderRows({ providers: "nope" })).toEqual([]);
  });

  it("says until when a run waits", () => {
    expect(waitingText({ status: "running", resume_at: null })).toBeNull();
    expect(waitingText({ status: "waiting", resume_at: null })).toBe("waiting for rate limit");
    expect(waitingText({ status: "waiting", resume_at: AT })).toMatch(/^waiting for rate limit until /);
  });
});

describe("ATT&CK", () => {
  const label = (over: Partial<AttackLabel>): AttackLabel => ({
    id: "T1055",
    technique_id: "T1055",
    name: "Process Injection",
    tactics: [
      { shortname: "privilege-escalation", name: "Privilege Escalation" },
      { shortname: "stealth", name: "Stealth" },
    ],
    is_subtechnique: false,
    parent: null,
    parent_name: null,
    deprecated: false,
    revoked: false,
    url: "https://attack.mitre.org/techniques/T1055/",
    ...over,
  });

  it("keeps only valid ids (the route rejects a batch with one bad id)", () => {
    expect(attackIds(["t1055", "T1055", " T1059.001 ", "T12", "x"])).toEqual(["T1055", "T1059.001"]);
    expect(attackIdsFromAttributes({ attack: "T1055.003, T1620" })).toEqual(["T1055.003", "T1620"]);
    expect(attackIdsFromAttributes({ attack: ["T1027", 5] })).toEqual(["T1027"]);
    expect(attackIdsFromAttributes({})).toEqual([]);
  });

  it("labels known, revoked and unknown ids", () => {
    const known = attackChip("T1055", label({}), { version: "20.0" });
    expect(known.text).toBe("T1055 · Process Injection");
    expect(known.title).toMatch(/Tactics: Privilege Escalation, Stealth/);
    expect(known.href).toBe("https://attack.mitre.org/techniques/T1055/");

    const sub = attackChip("T1055.001", label({ id: "T1055.001", technique_id: "T1055.001", name: "DLL Injection", parent_name: "Process Injection" }), undefined);
    expect(sub.text).toBe("T1055.001 · Process Injection: DLL Injection");

    const revoked = attackChip("T1000", label({ id: "T1000", technique_id: "T1001", revoked: true }), undefined);
    expect(revoked.text).toBe("T1000 (revoked → T1001)");

    const unknown = attackChip("T9999", undefined, { version: "20.0" });
    expect(unknown).toMatchObject({ text: "T9999", title: "T9999: not in ATT&CK v20.0", href: null });

    expect(attackChip("T1055", label({ url: "http://attack.mitre.org/x" }), undefined).href).toBeNull();
  });
});

describe("no indicator in a request URL (M7 phase 11)", () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  it.each(["lib/ti.ts", "lib/use-ti.ts", "app/(app)/o/[orgId]/intel/ioc/page.tsx"])("%s", (file) => {
    const code = readFileSync(path.join(root, file), "utf8");
    // No `?value=` link, no M4 `GET /ti/results?value=` history, no query-string state.
    expect(code).not.toMatch(/\?(?:[\w-]+=[^&#\s]*&)*value=/);
    expect(code).not.toMatch(/GET\("\/api\/v1\/orgs\/\{org_id\}\/ti\/results",/);
    expect(code).not.toMatch(/useSearchParams|query:\s*\{[^}]*\bvalue\b/);
  });
});
