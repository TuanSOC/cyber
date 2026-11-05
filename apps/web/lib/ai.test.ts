import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  AI_ERROR_TEXT,
  AI_RUN_STATUSES,
  AI_STATUS_LABELS,
  type AiCitation,
  type AiDeepLink,
  FLAG_TEXT,
  REASON_TEXT,
  TASK_LABELS,
  aiErrorText,
  aiPollMs,
  childFlags,
  citationChip,
  claimSupportText,
  contextTruncationNotes,
  deepLinkHref,
  digestProgress,
  displayText,
  failedChildren,
  formatCost,
  hiddenClaimsText,
  latestByTask,
  partitionClaims,
  pseudonymizationText,
  routeForTask,
  runStateView,
  runTargetHref,
  supersededIds,
  visibleSlice,
} from "@/lib/ai";
import { REF_TABS, parseTab } from "@/lib/pcap-results";
import { STATIC_REF_TABS, parseStaticTab } from "@/lib/static-results";

const ORG = "11111111-1111-4111-8111-111111111111";
const JOB = "22222222-2222-4222-8222-222222222222";
const ROW = "33333333-3333-4333-8333-333333333333";

function citation(over: Partial<AiCitation> = {}): AiCitation {
  return {
    label: "F1",
    kind: "finding",
    status: "verified",
    reason: null,
    field: "title",
    quote: "beacon to 10.0.0.5",
    ref_id: ROW,
    job_id: JOB,
    stale: false,
    link: { route: "pcap", job_id: JOB, tab: "findings", ref: ROW },
    ...over,
  };
}

describe("deepLinkHref", () => {
  it("maps verified descriptors to internal routes only", () => {
    expect(deepLinkHref(ORG, { route: "pcap", job_id: JOB, tab: "findings", ref: ROW })).toBe(
      `/o/${ORG}/pcap/${JOB}?tab=findings&ref=${ROW}`,
    );
    expect(deepLinkHref(ORG, { route: "malware", job_id: JOB, tab: "overview", ref: null })).toBe(`/o/${ORG}/malware/${JOB}`);
    expect(deepLinkHref(ORG, { route: "evidence", job_id: null, tab: null, ref: ROW })).toBe(`/o/${ORG}/evidence/${ROW}`);
    expect(deepLinkHref(ORG, { route: "investigation", job_id: null, tab: null, ref: ROW })).toBe(
      `/o/${ORG}/investigations/${ROW}`,
    );
  });

  it("URL-encodes a flow ref (analyzer-written Zeek uid, RT16)", () => {
    const href = deepLinkHref(ORG, { route: "pcap", job_id: JOB, tab: "flows", ref: "C1&x=<script>/../#" });
    expect(href).toBe(`/o/${ORG}/pcap/${JOB}?tab=flows&ref=C1%26x%3D%3Cscript%3E%2F..%2F%23`);
    expect(new URL(href!, "https://app.invalid").searchParams.get("ref")).toBe("C1&x=<script>/../#");
  });

  it("drops unknown routes, unknown tabs, non-uuid ids and over-long refs", () => {
    const bad: unknown[] = [
      { route: "https://evil.example", job_id: JOB, tab: "findings", ref: ROW },
      { route: "pcap", job_id: JOB, tab: "javascript:alert(1)", ref: ROW },
      { route: "pcap", job_id: "../../admin", tab: "findings", ref: ROW },
      { route: "malware", job_id: JOB, tab: "alerts", ref: ROW },
      { route: "evidence", job_id: null, tab: null, ref: "//evil.example" },
      { route: "pcap", job_id: JOB, tab: "flows", ref: "x".repeat(129) },
    ];
    for (const link of bad) expect(deepLinkHref(ORG, link as AiDeepLink)).toBeNull();
    expect(deepLinkHref("not-an-org", { route: "pcap", job_id: JOB, tab: "findings", ref: ROW })).toBeNull();
    expect(deepLinkHref(ORG, null)).toBeNull();
  });

  it("never produces an absolute or external URL", () => {
    const routes = ["pcap", "malware", "evidence", "investigation", "x"] as const;
    const tabs = [null, "overview", "findings", "flows", "strings", "imports", "dns"] as const;
    const refs = [null, ROW, "http://evil.example", "//evil", "javascript:alert(1)"];
    for (const route of routes)
      for (const tab of tabs)
        for (const ref of refs) {
          const href = deepLinkHref(ORG, { route, job_id: JOB, tab, ref } as AiDeepLink);
          if (href !== null) {
            expect(href.startsWith(`/o/${ORG}/`)).toBe(true);
            expect(href).not.toMatch(/^\/\/|:\/\/|javascript:/i);
          }
        }
  });

  // Each verified chip lands on the exact cited row: the tab is one the page opens, and that
  // tab reads `ref` (flows highlights its uid; overview / sections carry no row).
  it.each([
    ["pcap", "findings"],
    ["pcap", "alerts"],
    ["pcap", "dns"],
    ["pcap", "http"],
    ["pcap", "tls"],
    ["pcap", "iocs"],
    ["pcap", "timeline"],
    ["malware", "findings"],
    ["malware", "signatures"],
    ["malware", "capabilities"],
    ["malware", "strings"],
    ["malware", "iocs"],
  ] as const)("%s %s chip opens that tab filtered to the row", (route, tab) => {
    const href = deepLinkHref(ORG, { route, job_id: JOB, tab, ref: ROW });
    const url = new URL(href!, "https://app.invalid");
    expect(url.pathname).toBe(`/o/${ORG}/${route}/${JOB}`);
    expect(url.searchParams.get("ref")).toBe(ROW);
    const opened = route === "pcap" ? parseTab(url.searchParams.get("tab")) : parseStaticTab(url.searchParams.get("tab"), "full");
    expect(opened).toBe(tab);
    expect((route === "pcap" ? REF_TABS : STATIC_REF_TABS).has(opened)).toBe(true);
  });
});

describe("citationChip", () => {
  it("links verified citations only, with field and quote in the tooltip", () => {
    const chip = citationChip(ORG, citation());
    expect(chip.href).toBe(`/o/${ORG}/pcap/${JOB}?tab=findings&ref=${ROW}`);
    expect(chip.text).toBe("F1 · finding");
    expect(chip.title).toContain("field: title");
    expect(chip.title).toContain("beacon to 10.0.0.5");
  });

  it("never links unverified or invalid citations, even if a descriptor is present", () => {
    const unverified = citationChip(ORG, citation({ status: "unverified", reason: "quote_mismatch" }));
    expect(unverified.href).toBeNull();
    expect(unverified.title).toBe("Unverified citation: quote not found in record");
    const invalid = citationChip(ORG, citation({ status: "invalid", reason: "out_of_scope" }));
    expect(invalid.href).toBeNull();
    expect(invalid.title).toBe("Invalid citation: outside this case");
    expect(citationChip(ORG, citation({ status: "invalid", reason: "unknown_label", kind: null })).title).toContain(
      "unknown reference",
    );
  });

  it("drops a verified citation's link when the descriptor is unknown", () => {
    const chip = citationChip(ORG, citation({ link: { route: "malware", job_id: JOB, tab: "alerts", ref: ROW } }));
    expect(chip.href).toBeNull();
  });
});

describe("claims", () => {
  it("hides unsupported claims, keeping order", () => {
    const items = [
      { id: "a", status: "supported" as const },
      { id: "b", status: "unsupported" as const },
      { id: "c", status: "hypothesis" as const },
      { id: "d", status: "unsupported" as const },
    ];
    const { shown, hidden } = partitionClaims(items);
    expect(shown.map((c) => c.id)).toEqual(["a", "c"]);
    expect(hidden.map((c) => c.id)).toEqual(["b", "d"]);
    expect(hiddenClaimsText(2)).toBe("2 statements hidden: not supported by verified evidence");
    expect(hiddenClaimsText(1)).toBe("1 statement hidden: not supported by verified evidence");
  });

  it("says 'backed by cited evidence', never 'verified' or 'true' (RT21)", () => {
    expect(claimSupportText({ status: "supported" })).toBe("backed by cited evidence");
    expect(claimSupportText({ status: "hypothesis" })).toBe("hypothesis");
    expect(claimSupportText({ status: "unsupported", reason: "weak_anchor" })).toBe(
      "not supported: quote does not support this statement",
    );
    expect(claimSupportText({ status: "unsupported", reason: "quote_too_short" })).toBe(
      "not supported: quote too short to check",
    );
    for (const status of ["supported", "hypothesis"] as const) {
      expect(claimSupportText({ status })).not.toMatch(/\b(verified|true|confirmed)\b/i);
    }
  });

  it("collapses long sections after 10 items", () => {
    const items = Array.from({ length: 40 }, (_, i) => i);
    expect(visibleSlice(items, false)).toHaveLength(10);
    expect(visibleSlice(items, true)).toHaveLength(40);
  });
});

describe("run states", () => {
  it("labels every status and maps every state to a message", () => {
    for (const status of AI_RUN_STATUSES) expect(AI_STATUS_LABELS[status]).toBeTruthy();
    const base = { error_code: null, refusal_category: null, resume_at: null };
    expect(runStateView({ ...base, status: "queued" })?.tone).toBe("active");
    expect(runStateView({ ...base, status: "running" })?.tone).toBe("active");
    expect(runStateView({ ...base, status: "waiting", resume_at: "2026-11-05T10:00:00Z" }, () => "10:00")?.title).toBe(
      "Provider rate-limited, retrying at 10:00",
    );
    expect(runStateView({ ...base, status: "refused", refusal_category: "cyber" })?.title).toBe(
      "The provider declined this request (category: cyber). No retry is made.",
    );
    expect(runStateView({ ...base, status: "failed", error_code: "canary_leak" })?.detail).toMatch(/output is withheld/);
    expect(runStateView({ ...base, status: "completed" })).toBeNull();
  });

  it.each([
    "budget_exhausted",
    "spend_limit",
    "auth_failed",
    "max_tokens",
    "invalid_output",
    "deadline",
    "canary_leak",
    "provider_unavailable",
    "provider_disabled",
    "provider_error",
    "overloaded",
    "context_too_large",
    "ai_disabled",
    "no_digest",
    "not_implemented",
    "refused",
  ])("has a message for %s", (code) => {
    expect(Object.hasOwn(AI_ERROR_TEXT, code)).toBe(true);
    expect(aiErrorText(code)).not.toMatch(/\(/);
  });

  it("names unknown codes verbatim", () => {
    expect(aiErrorText("weird_code")).toBe("The run failed (weird_code).");
  });

  it("polls at 2 s while active, until resume_at while waiting, never when final", () => {
    const now = Date.parse("2026-11-05T10:00:00Z");
    expect(aiPollMs({ status: "running" }, 1, now)).toBe(2000);
    expect(aiPollMs({ status: "queued" }, 5, now)).toBe(2000);
    expect(aiPollMs({ status: "waiting", resume_at: "2026-11-05T10:00:20Z" }, 1, now)).toBe(20_500);
    expect(aiPollMs({ status: "waiting", resume_at: "2026-11-05T11:00:00Z" }, 1, now)).toBe(60_000);
    expect(aiPollMs({ status: "waiting", resume_at: "2026-11-05T09:00:00Z" }, 1, now)).toBe(2000);
    for (const status of ["completed", "partial", "failed", "refused"] as const) {
      expect(aiPollMs({ status }, 1, now)).toBe(false);
    }
    expect(aiPollMs(undefined, 1, now)).toBe(false);
    expect(aiPollMs({ status: "running" }, 200, now)).toBe(15_000);
  });
});

describe("context and output notes", () => {
  it("states truncation and pseudonymization counts", () => {
    const stats = {
      dropped_keys: 0,
      est_tokens: 1200,
      jobs_omitted: 2,
      neutralized: 0,
      omitted: 5,
      per_kind: { finding: { included: 10, total: 15 }, alert: { included: 3, total: 3 } },
      policy_excluded: 0,
      pseudonymized: { ip: 3, host: 1 },
      stripped: {},
      truncated: true,
      truncated_fields: { description: 2 },
    };
    const notes = contextTruncationNotes(stats);
    expect(notes[0]).toContain("10 of 15 finding items");
    expect(notes.join(" ")).toContain("description (2)");
    expect(notes.join(" ")).toContain("2 analysis jobs were left out");
    expect(pseudonymizationText(stats)).toBe("Replaced by pseudonyms before sending: 3 internal IPs, 1 internal hostnames.");
    expect(contextTruncationNotes(null)).toEqual([]);
  });

  it("makes bidi controls visible instead of applying them", () => {
    expect(displayText("abc‮evil")).toBe("abc[U+202E]evil");
    expect(displayText("<b>x</b> [a](javascript:1)")).toBe("<b>x</b> [a](javascript:1)");
  });

  it("formats cost as an approximation", () => {
    expect(formatCost(12_300)).toBe("≈ $0.0123");
    expect(formatCost(1_500_000)).toBe("≈ $1.50");
    expect(formatCost(null)).toBe("—");
  });

  it("carries child flags to the incident parent (RT23) and counts digests", () => {
    const children = [
      { flags: ["verdict_language" as const], status: "completed" as const },
      { flags: ["external_url" as const, "verdict_language" as const], status: "failed" as const },
      { flags: [], status: "running" as const },
    ];
    expect(childFlags(children)).toEqual(["verdict_language", "external_url"]);
    expect(digestProgress(children)).toEqual({ done: 2, total: 3 });
    expect(failedChildren(children)).toHaveLength(1);
  });
});

describe("run targets and lists", () => {
  const run = { scope: "job" as const, job_id: JOB, investigation_id: null, target_kind: null, target_id: null };
  it("links targets internally", () => {
    expect(runTargetHref(ORG, run, "pcap")).toBe(`/o/${ORG}/pcap/${JOB}?tab=ai`);
    expect(runTargetHref(ORG, { ...run, target_kind: "alert", target_id: ROW }, "pcap")).toBe(
      `/o/${ORG}/pcap/${JOB}?tab=alerts&ref=${ROW}`,
    );
    expect(runTargetHref(ORG, { ...run, scope: "investigation", job_id: null, investigation_id: ROW }, null)).toBe(
      `/o/${ORG}/investigations/${ROW}`,
    );
    expect(runTargetHref(ORG, run, null)).toBeNull();
    expect(routeForTask("summarize_pcap")).toBe("pcap");
    expect(routeForTask("explain_static")).toBe("malware");
    expect(routeForTask("ioc_correlation")).toBeNull();
  });

  it("picks the newest run per task and marks superseded runs", () => {
    const runs = [
      { id: "3", task: "summarize_pcap" as const, supersedes_run_id: "1" },
      { id: "2", task: "attack_mapping" as const, supersedes_run_id: null },
      { id: "1", task: "summarize_pcap" as const, supersedes_run_id: null },
    ];
    expect(latestByTask(runs).get("summarize_pcap")?.id).toBe("3");
    expect([...supersededIds(runs)]).toEqual(["1"]);
  });
});

// ---------------------------------------------------------------------------------------------
// Wording and rendering rules over the AI view sources

const FORBIDDEN = /\b(malicious|benign|clean|safe|verdict|harmless)\b/i;
const WEB_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SOURCES = ["lib/ai.ts", "lib/use-ai.ts", "components/ai", "app/(app)/o/[orgId]/ai-analyst"];

function files(entry: string): string[] {
  const full = path.join(WEB_ROOT, entry);
  if (statSync(full).isFile()) return [full];
  return readdirSync(full).flatMap((name) => files(path.join(entry, name)));
}

function withoutComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
}

describe("AI view sources", () => {
  const sources = SOURCES.flatMap(files).filter((f) => /\.(ts|tsx)$/.test(f) && !/\.test\.tsx?$/.test(f));

  it("scans the AI components and pages", () => {
    expect(sources.length).toBeGreaterThanOrEqual(15);
  });

  it.each(sources.map((f) => [path.relative(WEB_ROOT, f), f]))("%s has no verdict words", (_name, file) => {
    const text = withoutComments(readFileSync(file, "utf8"));
    expect(text.match(FORBIDDEN)?.[0] ?? null).toBeNull();
  });

  it.each(sources.map((f) => [path.relative(WEB_ROOT, f), f]))("%s never renders HTML or links model text", (_name, file) => {
    const text = withoutComments(readFileSync(file, "utf8"));
    expect(text).not.toMatch(/dangerouslySetInnerHTML|innerHTML|markdown|<a\s/i);
    // Every href comes from a builder over ids (chip / deep link / target / orgPath / back), never
    // from an output body field (text, quote, rationale, claim, output …).
    for (const match of text.matchAll(/href=\{([^}]*)\}/g)) {
      expect(match[1]).not.toMatch(/\b(text|quote|rationale|claim|output|label|field|step|entry|summary)\b/);
      expect(match[1]).toMatch(/^(chip\.href|target|back|orgPath\(|`\/o\/)/);
    }
  });

  it("keeps fixed texts verdict-free", () => {
    const texts = [
      ...Object.values(AI_ERROR_TEXT),
      ...Object.values(FLAG_TEXT),
      ...Object.values(REASON_TEXT),
      ...Object.values(TASK_LABELS),
      ...Object.values(AI_STATUS_LABELS),
    ];
    for (const text of texts) expect(text).not.toMatch(FORBIDDEN);
  });
});
