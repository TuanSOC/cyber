import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  type IocEnrichment,
  type ProviderName,
  PROVIDERS,
  attributedText,
  chipText,
  chipTitle,
  itemReasonText,
  runOutcomeNotes,
  skipReasonText,
  summaryFields,
  verifyErrorText,
} from "@/lib/ti";

/*
 * Wording rule (plan "Presentation", RT20): TI UI text never labels an indicator as malicious,
 * benign, clean or safe, and never speaks of a verdict. VirusTotal's category name appears only
 * inside the one attributed template "N engines: M report malicious" (`vtEnginesText`).
 */

const FORBIDDEN = /\b(malicious|benign|clean|safe|verdict)\b/i;
const ALLOWED_TEMPLATE = /report malicious/g;

const WEB_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SOURCES = [
  "lib/ti.ts",
  "lib/use-ti.ts",
  "components/ti",
  "components/analysis/iocs-tab.tsx",
  "app/(app)/o/[orgId]/intel",
  "app/(app)/o/[orgId]/settings/integrations",
];

function files(entry: string): string[] {
  const full = path.join(WEB_ROOT, entry);
  if (statSync(full).isFile()) return [full];
  return readdirSync(full).flatMap((name) => files(path.join(entry, name)));
}

/** Source without comments, provider field accesses (`d.malicious`) and the allowed template. */
function userFacing(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:"'`])\/\/.*$/gm, "$1")
    .replace(/\.(malicious|suspicious|harmless|undetected)\b/g, "")
    .replace(ALLOWED_TEMPLATE, "");
}

describe("threat intel wording", () => {
  const sources = SOURCES.flatMap(files).filter((f) => /\.(ts|tsx)$/.test(f) && !/\.test\.tsx?$/.test(f));

  it("scans the TI components and pages", () => {
    expect(sources.length).toBeGreaterThanOrEqual(10);
  });

  it.each(sources.map((f) => [path.relative(WEB_ROOT, f), f]))("%s has no verdict words", (_name, file) => {
    const text = userFacing(readFileSync(file, "utf8"));
    const match = text.match(FORBIDDEN);
    expect(match?.[0] ?? null, `forbidden word in ${file}`).toBeNull();
  });

  const at = "2026-11-05T10:00:00Z";
  const base = (provider: ProviderName, over: Partial<IocEnrichment> = {}): IocEnrichment => ({
    provider,
    status: "ok",
    found: true,
    score: 87,
    score_scale: null,
    detections: { malicious: 12, suspicious: 2, total: 71 },
    tags: [],
    families: [],
    attack_ids: [],
    fetched_at: at,
    expires_at: null,
    stale: true,
    permalink: null,
    result_id: "00000000-0000-0000-0000-000000000001",
    ...over,
  });

  it("keeps chip and attributed templates verdict-free", () => {
    const statuses: IocEnrichment["status"][] = ["ok", "not_found", "error", "auth_failed"];
    const texts = PROVIDERS.flatMap((p) =>
      statuses.flatMap((status) => {
        const e = base(p, { status, found: status === "ok" });
        return [chipText(e), chipTitle(e), attributedText(e)];
      }),
    );
    for (const text of texts) {
      expect(text.replace(ALLOWED_TEMPLATE, "")).not.toMatch(FORBIDDEN);
      expect(text).not.toMatch(/\bmalicious\b(?<!report malicious)/);
    }
    // Every chip title names its source.
    for (const p of PROVIDERS) expect(chipTitle(base(p))).toMatch(/^Reported by /);
  });

  it("keeps generated labels and notes verdict-free", () => {
    const texts = [
      ...["not_global_ip", "special_use_name", "excluded_suffix", "unsupported_type", "invalid"].map(skipReasonText),
      ...["rate_limited", "quota_exhausted", "deadline", "auth_failed"].map(itemReasonText),
      ...["auth", "timeout", "misp_url_not_public", "bad_json"].map(verifyErrorText),
      ...runOutcomeNotes({ status: "partial", summary: { providers: { virustotal: { abandoned_deadline: 1, error: 1 } } } }),
      ...summaryFields({
        provider: "virustotal",
        tags: ["t"],
        reputation: -5,
        total_votes: { malicious: 3, harmless: 1 },
        last_analysis_stats: { malicious: 1, suspicious: 0, harmless: 1, undetected: 1, timeout: 0 },
      }).flatMap((f) => [f.label, f.text ?? ""]),
    ];
    for (const text of texts) expect((text ?? "").replace(ALLOWED_TEMPLATE, "")).not.toMatch(FORBIDDEN);
  });
});
