/**
 * ATT&CK case mapping (M6): analyst-confirmed techniques with suggestions from capa, findings
 * and verified AI citations. Statuses are styled neutrally (no verdict colours); rationale is
 * plain text. Source links are internal only.
 */
import type { Schemas } from "@cyberlab/contracts";

import { type JobRoute, deepLinkHref, isUuid } from "@/lib/ai";

export type CaseAttack = Schemas["CaseAttackOut"];
export type AttackMapping = Schemas["AttackMappingOut"];
export type AttackMappingCreate = Schemas["AttackMappingCreate"];
export type AttackMappingUpdate = Schemas["AttackMappingUpdate"];
export type AttackSuggestion = Schemas["AttackSuggestion"];
export type AttackSuggestions = Schemas["AttackSuggestionsOut"];
export type SourceDescriptor = Schemas["SourceDescriptor"];
export type AttackSourceRef = Schemas["AttackSourceRef"];
export type MappingStatus = AttackMapping["status"];
export type MatrixTactic = Schemas["MatrixTactic"];

export const RATIONALE_MAX = 2_000;
export const MAX_SOURCES = 32;

export const MAPPING_STATUSES: readonly MappingStatus[] = ["confirmed", "suspected", "rejected"];

export const MAPPING_STATUS_LABELS: Record<MappingStatus, string> = {
  confirmed: "Confirmed",
  suspected: "Suspected",
  rejected: "Rejected",
};

export const SOURCE_KIND_LABELS: Record<SourceDescriptor["kind"], string> = {
  capability: "capa capability",
  finding: "finding",
  ai_run: "AI — verified citation",
};

const TECHNIQUE = /^T\d{4}(\.\d{3})?$/;

/** Upper-cased, trimmed id when it has the ATT&CK shape (T1234 or T1234.001), else null. */
export function parseTechniqueId(input: string): string | null {
  const id = input.trim().toUpperCase();
  return TECHNIQUE.test(id) ? id : null;
}

/** Ids from a comma / space separated input (deduplicated, valid shapes only, at most 20). */
export function parseTechniqueIds(input: string): { ids: string[]; invalid: string[] } {
  const ids: string[] = [];
  const invalid: string[] = [];
  for (const part of input.split(/[\s,;]+/).filter(Boolean)) {
    const id = parseTechniqueId(part);
    if (id) {
      if (!ids.includes(id)) ids.push(id);
    } else invalid.push(part);
  }
  return { ids: ids.slice(0, 20), invalid };
}

const SAFE_PATH = /^\/o\/[0-9a-f-]{36}\/[A-Za-z0-9/_-]*(\?[A-Za-z0-9=&_.%-]*)?$/;

/**
 * Internal link of a mapping source: the server's `path` when it is an internal path of this
 * org (no scheme, host, `..` or `//`), else built from the kind; null when unknown.
 */
export function sourceHref(orgId: string, source: SourceDescriptor, routes: ReadonlyMap<string, JobRoute>): string | null {
  if (!isUuid(orgId)) return null;
  const prefix = `/o/${orgId}/`;
  if (source.path && source.path.startsWith(prefix) && SAFE_PATH.test(source.path) && !source.path.includes("..")) {
    return source.path;
  }
  if (source.kind === "ai_run") {
    return isUuid(source.run_id) ? `/o/${encodeURIComponent(orgId)}/ai-analyst/${encodeURIComponent(source.run_id)}` : null;
  }
  if (!source.job_id) return null;
  if (source.kind === "capability") {
    return deepLinkHref(orgId, { route: "malware", job_id: source.job_id, tab: "capabilities", ref: source.ref_id });
  }
  const route = routes.get(source.job_id);
  return route ? deepLinkHref(orgId, { route, job_id: source.job_id, tab: "findings", ref: source.ref_id }) : null;
}

/** The sources of a suggestion as the create body expects them. */
export function toSourceRefs(sources: readonly SourceDescriptor[]): AttackSourceRef[] {
  return sources.slice(0, MAX_SOURCES).map((s) => ({
    kind: s.kind,
    ref_id: s.ref_id,
    job_id: s.job_id ?? null,
    run_id: s.run_id ?? null,
  }));
}

/** Technique label "T1055 · Process Injection" (id only when the index has no name). */
export function techniqueText(label: Pick<Schemas["TechniqueLabel"], "technique_id" | "name">): string {
  return label.name ? `${label.technique_id} · ${label.name}` : label.technique_id;
}

/** "revoked" / "deprecated" note of a label, if any. */
export function techniqueWarning(label: Pick<Schemas["TechniqueLabel"], "revoked" | "deprecated">): string | null {
  if (label.revoked) return "revoked in the current ATT&CK version";
  if (label.deprecated) return "deprecated in the current ATT&CK version";
  return null;
}

/** Only an https MITRE page is linked. */
export function mitreHref(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" && parsed.hostname === "attack.mitre.org" ? parsed.toString() : null;
  } catch {
    return null;
  }
}

/** Tactic heading from the matrix value ("defense-evasion" → "Defense Evasion"). */
export function tacticLabel(tactic: string): string {
  return tactic
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((w) => (w === "and" || w === "of" ? w : w[0].toUpperCase() + w.slice(1)))
    .join(" ");
}
