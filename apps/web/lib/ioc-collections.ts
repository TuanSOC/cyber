/**
 * Case-wide IOCs and IOC collections (M6). IOC values are attacker-controlled: they are shown
 * defanged by default, as text, never as links. The client-side shape checks only help the
 * analyst; the server normalizes and validates every value (`invalid` per item).
 */
import type { Schemas } from "@cyberlab/contracts";

import type { ProviderName } from "@/lib/ti";

export type CaseIoc = Schemas["CaseIocOut"];
export type CaseIocPage = Schemas["CaseIocPage"];
export type IocCollection = Schemas["IocCollectionOut"];
export type IocCollectionDetail = Schemas["IocCollectionDetail"];
export type IocCollectionItem = Schemas["IocCollectionItemOut"];
export type IocItemManual = Schemas["IocItemManual"];
export type IocItemsAddResult = Schemas["IocItemsAddResult"];
export type IocItemResult = Schemas["IocItemResult"];
export type TiSummary = Schemas["TiSummaryOut"];
export type ManualIocType = Schemas["TiIocType"];

export const COLLECTION_NAME_MAX = 120;
export const COLLECTION_DESCRIPTION_MAX = 2_000;
export const ITEM_NOTE_MAX = 500;
export const MAX_ITEMS_PER_ADD = 500;
const VALUE_MAX = 2_048;

// ---------------------------------------------------------------------------------------------
// Defang (display only)

/**
 * Display form that cannot be clicked or pasted as a live indicator: `hxxp(s)`, `[.]` for dots
 * in hosts and addresses, `[@]` in emails, `[:]//` after the scheme. Hashes are unchanged.
 */
export function defang(value: string, type?: string): string {
  if (/^(md5|sha1|sha256|file_md5|file_sha1|file_sha256|ja3s?|cert_sha256)$/.test(type ?? "")) return value;
  let out = value.replace(/^(h)(tt)(p(?:s)?)(:\/\/)/i, (_m, h: string, _tt: string, rest: string) => `${h}xx${rest}[:]//`);
  out = out.replace(/^(ftp)(s?)(:\/\/)/i, (_m, _f: string, s: string) => `fxp${s}[:]//`);
  if (type === "email" || (!type && /^[^@\s]+@[^@\s]+$/.test(out))) out = out.replace("@", "[@]");
  if (type === "ipv6" || (type === "ip" && out.includes(":"))) return out.replace(/:/g, "[:]");
  return out.replace(/\./g, "[.]");
}

/** The value as shown: defanged unless the user revealed it. */
export function iocDisplay(value: string, type: string, reveal: boolean): string {
  return reveal ? value : defang(value, type);
}

// ---------------------------------------------------------------------------------------------
// Manual add: client-side shape checks (the server stays authoritative)

export const MANUAL_TYPES: readonly ManualIocType[] = ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email"];

const SHAPES: Record<ManualIocType, RegExp> = {
  ipv4: /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/,
  ipv6: /^[0-9a-f:.]+$/i,
  domain: /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/i,
  url: /^(https?|ftp):\/\/[^\s/?#]+[^\s]*$/i,
  md5: /^[0-9a-f]{32}$/i,
  sha1: /^[0-9a-f]{40}$/i,
  sha256: /^[0-9a-f]{64}$/i,
  email: /^[^@\s]+@[^@\s]+\.[^@\s]+$/,
};

/** Undo common defanging before the check and the request (the server refangs too). */
export function refangInput(value: string): string {
  return value
    .trim()
    .replace(/^hxxp(s?)(\[:\]|:)\/\//i, (_m, s: string) => `http${s}://`)
    .replace(/^fxp(s?)(\[:\]|:)\/\//i, (_m, s: string) => `ftp${s}://`)
    .replace(/\[\.\]|\(\.\)|\[dot\]/gi, ".")
    .replace(/\[@\]|\[at\]/gi, "@")
    .replace(/\[:\]/g, ":");
}

/** Null when the value looks like the type, else a short reason. */
export function checkManualIoc(type: ManualIocType, raw: string): string | null {
  const value = refangInput(raw);
  if (!value) return "Enter a value.";
  if (value.length > VALUE_MAX) return `At most ${VALUE_MAX} characters.`;
  if (/\s/.test(value)) return "No spaces inside a value.";
  if (type === "ipv6" && (!value.includes(":") || value.split("::").length > 2)) return "Not an IPv6 address.";
  if (!SHAPES[type].test(value)) return `This does not look like a ${type} value.`;
  return null;
}

/** Job IOC type → the collection (TI) type, picking IPv4 / IPv6 by shape; null when not addable manually. */
export function manualTypeFor(type: string, value: string): ManualIocType | null {
  switch (type) {
    case "ip":
      return value.includes(":") ? "ipv6" : "ipv4";
    case "file_md5":
      return "md5";
    case "file_sha1":
      return "sha1";
    case "file_sha256":
      return "sha256";
    default:
      return (MANUAL_TYPES as readonly string[]).includes(type) ? (type as ManualIocType) : null;
  }
}

/**
 * The case IOCs selected for "Add to collection", as manual items. The case list carries no
 * job IOC row id, so the values are added by type and value (normalized by the server).
 */
export function selectionToItems(iocs: readonly Pick<CaseIoc, "ioc_type" | "value">[]): {
  items: IocItemManual[];
  skipped: number;
} {
  const items: IocItemManual[] = [];
  let skipped = 0;
  for (const ioc of iocs) {
    const type = manualTypeFor(ioc.ioc_type, ioc.value);
    if (type) items.push({ type, value: ioc.value });
    else skipped += 1;
  }
  return { items: items.slice(0, MAX_ITEMS_PER_ADD), skipped: skipped + Math.max(0, items.length - MAX_ITEMS_PER_ADD) };
}

// ---------------------------------------------------------------------------------------------
// Add results

const INVALID_TEXT: Record<string, string> = {
  invalid: "not a valid indicator",
  invalid_ioc: "not a valid indicator",
  out_of_scope: "not part of this case",
  ref_out_of_scope: "not part of this case",
  unsupported_type: "unsupported type",
  too_long: "too long",
};

export function itemOutcomeText(result: Pick<IocItemResult, "outcome" | "reason">): string {
  if (result.outcome === "added") return "added";
  if (result.outcome === "duplicate") return "already in the collection";
  const reason = result.reason ?? "";
  return `invalid: ${Object.hasOwn(INVALID_TEXT, reason) ? INVALID_TEXT[reason] : reason || "rejected"}`;
}

export function addSummary(result: Pick<IocItemsAddResult, "added" | "duplicates" | "invalid">): string {
  return `${result.added} added, ${result.duplicates} already present, ${result.invalid} invalid`;
}

// ---------------------------------------------------------------------------------------------
// Exports

export type ExportFormat = "csv" | "json" | "stix21";

export const EXPORT_FORMATS: readonly [ExportFormat, string][] = [
  ["csv", "CSV"],
  ["json", "JSON"],
  ["stix21", "STIX 2.1 bundle"],
];

/** Query of an export: clear-text (`defang=false`) only for `evidence.write` holders. */
export function exportQuery(format: ExportFormat, clearText: boolean, canWrite: boolean): { format: ExportFormat; defang: boolean } {
  return { format, defang: !(clearText && canWrite) };
}

export function exportFallbackName(collectionName: string, format: ExportFormat): string {
  const base = collectionName.replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^[._]+/, "").slice(0, 60) || "collection";
  return `${base}.${format === "stix21" ? "stix.json" : format}`;
}

// ---------------------------------------------------------------------------------------------
// TI chips (the M4 attributed chip)

/** A collection item's TI summary in the shape of the M4 `ProviderChip`. */
export function tiChipSource(t: TiSummary) {
  return {
    provider: t.provider as ProviderName,
    status: t.status as Schemas["ResultStatus"],
    found: t.found,
    score: t.score,
    score_scale: t.score_scale,
    detections: null,
    stale: false,
    fetched_at: t.fetched_at,
  };
}
