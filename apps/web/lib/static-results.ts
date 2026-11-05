/**
 * Pure helpers for the static (malware) analysis views. Everything the analyzer reports is
 * derived from an attacker-controlled sample: parsed defensively, only ever rendered as text.
 */
import type { Schemas } from "@cyberlab/contracts";

import { toolVersions } from "@/lib/analysis";

export type StaticSample = Schemas["SampleOut"];
export type PeFacts = Schemas["PeOut"];
export type ElfFacts = Schemas["ElfOut"];
export type Section = Schemas["SectionOut"];
export type Import = Schemas["ImportOut"];
export type Export = Schemas["ExportOut"];
export type Resource = Schemas["ResourceOut"];
export type SampleString = Schemas["StringOut"];
export type StringEncoding = Schemas["StringEncoding"];
export type Signature = Schemas["SignatureOut"];
export type SignatureEngine = Schemas["SignatureEngine"];
export type Capability = Schemas["CapabilityOut"];
export type StaticReport = Schemas["StaticReport"];

type Json = Record<string, unknown>;

const isRecord = (value: unknown): value is Json =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const finite = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) ? value : null;
const text = (value: unknown): string | null => (typeof value === "string" && value !== "" ? value : null);

// ---------------------------------------------------------------------------------------------
// Tabs

export const STATIC_TABS = [
  ["findings", "Findings"],
  ["signatures", "Signatures"],
  ["capabilities", "Capabilities"],
  ["sections", "Sections"],
  ["imports", "Imports"],
  ["exports", "Exports"],
  ["resources", "Resources"],
  ["strings", "Strings"],
  ["iocs", "IOCs"],
  ["ai", "AI Analyst"],
] as const;

export type StaticTab = (typeof STATIC_TABS)[number][0] | "overview";

// The AV profile runs ClamAV + YARA only: no structure, strings or capa results exist.
const AV_TABS = new Set<string>(["findings", "signatures", "iocs", "ai"]);

/** Static tabs whose list reads `?ref=<row id>` (citation deep links). */
export const STATIC_REF_TABS = new Set<string>(["findings", "signatures", "capabilities", "strings", "imports", "iocs"]);

export function staticTabs(profile: string | null | undefined): (typeof STATIC_TABS)[number][] {
  return profile === "av" ? STATIC_TABS.filter(([value]) => AV_TABS.has(value)) : [...STATIC_TABS];
}

/** The `tab` search param as a tab offered for this profile; anything else is the overview. */
export function parseStaticTab(value: string | null | undefined, profile: string | null | undefined): StaticTab {
  return value && staticTabs(profile).some(([tab]) => tab === value) ? (value as StaticTab) : "overview";
}

// ---------------------------------------------------------------------------------------------
// Entropy (Shannon, bits per byte: 0–8)

/** Same threshold as the analyzer's packer heuristic. */
export const HIGH_ENTROPY = 7.2;
export const ELEVATED_ENTROPY = 6.5;

export type EntropyLevel = "low" | "typical" | "elevated" | "high";

export function entropyLevel(entropy: number): EntropyLevel {
  if (!Number.isFinite(entropy)) return "typical";
  if (entropy > HIGH_ENTROPY) return "high";
  if (entropy >= ELEVATED_ENTROPY) return "elevated";
  if (entropy < 1) return "low";
  return "typical";
}

export const ENTROPY_LABELS: Record<EntropyLevel, string> = {
  low: "very low (padding or empty)",
  typical: "typical of code and data",
  elevated: "elevated (compressed-like)",
  high: "high (packed or encrypted-like)",
};

/** 0–100 for bars and gauges (clamped). */
export function entropyPercent(entropy: number): number {
  if (!Number.isFinite(entropy)) return 0;
  return Math.min(100, Math.max(0, (entropy / 8) * 100));
}

export function formatEntropy(entropy: number | null | undefined): string {
  return entropy === null || entropy === undefined || !Number.isFinite(entropy) ? "—" : entropy.toFixed(2);
}

// ---------------------------------------------------------------------------------------------
// Sections

export function isWritableExecutable(flags: readonly string[]): boolean {
  const set = new Set(flags.map((flag) => flag.toLowerCase()));
  return set.has("write") && set.has("execute");
}

/** Reasons a section deserves a closer look (empty = nothing notable). */
export function sectionWarnings(section: Pick<Section, "flags" | "entropy" | "raw_size" | "virtual_size">): string[] {
  const out: string[] = [];
  if (isWritableExecutable(section.flags)) out.push("writable and executable");
  if (section.entropy > HIGH_ENTROPY) out.push("high entropy");
  if (section.raw_size === 0 && section.virtual_size > 0 && section.flags.includes("execute")) {
    out.push("executable with no raw data");
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Notable imports (mirrors the API report's NOTABLE_APIS: names often worth a closer look,
// common in benign software too; never a verdict)

export const NOTABLE_APIS: Record<string, readonly string[]> = {
  process_injection: [
    "VirtualAllocEx",
    "VirtualProtectEx",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "NtCreateThreadEx",
    "RtlCreateUserThread",
    "QueueUserAPC",
    "NtQueueApcThread",
    "SetThreadContext",
    "NtUnmapViewOfSection",
    "ZwUnmapViewOfSection",
    "NtWriteVirtualMemory",
    "NtMapViewOfSection",
  ],
  anti_analysis: [
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "NtSetInformationThread",
    "OutputDebugString",
  ],
  dynamic_resolution: ["LdrLoadDll", "LdrGetProcedureAddress"],
  input_capture: ["SetWindowsHookEx", "GetAsyncKeyState", "RegisterRawInputDevices"],
  execution: ["WinExec", "ShellExecute", "ShellExecuteEx", "CreateProcessAsUser", "CreateProcessWithLogon"],
  persistence: ["CreateService", "ChangeServiceConfig", "RegSetValueEx", "RegCreateKeyEx"],
  networking: [
    "InternetOpen",
    "InternetOpenUrl",
    "InternetConnect",
    "HttpSendRequest",
    "URLDownloadToFile",
    "WinHttpOpen",
    "WinHttpSendRequest",
    "WSAStartup",
  ],
  cryptography: ["CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContext", "BCryptEncrypt", "BCryptDecrypt"],
  privileges: ["AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue", "ImpersonateLoggedOnUser"],
  credential_access: ["MiniDumpWriteDump", "LsaRetrievePrivateData", "CredEnumerate"],
  discovery: ["CreateToolhelp32Snapshot", "Process32First", "Process32Next", "EnumProcesses"],
};

export const NOTABLE_CATEGORY_LABELS: Record<string, string> = {
  process_injection: "Process injection",
  anti_analysis: "Anti-analysis",
  dynamic_resolution: "Dynamic resolution",
  input_capture: "Input capture",
  execution: "Execution",
  persistence: "Persistence",
  networking: "Networking",
  cryptography: "Cryptography",
  privileges: "Privileges",
  credential_access: "Credential access",
  discovery: "Discovery",
};

// Exact names with the ANSI (A) / wide (W) variants, like the API report.
const NOTABLE_FUNCTIONS = new Map<string, string>(
  Object.entries(NOTABLE_APIS).flatMap(([category, names]) =>
    names.flatMap((name) => ["", "A", "W"].map((suffix) => [`${name}${suffix}`, category] as const)),
  ),
);

/** Category of a notable imported function (exact, case-sensitive like the API), else null. */
export function notableCategory(fn: string | null | undefined): string | null {
  if (!fn) return null;
  return NOTABLE_FUNCTIONS.get(fn) ?? null;
}

export function categoryLabel(category: string): string {
  return Object.hasOwn(NOTABLE_CATEGORY_LABELS, category) ? NOTABLE_CATEGORY_LABELS[category] : category;
}

/** Consecutive imports of the same library (the API orders by library, then function). */
export function groupByLibrary<T extends { library: string }>(items: readonly T[]): { library: string; items: T[] }[] {
  const groups: { library: string; items: T[] }[] = [];
  for (const item of items) {
    const last = groups.at(-1);
    if (last && last.library === item.library) last.items.push(item);
    else groups.push({ library: item.library, items: [item] });
  }
  return groups;
}

// ---------------------------------------------------------------------------------------------
// Filters

/** ATT&CK technique filter as the API accepts it (`T1055` or `T1055.012`); empty = none. */
export function parseAttackFilter(input: string): { attack?: string; invalid: boolean } {
  const value = input.trim().toUpperCase();
  if (!value) return { invalid: false };
  return /^T\d{4}(\.\d{3})?$/.test(value) ? { attack: value, invalid: false } : { invalid: true };
}

export const STRING_ENCODING_LABELS: Record<StringEncoding, string> = {
  ascii: "ASCII",
  utf16le: "UTF-16LE",
  floss_decoded: "FLOSS decoded",
  floss_stack: "FLOSS stack",
  floss_tight: "FLOSS tight",
};

export const SIGNATURE_ENGINE_LABELS: Record<SignatureEngine, string> = { clamav: "ClamAV", yara: "YARA" };

export const STATIC_FINDING_TYPES: [string, string][] = [
  ["av_signature_match", "AV signature match"],
  ["yara_match", "YARA match"],
  ["packer_indicators", "Packer indicators"],
  ["timestamp_anomaly", "Timestamp anomaly"],
  ["tls_callbacks", "TLS callbacks"],
  ["high_entropy_resource", "High-entropy resource"],
  ["overlay", "Overlay"],
  ["api_injection", "API set: injection"],
  ["api_keylogging", "API set: keylogging"],
  ["api_anti_debug", "API set: anti-debugging"],
  ["api_credential_access", "API set: credential access"],
  ["api_persistence", "API set: persistence"],
  ["api_downloader", "API set: downloader"],
  ["capability_injection", "Capability: injection"],
  ["capability_keylogging", "Capability: keylogging"],
  ["capability_credential_access", "Capability: credential access"],
  ["capability_persistence", "Capability: persistence"],
  ["capability_anti_analysis", "Capability: anti-analysis"],
];

/** Finding types that describe the file's structure (packer / anomaly warnings on the overview). */
export const STRUCTURE_FINDING_TYPES = new Set([
  "packer_indicators",
  "timestamp_anomaly",
  "tls_callbacks",
  "high_entropy_resource",
  "overlay",
]);

// ---------------------------------------------------------------------------------------------
// Formatting

/** Address as hex text ("0x401000"). Values above 2^53 may have lost precision in JSON. */
export function hex(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value) || value < 0) return "—";
  return `0x${Math.trunc(value).toString(16)}`;
}

/** A raw PE TimeDateStamp as UTC text (null for 0 / missing: "not set"). */
export function compileTimeText(timestamp: number | null | undefined): string | null {
  if (timestamp === null || timestamp === undefined || !Number.isFinite(timestamp) || timestamp <= 0) return null;
  const date = new Date(timestamp * 1000);
  return Number.isNaN(date.getTime()) ? null : date.toISOString().replace(".000Z", "Z");
}

/** YARA / ClamAV meta as sorted [key, value] text pairs. */
export function metaEntries(meta: Record<string, unknown> | null | undefined): [string, string][] {
  if (!isRecord(meta)) return [];
  return Object.entries(meta)
    .map(([key, value]): [string, string] => [
      key,
      typeof value === "string" ? value : typeof value === "number" || typeof value === "boolean" ? String(value) : "",
    ])
    .sort(([a], [b]) => a.localeCompare(b));
}

// ---------------------------------------------------------------------------------------------
// Engine errors and truncation (header of every static.v1 result)

const ENGINE_ERROR_TEXT: Record<string, string> = {
  av_unavailable: "ClamAV was not available: the file was not scanned for antivirus signatures.",
  av_timeout: "ClamAV did not finish in time: antivirus signature matches may be missing.",
  av_not_fully_scanned:
    "ClamAV could not scan the whole file (size, nesting or archive limits): a missing match is not a clean result.",
  yara_skipped: "YARA was skipped (no time left in the job): rule matches are missing.",
  yara_timeout: "YARA did not finish in time: rule matches may be missing.",
  yara_failed: "YARA failed: rule matches are missing.",
  yara_rule_error: "A YARA rule set could not be loaded: some rule matches may be missing.",
  yara_no_rules: "No YARA rules were available.",
  facts_skipped: "File identification was skipped (no time left): file type and ssdeep are missing.",
  facts_failed: "File identification failed: file type and ssdeep are missing.",
  facts_timeout: "File identification did not finish in time: file type and ssdeep are missing.",
  ssdeep_failed: "The ssdeep fuzzy hash could not be computed.",
  libmagic_failed: "The file type could not be identified (libmagic failed).",
  probe_inconsistent: "The identification probe disagreed with the file's hash; its output was discarded.",
  pe_skipped: "PE parsing was skipped (no time left): header, sections and imports are missing.",
  pe_failed: "PE parsing failed: header, sections and imports are missing.",
  pe_timeout: "PE parsing did not finish in time: structure results may be incomplete.",
  pe_parse_error: "The PE structure is malformed; only part of it could be read.",
  pe_partial: "Parts of the PE structure could not be parsed.",
  elf_skipped: "ELF parsing was skipped (no time left): header, sections and symbols are missing.",
  elf_failed: "ELF parsing failed: header, sections and symbols are missing.",
  elf_timeout: "ELF parsing did not finish in time: structure results may be incomplete.",
  elf_parse_error: "The ELF structure is malformed; only part of it could be read.",
  elf_partial: "Parts of the ELF structure could not be parsed.",
  strings_skipped: "String extraction was skipped (no time left).",
  strings_failed: "String extraction failed.",
  strings_timeout: "String extraction did not finish in time: strings are incomplete.",
  capa_skipped: "capa was skipped (not PE/ELF, over its size cap, or no time left): capabilities are missing.",
  capa_timeout: "capa did not finish in time: capabilities are missing.",
  capa_failed: "capa failed: capabilities are missing.",
  capa_output_too_large: "capa's output exceeded the limit: capabilities are missing.",
  floss_skipped: "FLOSS was skipped (not PE, over its size cap, or no time left): decoded strings are missing.",
  floss_timeout: "FLOSS did not finish in time: decoded strings are missing.",
  floss_failed: "FLOSS failed: decoded strings are missing.",
  floss_output_too_large: "FLOSS output exceeded the limit: decoded strings are missing.",
};

/** Human text for a static `engine_errors` code; unknown codes are shown verbatim (as text). */
export function staticEngineErrorText(code: string): string {
  return Object.hasOwn(ENGINE_ERROR_TEXT, code)
    ? ENGINE_ERROR_TEXT[code]
    : `An analysis engine reported a problem (${code}).`;
}

const TRUNCATION_TEXT: Record<string, string> = {
  sections: "Sections capped: only the first sections were kept.",
  imports: "Imports capped: only the first imports were kept.",
  exports: "Exports capped: only the first exports were kept.",
  resources: "Resources capped: only the first resources were kept.",
  strings: "Strings capped: only the first strings were kept.",
  signature_matches: "Signature matches capped.",
  capabilities: "Capabilities capped.",
  findings: "Findings capped.",
  iocs: "IOCs capped.",
  clamav_limits: "ClamAV scan limits were hit (see the antivirus warning).",
  clamav_output: "ClamAV output was cut at its size limit.",
  capa_output: "capa output exceeded its size limit.",
  capa_skipped_not_pe_or_elf: "capa not run: the file is neither PE nor ELF.",
  capa_skipped_size_cap: "capa not run: the file is over capa's size cap (16 MiB).",
  capa_skipped_time: "capa not run: no time left in the job.",
  floss_skipped_not_pe: "FLOSS not run: the file is not a PE.",
  floss_skipped_size_cap: "FLOSS not run: the file is over FLOSS's size cap (8 MiB).",
  floss_skipped_time: "FLOSS not run: no time left in the job.",
  engine_report: "The engine report itself was capped (too many warnings).",
};

export function staticTruncationText(key: string): string {
  return Object.hasOwn(TRUNCATION_TEXT, key) ? TRUNCATION_TEXT[key] : `Results are partial: ${key} capped.`;
}

// ---------------------------------------------------------------------------------------------
// Tool versions and the AV signature database age

const TOOL_LABELS: Record<string, string> = {
  clamav: "ClamAV",
  clamav_db: "ClamAV DB",
  clamav_db_date: "AV DB date",
  yara: "YARA",
  capa: "capa",
  capa_rules: "capa rules",
  floss: "FLOSS",
  pefile: "pefile",
  pyelftools: "pyelftools",
  ppdeep: "ppdeep",
  python: "Python",
};

export function toolLabel(name: string): string {
  return Object.hasOwn(TOOL_LABELS, name) ? TOOL_LABELS[name] : name;
}

export const AV_DB_MAX_AGE_DAYS = 7;
const DAY_MS = 24 * 3600 * 1000;

export type AvDbAge = { version: string | null; date: string | null; days: number | null; stale: boolean; custom: boolean };

/**
 * Age of the ClamAV signature database at analysis time (`analyzedAtMs`, e.g. the job's start):
 * stale when older than 7 days. A custom test DB has no date. Null when ClamAV did not report.
 */
export function avDbAge(versions: readonly [string, string][], analyzedAtMs: number): AvDbAge | null {
  const map = new Map(versions);
  const version = map.get("clamav_db") ?? null;
  const rawDate = map.get("clamav_db_date") ?? null;
  if (version === null && rawDate === null) return null;
  const custom = Boolean(version?.startsWith("custom:"));
  const parsed = rawDate ? Date.parse(rawDate) : Number.NaN;
  if (Number.isNaN(parsed) || !Number.isFinite(analyzedAtMs)) {
    return { version, date: rawDate, days: null, stale: false, custom };
  }
  const days = Math.max(0, Math.floor((analyzedAtMs - parsed) / DAY_MS));
  return { version, date: new Date(parsed).toISOString().slice(0, 10), days, stale: days > AV_DB_MAX_AGE_DAYS, custom };
}

// ---------------------------------------------------------------------------------------------
// Job summary (analysis_jobs.summary written by the static ingest)

export type StaticCountRow = { key: string; label: string; stored: number };

export type StaticSummary = {
  profile: string | null;
  fileFormat: string | null;
  fileType: string | null;
  mime: string | null;
  entropy: number | null;
  counts: Record<string, number>;
  countRows: StaticCountRow[];
  engineErrors: string[];
  truncated: string[];
  toolVersions: [string, string][];
};

const COUNT_KINDS: [string, string][] = [
  ["findings", "Findings"],
  ["signatures", "Signature matches"],
  ["capabilities", "Capabilities"],
  ["sections", "Sections"],
  ["imports", "Imports"],
  ["exports", "Exports"],
  ["resources", "Resources"],
  ["strings", "Strings"],
  ["iocs", "IOCs"],
];

export function parseStaticSummary(summary: unknown): StaticSummary {
  const s = isRecord(summary) ? summary : {};
  const sample = isRecord(s.sample) ? s.sample : {};
  const counts: Record<string, number> = {};
  if (isRecord(s.counts)) {
    for (const [key, value] of Object.entries(s.counts)) {
      const n = finite(value);
      if (n !== null) counts[key] = n;
    }
  }
  return {
    profile: text(s.profile),
    fileFormat: text(s.file_format),
    fileType: text(sample.file_type),
    mime: text(sample.mime),
    entropy: finite(sample.entropy),
    counts,
    countRows: COUNT_KINDS.filter(([key]) => key in counts).map(([key, label]) => ({ key, label, stored: counts[key] })),
    engineErrors: Array.isArray(s.engine_errors)
      ? s.engine_errors.filter((code): code is string => typeof code === "string" && code !== "")
      : [],
    truncated: isRecord(s.truncated)
      ? Object.entries(s.truncated)
          .filter(([, flag]) => flag === true)
          .map(([key]) => key)
      : [],
    toolVersions: toolVersions(s),
  };
}

// ---------------------------------------------------------------------------------------------
// Report download

const FALLBACK_NAME = "static-report.json";

/**
 * File name from a Content-Disposition header (RFC 5987 `filename*` preferred), reduced to a
 * safe basename that always ends in `.json`.
 */
export function reportFilename(disposition: string | null | undefined): string {
  if (!disposition) return FALLBACK_NAME;
  let name: string | null = null;
  const extended = /filename\*\s*=\s*([^']*)'[^']*'([^;]+)/i.exec(disposition);
  if (extended) {
    try {
      name = decodeURIComponent(extended[2].trim());
    } catch {
      name = null;
    }
  }
  if (!name) {
    const plain = /filename\s*=\s*("([^"]*)"|[^;]+)/i.exec(disposition);
    name = plain ? (plain[2] ?? plain[1]).trim() : null;
  }
  if (!name) return FALLBACK_NAME;
  const safe = name.replace(/[\u0000-\u001f\u007f/\\:*?"<>|]+/g, "_").replace(/^\.+/, "").slice(0, 200);
  if (!safe) return FALLBACK_NAME;
  return safe.toLowerCase().endsWith(".json") ? safe : `${safe}.json`;
}
