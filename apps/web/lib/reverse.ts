/**
 * Pure helpers and read-model types of the Reverse Engineering pages (M10 phase 10).
 *
 * The types mirror `apps/api/app/modules/reverse_engineering/schemas.py` (frozen in phase 1).
 * They are written by hand here because the contracts package is regenerated later, in Docker
 * (`node scripts/gen-contracts.mjs`); once it is, they can become `Schemas["…"]` aliases.
 *
 * Addresses arrive as `0x…` text (the API never sends a JSON number above 2**53): they are
 * compared and formatted with `BigInt`, never `Number`. Names, signatures, strings and code
 * are attacker-influenced text, rendered as React text only.
 */
import { analysisErrorText } from "@/lib/analysis";
import { ApiError, errorMessage } from "@/lib/api";
import { apiErrorText } from "@/lib/http-errors";

// ---------------------------------------------------------------------------------------------
// Read-model types (schemas.py)

export type HexAddress = string;
export type ReProfileName = "quick" | "full";
export type ReEngine = "ghidra" | "radare2" | "replay";
export type CodeKind = "pseudo_c" | "disasm";
export type ReStage = "analyze" | "decompile" | "r2";
export type StageState = "ok" | "timeout" | "failed" | "skipped";
export type NameSource = "export" | "import" | "symbol" | "debug" | "fid_library" | "generated";
export type DecompileStatus = "ok" | "timeout" | "failed" | "truncated" | "skipped_budget";
export type FunctionDecompileState = DecompileStatus | "not_selected";
export type PriorityReason = "requested" | "entry_or_export" | "capability" | "suspicious_import" | "ioc_string" | "size";

export type ReStageOut = {
  stage: ReStage;
  status: StageState;
  duration_ms: number;
  error_code?: string | null;
  truncated: boolean;
  peak_memory_bytes?: number | null;
};

export type ReSummary = {
  job_id: string;
  evidence_id: string;
  source_job_id: string;
  profile: ReProfileName;
  engine: ReEngine;
  engine_version?: string | null;
  code_kind: CodeKind;
  format: "pe" | "elf";
  arch: "x86" | "x86_64" | "other";
  machine?: string | null;
  bits: number;
  endianness: "little" | "big";
  language_id?: string | null;
  compiler_spec?: string | null;
  image_base: HexAddress;
  preferred_base: HexAddress;
  entry?: HexAddress | null;
  analysis_status: "complete" | "timeout" | "failed" | "not_run";
  peak_memory_bytes?: number | null;
  stages: ReStageOut[];
  counts: Record<string, number>;
  truncated: Record<string, boolean>;
  tool_versions: Record<string, string>;
  decompile_addresses: HexAddress[];
  newer_job_id?: string | null;
};

export type FunctionRef = { entry: HexAddress; name: string };

export type ReFunction = {
  id: string;
  entry: HexAddress;
  rva: HexAddress;
  name: string;
  name_source: NameSource;
  size: number;
  is_thunk: boolean;
  is_external: boolean;
  is_library: boolean;
  signature: string | null;
  calling_convention: string | null;
  instructions: number;
  callers: number;
  callees: number;
  decompile_status: FunctionDecompileState;
  priority_rank: number | null;
  priority_reason?: PriorityReason | null;
  capabilities: number;
};

export type Page<T> = { items: T[]; total: number };

export type LinkedCapability = {
  capability_id: string;
  static_job_id: string;
  name: string;
  namespace: string | null;
  attack: string[];
  file_va: HexAddress;
};

export type DecompilationMeta = {
  status: DecompileStatus;
  code_kind: CodeKind;
  lines: number;
  code_sha256: string | null;
  truncated_bytes: number;
  duration_ms: number;
};

export type ReImport = {
  id: string;
  library: string;
  name: string | null;
  ordinal: number | null;
  address: HexAddress | null;
  function_count: number;
  functions: FunctionRef[];
};

export type ReString = {
  id: string;
  address: HexAddress;
  encoding: "ascii" | "utf8" | "utf16le" | "utf16be" | "utf32";
  value: string;
  length: number;
  function_count: number;
  functions: FunctionRef[];
};

export type FunctionDetail = {
  function: ReFunction;
  body: { start: HexAddress; end: HexAddress }[];
  body_truncated: boolean;
  callers: FunctionRef[];
  callees: FunctionRef[];
  imports: ReImport[];
  strings: ReString[];
  capabilities: LinkedCapability[];
  finding_ids: string[];
  decompilation: DecompilationMeta | null;
};

export type FunctionCode = {
  entry: HexAddress;
  name: string;
  status: DecompileStatus;
  code_kind: CodeKind;
  code: string | null;
  lines: number;
  code_sha256: string | null;
  truncated_bytes: number;
};

export type CapabilityFunctions = {
  locations: HexAddress[];
  re_job_id: string | null;
  functions: { re_job_id: string; function: FunctionRef; file_va: HexAddress }[];
  unlocated: number;
};

// ---------------------------------------------------------------------------------------------
// Addresses (BigInt only)

const HEX = /^0x[0-9a-f]{1,16}$/i;
const DECIMAL = /^[0-9]{1,20}$/;
const U64_MAX = (BigInt(1) << BigInt(64)) - BigInt(1);

/** An unsigned 64-bit address from `0x…` or decimal text; null when invalid or out of range. */
export function parseAddress(value: string | null | undefined): bigint | null {
  if (typeof value !== "string") return null;
  const text = value.trim();
  if (!HEX.test(text) && !DECIMAL.test(text)) return null;
  const n = BigInt(text);
  return n >= BigInt(0) && n <= U64_MAX ? n : null;
}

/** `0x…` lowercase hex of an address (text in, text out; "—" when invalid). */
export function formatAddress(value: string | null | undefined): string {
  const n = parseAddress(value);
  return n === null ? "—" : `0x${n.toString(16)}`;
}

/** Address order for client-side sorting (invalid addresses last). */
export function compareAddress(a: string | null | undefined, b: string | null | undefined): number {
  const x = parseAddress(a);
  const y = parseAddress(b);
  if (x === null || y === null) return x === null ? (y === null ? 0 : 1) : -1;
  return x < y ? -1 : x > y ? 1 : 0;
}

// ---------------------------------------------------------------------------------------------
// Tabs and deep links (`?tab=…&fn=<entry>`)

export type ReTab = "overview" | "functions" | "imports" | "strings" | "findings" | "iocs";
export type FunctionTab = "facts" | "code";

export const RE_TABS: readonly [Exclude<ReTab, "overview">, string][] = [
  ["functions", "Functions"],
  ["imports", "Imports"],
  ["strings", "Strings"],
  ["findings", "Findings"],
  ["iocs", "IOCs"],
];
/** Tabs a cited row (`?ref=<row id>`) narrows to that row. */
export const RE_REF_TABS: ReadonlySet<ReTab> = new Set(["functions", "imports", "strings", "findings", "iocs"]);

/**
 * The page's state from its query: `tab` (a function tab `facts` / `code` opens the Functions
 * tab with that function), `fn` (a function entry) and `ref` (a cited row id).
 */
export function parseReLocation(params: { get(name: string): string | null }): {
  tab: ReTab;
  fn: string | null;
  functionTab: FunctionTab;
  ref: string | null;
} {
  const raw = params.get("tab");
  const fnRaw = params.get("fn");
  const fn = parseAddress(fnRaw) === null ? null : formatAddress(fnRaw);
  const functionTab: FunctionTab = raw === "code" ? "code" : "facts";
  let tab: ReTab = "overview";
  if (raw === "facts" || raw === "code" || fn !== null) tab = "functions";
  else if (RE_TABS.some(([value]) => value === raw)) tab = raw as ReTab;
  return { tab, fn, functionTab, ref: params.get("ref") };
}

/** Internal link to one function of an RE job (ids and hex only, never model or binary text). */
export function functionHref(orgPrefix: string, jobId: string, entry: string, tab: FunctionTab = "facts"): string | null {
  const address = parseAddress(entry);
  if (address === null || !/^[0-9a-f-]{36}$/i.test(jobId)) return null;
  return `${orgPrefix}/reverse-engineering/${encodeURIComponent(jobId)}?tab=${tab}&fn=0x${address.toString(16)}`;
}

// ---------------------------------------------------------------------------------------------
// Labels and wording

export const STAGE_LABELS: Record<ReStage, string> = {
  analyze: "Analysis",
  decompile: "Decompilation",
  r2: "radare2",
};

export const STAGE_STATE_LABELS: Record<StageState, string> = {
  ok: "OK",
  timeout: "Timed out",
  failed: "Failed",
  skipped: "Skipped",
};

export const ENGINE_LABELS: Record<ReEngine, string> = {
  ghidra: "Ghidra",
  radare2: "radare2",
  replay: "Replay (test data, not a real analysis)",
};

export const NAME_SOURCE_LABELS: Record<NameSource, string> = {
  export: "export (named by the binary)",
  import: "import",
  symbol: "symbol table",
  debug: "debug information",
  fid_library: "library signature (named by the engine)",
  generated: "generated (named by the engine)",
};

export const DECOMPILE_LABELS: Record<FunctionDecompileState, string> = {
  ok: "Decompiled",
  truncated: "Decompiled (truncated)",
  timeout: "Timed out",
  failed: "Failed",
  skipped_budget: "Not decompiled (budget)",
  not_selected: "Not decompiled",
};

export const PRIORITY_REASON_TEXT: Record<PriorityReason, string> = {
  requested: "it was requested (Decompile this function)",
  entry_or_export: "it is the entry point or an export",
  capability: "a capa capability is located in it",
  suspicious_import: "it calls an import of a suspicious API set",
  ioc_string: "it references a string that yields an indicator",
  size: "of its size (the remaining budget goes to the largest functions)",
};

/** "Why (not) decompiled": one plain sentence from the stored rank and status. */
export function decompileReason(fn: Pick<ReFunction, "decompile_status" | "priority_reason" | "is_thunk" | "is_external" | "is_library">, profile: ReProfileName): string {
  if (profile === "quick") return "The quick profile (radare2) never decompiles: run a full analysis.";
  const why = fn.priority_reason ? PRIORITY_REASON_TEXT[fn.priority_reason] : null;
  switch (fn.decompile_status) {
    case "ok":
    case "truncated":
      return why ? `Decompiled because ${why}.` : "Decompiled.";
    case "timeout":
      return "Selected, but the decompiler ran out of time for this function.";
    case "failed":
      return "Selected, but the decompiler failed on this function.";
    case "skipped_budget":
      return "Selected, but the decompile budget (functions or total size) ran out before it.";
    default:
      if (fn.is_thunk || fn.is_external) return "Not decompiled: thunks and external functions are skipped.";
      if (fn.is_library) return "Not decompiled: recognized library functions are skipped.";
      return 'Not decompiled: it was not on the priority list. "Decompile this function" runs a new analysis with it first.';
  }
}

/** The thunk / external / library flags of one function. */
export function functionFlags(fn: Pick<ReFunction, "is_thunk" | "is_external" | "is_library">): string[] {
  const flags: string[] = [];
  if (fn.is_thunk) flags.push("thunk");
  if (fn.is_external) flags.push("external");
  if (fn.is_library) flags.push("library");
  return flags;
}

export const SYNTHETIC_METRICS_NOTE =
  "Function recovery and decompilation quality were measured on synthetic benign programs only; real samples (packed, obfuscated or unusual compilers) recover fewer functions.";
export const NEVER_EXECUTED =
  "The program is never executed: Ghidra (or radare2) only reads the file, offline, in an isolated worker with no network.";
export const RUN_COST =
  "A full analysis loads the whole program into Ghidra and decompiles the most relevant functions: it takes minutes (up to an hour for large programs) and uses one of the platform's heavy-analysis slots.";
export const DECOMPILE_CONFIRM =
  "This re-analyses the whole sample (minutes) with this function decompiled first, and creates a new reverse-engineering job. This job's results stay as they are.";

// ---------------------------------------------------------------------------------------------
// Function list filters (server-side) and client sort

export type FunctionFilters = {
  q: string;
  decompiled: boolean | null;
  hasCapability: boolean;
  callsSuspiciousImport: boolean;
  referencesIocString: boolean;
  includeLibrary: boolean;
};

export const EMPTY_FILTERS: FunctionFilters = {
  q: "",
  decompiled: null,
  hasCapability: false,
  callsSuspiciousImport: false,
  referencesIocString: false,
  includeLibrary: false,
};

/** The query of `GET …/reverse/functions` (only set filters are sent). */
export function functionQuery(f: FunctionFilters): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  const q = f.q.trim();
  if (q.length >= 1) out.q = q.slice(0, 128);
  if (f.decompiled !== null) out.decompiled = f.decompiled;
  if (f.hasCapability) out.has_capability = true;
  if (f.callsSuspiciousImport) out.calls_suspicious_import = true;
  if (f.referencesIocString) out.references_ioc_string = true;
  if (f.includeLibrary) out.include_library = true;
  return out;
}

export type FunctionSort = "rank" | "entry" | "size" | "name";
export const FUNCTION_SORT_LABELS: Record<FunctionSort, string> = {
  rank: "Priority",
  entry: "Address",
  size: "Size",
  name: "Name",
};

/** Sorts loaded rows (the API pages by priority rank, then entry). */
export function sortFunctions(rows: readonly ReFunction[], sort: FunctionSort): ReFunction[] {
  const copy = [...rows];
  const byEntry = (a: ReFunction, b: ReFunction) => compareAddress(a.entry, b.entry);
  switch (sort) {
    case "entry":
      return copy.sort(byEntry);
    case "size":
      return copy.sort((a, b) => b.size - a.size || byEntry(a, b));
    case "name":
      return copy.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : byEntry(a, b)));
    default:
      return copy.sort((a, b) => (a.priority_rank ?? Infinity) - (b.priority_rank ?? Infinity) || byEntry(a, b));
  }
}

// ---------------------------------------------------------------------------------------------
// Runs

/** A static job the "Reverse engineer" action is offered for: succeeded, full, PE / ELF. */
export function reOffered(job: { analyzer: string; status: string; profile?: string | null; summary?: unknown }): boolean {
  if (job.analyzer !== "static" || job.status !== "succeeded" || job.profile !== "full") return false;
  const summary = job.summary && typeof job.summary === "object" ? (job.summary as Record<string, unknown>) : {};
  const format = summary.file_format;
  return format === "pe" || format === "elf";
}

export const HEAVY_BUSY =
  "Another memory, disk or reverse-engineering analysis is running on this platform. Try again when it finishes.";

/** Plain text for a refused RE request (RT2: no queue position, there is no queue). */
export function reRunErrorText(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.code === "too_many_active_jobs" && error.extraString("reason") === "heavy_analysis_busy") return HEAVY_BUSY;
    const shared = apiErrorText(error);
    if (shared) return shared;
    const known = analysisErrorText(error.code);
    if (known) return known;
  }
  return errorMessage(error);
}

/** Facts of an RE job from its list row (`summary` is written by the trusted ingest). */
export function reJobFacts(job: { summary?: unknown }): { functions: number | null; engine: ReEngine | null } {
  const summary = job.summary && typeof job.summary === "object" ? (job.summary as Record<string, unknown>) : {};
  const counts = summary.counts && typeof summary.counts === "object" ? (summary.counts as Record<string, unknown>) : {};
  const functions = typeof counts.functions === "number" && Number.isFinite(counts.functions) ? counts.functions : null;
  const engine = summary.engine === "ghidra" || summary.engine === "radare2" || summary.engine === "replay" ? summary.engine : null;
  return { functions, engine };
}
