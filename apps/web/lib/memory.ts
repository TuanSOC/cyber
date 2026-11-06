/**
 * Pure helpers of the Memory Analysis views (M8 phase 9). Everything a memory image yields is
 * attacker-controlled (process names, command lines, banners, hex heads): parsed defensively
 * and only ever rendered as text. Nothing here names a verdict: findings are leads to review.
 *
 * Types come from the regenerated contracts (`apps/api/app/modules/memory_analysis/schemas.py`,
 * frozen in phase 1). Literal aliases of that file are inlined by OpenAPI, so they are read off
 * the models here (`MemoryArtifact["type"]`, `PluginStatus["status"]`).
 */
import type { Schemas } from "@cyberlab/contracts";

import { type MemoryProfile, type OsHint, knownErrorText } from "@/lib/analysis";
import { ApiError, errorMessage } from "@/lib/api";
import { apiErrorText } from "@/lib/http-errors";

export type MemorySummary = Schemas["MemorySummaryOut"];
export type MemoryProcess = Schemas["ProcessOut"];
export type ProcessDetail = Schemas["ProcessDetailOut"];
export type MemoryConnection = Schemas["ConnectionOut"];
export type MemoryInjection = Schemas["InjectionOut"];
export type MemoryArtifact = Schemas["ArtifactOut"];
export type MemoryArtifactType = MemoryArtifact["type"];
export type PluginStatus = Schemas["PluginStatusOut"];
export type PluginState = PluginStatus["status"];
export type SymbolsInfo = Schemas["SymbolsOut"];
export type WindowsPdb = Schemas["WindowsPdbOut"];
export type MemorySensitivity = Schemas["MemorySensitivityOut"];
export type SensitivityState = MemorySensitivity["state"];
export type ReleaseBody = Schemas["ReleaseIn"];
export type MemoryOs = "windows" | "linux";

type Json = Record<string, unknown>;

const isRecord = (value: unknown): value is Json =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const text = (value: unknown): string | null => (typeof value === "string" && value !== "" ? value : null);
const finite = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) ? value : null;

// ---------------------------------------------------------------------------------------------
// Tabs (no YARA tab: memory YARA is cut, RT8)

export const MEMORY_TABS = [
  ["processes", "Processes"],
  ["network", "Network"],
  ["regions", "Memory regions"],
  ["modules", "Modules"],
  ["services", "Services"],
  ["registry", "Registry"],
  ["linux", "Linux"],
  ["findings", "Findings"],
  ["iocs", "IOCs"],
  ["timeline", "Timeline"],
] as const;

export type MemoryTab = (typeof MEMORY_TABS)[number][0] | "overview";
type ListTab = Exclude<MemoryTab, "overview">;

const WINDOWS_ONLY = new Set<string>(["modules", "services", "registry"]);
const LINUX_ONLY = new Set<string>(["linux"]);

/** Tabs offered for the image's OS; an unknown OS (no summary yet) shows the common tabs. */
export function memoryTabs(os: MemoryOs | null | undefined): (typeof MEMORY_TABS)[number][] {
  return MEMORY_TABS.filter(([tab]) => {
    if (WINDOWS_ONLY.has(tab)) return os === "windows";
    if (LINUX_ONLY.has(tab)) return os === "linux";
    return true;
  });
}

/** The `tab` search param as a tab offered for this OS; anything else is the overview. */
export function parseMemoryTab(value: string | null | undefined, os: MemoryOs | null | undefined): MemoryTab {
  return value && memoryTabs(os).some(([tab]) => tab === value) ? (value as MemoryTab) : "overview";
}

/** Tabs whose list reads `?ref=<row id>` (citation deep links; every memory list route takes it). */
export const MEMORY_REF_TABS: ReadonlySet<string> = new Set<ListTab>([
  "processes",
  "network",
  "regions",
  "modules",
  "services",
  "registry",
  "linux",
  "findings",
  "iocs",
  "timeline",
]);

// ---------------------------------------------------------------------------------------------
// Artifacts

/** The artifact types each artifact tab lists (one request per type, never mixed pages). */
export const TAB_ARTIFACT_TYPES = {
  modules: ["module", "ldr_unlinked"],
  services: ["service"],
  registry: ["hive", "userassist"],
  linux: ["bash", "open_file", "syscall_hook", "hidden_module"],
} as const satisfies Record<string, readonly MemoryArtifactType[]>;

export type ArtifactTab = keyof typeof TAB_ARTIFACT_TYPES;

export const ARTIFACT_TYPE_LABELS: Record<MemoryArtifactType, string> = {
  module: "Loaded modules",
  ldr_unlinked: "Modules missing from a loader list",
  service: "Services",
  hive: "Registry hives",
  userassist: "UserAssist",
  bash: "Bash history",
  open_file: "Open files",
  syscall_hook: "Syscall table checks",
  hidden_module: "Hidden kernel modules",
};

/** Plugins behind each artifact type (for "this profile did not run it" notes). */
export const FULL_PROFILE_ARTIFACTS: ReadonlySet<MemoryArtifactType> = new Set([
  "ldr_unlinked",
  "open_file",
  "syscall_hook",
  "hidden_module",
]);

export type ArtifactField = {
  key: string;
  label: string;
  format?: "mono" | "address" | "date" | "bool" | "bytes";
};

/** Columns of each artifact type (the normalizers' attribute keys); other keys go to the detail. */
export const ARTIFACT_FIELDS: Record<MemoryArtifactType, readonly ArtifactField[]> = {
  module: [
    { key: "name", label: "Name" },
    { key: "path", label: "Path", format: "mono" },
    { key: "base", label: "Base", format: "address" },
    { key: "size", label: "Size", format: "bytes" },
  ],
  ldr_unlinked: [
    { key: "path", label: "Path", format: "mono" },
    { key: "base", label: "Base", format: "address" },
    { key: "in_load", label: "Load list", format: "bool" },
    { key: "in_init", label: "Init list", format: "bool" },
    { key: "in_mem", label: "Memory list", format: "bool" },
  ],
  service: [
    { key: "name", label: "Name" },
    { key: "state", label: "State" },
    { key: "start", label: "Start" },
    { key: "binary", label: "Binary", format: "mono" },
  ],
  hive: [
    { key: "path", label: "Path", format: "mono" },
    { key: "offset", label: "Offset", format: "address" },
  ],
  userassist: [
    { key: "path", label: "Program", format: "mono" },
    { key: "count", label: "Runs" },
    { key: "last_updated", label: "Last run", format: "date" },
    { key: "hive", label: "Hive", format: "mono" },
  ],
  bash: [
    { key: "time", label: "Time", format: "date" },
    { key: "command", label: "Command", format: "mono" },
  ],
  open_file: [
    { key: "fd", label: "FD" },
    { key: "path", label: "Path", format: "mono" },
    { key: "type", label: "Type" },
    { key: "size", label: "Size", format: "bytes" },
  ],
  syscall_hook: [
    { key: "table", label: "Table" },
    { key: "index", label: "Index" },
    { key: "handler", label: "Handler", format: "mono" },
    { key: "table_address", label: "Table address", format: "address" },
  ],
  hidden_module: [
    { key: "name", label: "Name" },
    { key: "offset", label: "Offset", format: "address" },
    { key: "code_size", label: "Code size", format: "bytes" },
    { key: "taints", label: "Taints" },
  ],
};

const COUNT = new Intl.NumberFormat("en-US");

/** One attribute as display text (scalars only; anything else is dropped), null when absent. */
export function attributeValue(attributes: unknown, field: ArtifactField): string | null {
  if (!isRecord(attributes) || !Object.hasOwn(attributes, field.key)) return null;
  const value = attributes[field.key];
  if (value === null || value === undefined || value === "") return null;
  switch (field.format) {
    case "address":
      return formatAddress(value as number | string);
    case "bool":
      return typeof value === "boolean" ? (value ? "yes" : "no") : String(value);
    case "bytes":
      return typeof value === "number" && Number.isFinite(value) ? COUNT.format(value) : String(value);
    default:
      if (typeof value === "number") return Number.isFinite(value) ? String(value) : null;
      if (typeof value === "string" || typeof value === "boolean") return String(value);
      return null;
  }
}

/** The attributes not shown as columns, as [key, text] (the detail row). */
export function otherAttributes(type: MemoryArtifactType, attributes: unknown): [string, string][] {
  if (!isRecord(attributes)) return [];
  const shown = new Set(ARTIFACT_FIELDS[type]?.map((field) => field.key) ?? []);
  return Object.entries(attributes)
    .filter(([key]) => !shown.has(key))
    .map(([key]) => [key, attributeValue(attributes, { key, label: key })] as const)
    .filter((entry): entry is [string, string] => entry[1] !== null);
}

// ---------------------------------------------------------------------------------------------
// Addresses and hex

/**
 * An unsigned 64-bit address as hex text. JSON numbers above 2^53 lose their low bits in the
 * browser, so such values are marked approximate ("≈"); `0x…` strings (the normalizers' text
 * form of addresses that do not fit a bigint) are shown as they are.
 */
export function formatAddress(value: number | string | null | undefined): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string") {
    if (/^0x[0-9a-f]{1,16}$/i.test(value)) return value.toLowerCase();
    if (/^\d{1,20}$/.test(value)) return `0x${BigInt(value).toString(16)}`;
    return "—";
  }
  if (!Number.isFinite(value) || value < 0 || !Number.isInteger(value)) return "—";
  const hex = `0x${BigInt(value).toString(16)}`;
  return Number.isSafeInteger(value) ? hex : `≈${hex}`;
}

const HEX_HEAD = /^(?:[0-9a-f]{2}){0,64}$/i;

/**
 * The first bytes of a memory region as hex-dump lines ("0000  4d 5a 90 …  MZ."), 16 bytes
 * per line, printable ASCII only in the text column. Text for a `<pre>`, never HTML.
 */
export function hexDumpLines(headHex: string | null | undefined): string[] {
  if (!headHex) return [];
  if (!HEX_HEAD.test(headHex)) return [headHex.slice(0, 256)];
  const bytes = headHex.match(/../g)?.map((pair) => Number.parseInt(pair, 16)) ?? [];
  const lines: string[] = [];
  for (let at = 0; at < bytes.length; at += 16) {
    const chunk = bytes.slice(at, at + 16);
    const hex = chunk.map((b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ");
    const ascii = chunk.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${at.toString(16).padStart(4, "0")}  ${hex}  ${ascii}`);
  }
  return lines;
}

// ---------------------------------------------------------------------------------------------
// Plugin status (a partial run is never shown as complete)

export const PLUGIN_STATE_LABELS: Record<PluginState, string> = {
  ok: "OK",
  failed: "Failed",
  timeout: "Timed out",
  skipped: "Skipped",
  unsupported: "Not supported",
};

export type Completeness = {
  complete: boolean;
  /** Plugins that did not finish `ok`. */
  incomplete: PluginStatus[];
  /** Plugins whose rows were cut at a cap. */
  truncatedPlugins: PluginStatus[];
  /** Record kinds cut at a cap at ingest (`processes`, `artifacts`…). */
  truncatedKinds: string[];
};

export function completeness(summary: Pick<MemorySummary, "plugins" | "truncated"> | null | undefined): Completeness {
  const plugins = summary?.plugins ?? [];
  const incomplete = plugins.filter((p) => p.status !== "ok");
  const truncatedPlugins = plugins.filter((p) => p.truncated);
  const truncatedKinds = Object.entries(isRecord(summary?.truncated) ? summary.truncated : {})
    .filter(([, value]) => value === true)
    .map(([key]) => key);
  return {
    complete: plugins.length > 0 && incomplete.length === 0 && truncatedPlugins.length === 0 && truncatedKinds.length === 0,
    incomplete,
    truncatedPlugins,
    truncatedKinds,
  };
}

// ---------------------------------------------------------------------------------------------
// Symbols missing (RT12)

/** The Windows kernel PDB allow-list of the contract (`cyberlab_jobs.memory.KERNEL_PDB_NAMES`). */
export const KERNEL_PDB_NAMES: ReadonlySet<string> = new Set(["ntkrnlmp.pdb", "ntoskrnl.pdb", "ntkrnlpa.pdb", "ntkrpamp.pdb"]);
const PDB_GUID = /^[0-9A-F]{32}$/;

/** Re-checks the three fields against the ingest's patterns (the API validated them already). */
export function validWindowsPdb(pdb: unknown): pdb is WindowsPdb {
  if (!isRecord(pdb)) return false;
  const { name, guid, age } = pdb;
  return (
    typeof name === "string" &&
    KERNEL_PDB_NAMES.has(name) &&
    typeof guid === "string" &&
    PDB_GUID.test(guid) &&
    typeof age === "number" &&
    Number.isInteger(age) &&
    age >= 0 &&
    age <= 65_535
  );
}

/**
 * The operator command that fetches a Windows kernel's symbols, built from the three
 * validated fields only, or null when any field fails its pattern. No other job value (and
 * never a Linux banner) ever goes into a command.
 */
export function windowsSymbolsCommand(pdb: unknown): string | null {
  if (!validWindowsPdb(pdb)) return null;
  return `pnpm memory:symbols -- fetch-windows --pdb ${pdb.name} --guid ${pdb.guid} --age ${pdb.age}`;
}

/** Where the Linux symbol workflow is documented (a doc path, shown as text). */
export const SYMBOLS_RUNBOOK = "docs/DEPLOYMENT.md, “Memory forensics (M8)” → “Symbols runbook”";

/**
 * The Linux banner for display: printable ASCII only (anything else becomes "?"), ≤ 512
 * characters. It is attacker-chosen text: shown quoted and inert, never in a command or a
 * copy button.
 */
export function bannerText(banner: string | null | undefined): string | null {
  if (!banner) return null;
  return banner.slice(0, 512).replace(/[^\x20-\x7e]/g, "?");
}

// ---------------------------------------------------------------------------------------------
// Process flags and the tree

export type ProcessFlag = "hidden" | "terminated" | "private_exec" | "lineage";

export const PROCESS_FLAG_LABELS: Record<ProcessFlag, string> = {
  hidden: "Not in the active list",
  terminated: "Exited",
  private_exec: "Private executable region",
  lineage: "Unusual parent",
};

export const PROCESS_FLAG_HINTS: Record<ProcessFlag, string> = {
  hidden: "Found by the pool scan but not in the active process list (unlinked, or exited and not yet reused).",
  terminated: "The process has an exit time.",
  private_exec: "A private memory region with execute permission was reported for this process.",
  lineage: "Its parent differs from the usual one for this process name.",
};

export type FlagContext = {
  hiddenPids: ReadonlySet<number>;
  privateExecPids: ReadonlySet<number>;
  lineagePids: ReadonlySet<number>;
};

export const EMPTY_FLAGS: FlagContext = { hiddenPids: new Set(), privateExecPids: new Set(), lineagePids: new Set() };

const FLAG_FINDING_TYPES: Record<string, keyof FlagContext> = {
  mem_hidden_process: "hiddenPids",
  mem_private_exec_pe: "privateExecPids",
  mem_private_exec_region: "privateExecPids",
  mem_process_lineage: "lineagePids",
};

/** Per-pid flags from the job's findings (`attributes.pid`) and memory regions. */
export function flagContext(
  findings: readonly { type: string; attributes?: unknown }[],
  injections: readonly { pid: number }[],
): FlagContext {
  const sets = { hiddenPids: new Set<number>(), privateExecPids: new Set<number>(), lineagePids: new Set<number>() };
  for (const finding of findings) {
    const target = Object.hasOwn(FLAG_FINDING_TYPES, finding.type) ? FLAG_FINDING_TYPES[finding.type] : null;
    const pid = isRecord(finding.attributes) ? finite(finding.attributes.pid) : null;
    if (target && pid !== null) sets[target].add(pid);
  }
  for (const injection of injections) sets.privateExecPids.add(injection.pid);
  return sets;
}

export function processFlags(
  p: Pick<MemoryProcess, "pid" | "sources" | "exit_time">,
  ctx: FlagContext = EMPTY_FLAGS,
): ProcessFlag[] {
  const flags: ProcessFlag[] = [];
  const scanOnly = p.sources.includes("psscan") && !p.sources.includes("pslist");
  if (scanOnly || ctx.hiddenPids.has(p.pid)) flags.push("hidden");
  if (p.exit_time) flags.push("terminated");
  if (ctx.privateExecPids.has(p.pid)) flags.push("private_exec");
  if (ctx.lineagePids.has(p.pid)) flags.push("lineage");
  return flags;
}

/** Substring match of the in-job search (name, pid, command line, image path). */
export function matchesProcess(p: Pick<MemoryProcess, "pid" | "name" | "cmdline" | "image_path">, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return (
    String(p.pid) === q ||
    p.name.toLowerCase().includes(q) ||
    (p.cmdline ?? "").toLowerCase().includes(q) ||
    (p.image_path ?? "").toLowerCase().includes(q)
  );
}

/** The server caps the tree at this many nodes (`MEMORY_TREE_MAX_NODES`); above it, the list. */
export const TREE_MAX_NODES = 5_000;
/** The API's largest page (`MAX_LIMIT`); never more than 200 rows per request either way. */
export const TREE_PAGE = 100;

export type TreeNode = {
  process: MemoryProcess;
  parentId: string | null;
  children: TreeNode[];
  /** `ppid` names a process that is not in the image (exited parent, or a hostile value). */
  parentMissing: boolean;
  /** The parent link was cut because it closed a cycle. */
  cycle: boolean;
};

const timeOf = (iso: string | null | undefined): number => {
  const t = iso ? Date.parse(iso) : Number.NaN;
  return Number.isNaN(t) ? Number.POSITIVE_INFINITY : t;
};

const byStart = (a: TreeNode, b: TreeNode) =>
  timeOf(a.process.create_time) - timeOf(b.process.create_time) || a.process.pid - b.process.pid || a.process.id.localeCompare(b.process.id);

/**
 * The process tree from ppid links, without recursion (hostile images can chain thousands of
 * processes or close cycles). A reused pid picks the latest instance started before the child;
 * a link that closes a cycle is cut (the node becomes a root, `cycle`); a ppid with no process
 * puts the node at the root with `parentMissing`. Roots and children are ordered by start time.
 */
export function buildProcessTree(processes: readonly MemoryProcess[]): TreeNode[] {
  const nodes = new Map<string, TreeNode>();
  const byPid = new Map<number, MemoryProcess[]>();
  for (const p of processes) {
    if (nodes.has(p.id)) continue;
    nodes.set(p.id, { process: p, parentId: null, children: [], parentMissing: false, cycle: false });
    const same = byPid.get(p.pid);
    if (same) same.push(p);
    else byPid.set(p.pid, [p]);
  }

  for (const node of nodes.values()) {
    const { ppid, id, create_time } = node.process;
    if (ppid === null || ppid === undefined || ppid === 0) continue;
    const candidates = (byPid.get(ppid) ?? []).filter((c) => c.id !== id);
    if (candidates.length === 0) {
      node.parentMissing = true;
      continue;
    }
    const born = timeOf(create_time);
    const earlier = candidates.filter((c) => timeOf(c.create_time) <= born);
    const parent =
      earlier.length > 0
        ? earlier.reduce((best, c) => (timeOf(c.create_time) > timeOf(best.create_time) ? c : best))
        : candidates[0];
    node.parentId = parent.id;
  }

  // Cut every link that closes a cycle, in linear time: walk up from each unvisited node,
  // marking the path; a parent already on the current path closes a loop.
  const state = new Map<string, "path" | "done">();
  for (const start of nodes.values()) {
    const path: TreeNode[] = [];
    let current: TreeNode | undefined = start;
    while (current && !state.has(current.process.id)) {
      state.set(current.process.id, "path");
      path.push(current);
      const up: TreeNode | undefined = current.parentId ? nodes.get(current.parentId) : undefined;
      if (up && state.get(up.process.id) === "path") {
        current.parentId = null;
        current.cycle = true;
        break;
      }
      current = up;
    }
    for (const node of path) state.set(node.process.id, "done");
  }

  const roots: TreeNode[] = [];
  for (const node of nodes.values()) {
    const parent = node.parentId ? nodes.get(node.parentId) : undefined;
    if (parent) parent.children.push(node);
    else roots.push(node);
  }
  for (const node of nodes.values()) node.children.sort(byStart);
  return roots.sort(byStart);
}

export type TreeRow = { node: TreeNode; depth: number; hasChildren: boolean; expanded: boolean };

/**
 * Visible rows of the tree in display order (iterative depth-first walk). `collapsed` holds
 * the ids whose children are hidden; `keep`, when given, limits the rows to those ids (a
 * search keeps the matches and their ancestors).
 */
export function flattenTree(roots: readonly TreeNode[], collapsed: ReadonlySet<string>, keep?: ReadonlySet<string>): TreeRow[] {
  const rows: TreeRow[] = [];
  const stack: { node: TreeNode; depth: number }[] = [];
  for (let i = roots.length - 1; i >= 0; i -= 1) stack.push({ node: roots[i], depth: 0 });
  while (stack.length > 0) {
    const { node, depth } = stack.pop() as { node: TreeNode; depth: number };
    if (keep && !keep.has(node.process.id)) continue;
    const children = keep ? node.children.filter((child) => keep.has(child.process.id)) : node.children;
    const expanded = !collapsed.has(node.process.id);
    rows.push({ node, depth, hasChildren: children.length > 0, expanded });
    if (!expanded) continue;
    for (let i = children.length - 1; i >= 0; i -= 1) stack.push({ node: children[i], depth: depth + 1 });
  }
  return rows;
}

/** Ids of the matching processes and all their ancestors (for a tree search). */
export function searchKeep(roots: readonly TreeNode[], query: string): Set<string> | undefined {
  if (!query.trim()) return undefined;
  const byId = new Map<string, TreeNode>();
  const stack = [...roots];
  while (stack.length > 0) {
    const node = stack.pop() as TreeNode;
    byId.set(node.process.id, node);
    stack.push(...node.children);
  }
  const keep = new Set<string>();
  for (const node of byId.values()) {
    if (!matchesProcess(node.process, query)) continue;
    let current: TreeNode | undefined = node;
    while (current && !keep.has(current.process.id)) {
      keep.add(current.process.id);
      current = current.parentId ? byId.get(current.parentId) : undefined;
    }
  }
  return keep;
}

// ---------------------------------------------------------------------------------------------
// The list page (the job summary of `AnalysisJobOut`, parsed defensively)

export type MemoryJobFacts = {
  os: MemoryOs | null;
  engine: string | null;
  symbols: "resolved" | "missing" | null;
};

/** OS, engine and symbols status from a memory job's summary (unknown shapes give nulls). */
export function memoryJobFacts(job: { summary?: unknown; error_code?: string | null }): MemoryJobFacts {
  const summary = isRecord(job.summary) ? job.summary : {};
  const os = text(summary.os);
  const symbols = isRecord(summary.symbols) ? text(summary.symbols.status) : text(summary.symbols_status ?? summary.symbols);
  return {
    os: os === "windows" || os === "linux" ? os : null,
    engine: text(summary.engine),
    symbols:
      job.error_code === "symbols_missing" ? "missing" : symbols === "resolved" || symbols === "missing" ? symbols : null,
  };
}

export const MEMORY_OS_LABELS: Record<MemoryOs, string> = { windows: "Windows", linux: "Linux" };

// ---------------------------------------------------------------------------------------------
// Run, upload, sensitivity

export const MEMORY_PROFILES: readonly MemoryProfile[] = ["triage", "full"];
export const OS_HINTS: readonly OsHint[] = ["auto", "windows", "linux"];

export const MEMORY_PROFILE_HINTS: Record<MemoryProfile, string> = {
  triage: "Processes, command lines, network, private executable regions, services, registry hives and UserAssist (Windows) or bash history (Linux).",
  full: "Triage plus loader-list checks (Windows) or open files, private executable regions, syscall table and hidden module checks (Linux).",
};

export const RUN_NOTICE =
  "A memory analysis takes minutes to an hour, runs offline, and marks this evidence restricted (TLP:RED material: not sent to AI or threat-intel providers) until an admin releases it.";

/** RT3: other analyses already ran on this evidence before it was restricted. */
export const EARLIER_JOBS_NOTICE =
  "This evidence already has other analyses. Their results were not restricted before; from this run on, the restriction covers them too.";

const RUN_ERROR_TEXT: Readonly<Record<string, string>> = {
  analysis_queue_full:
    "The memory analyzer is busy (one memory analysis per organization runs at a time). Try again when the running one finishes.",
  analysis_active: "A memory analysis of this evidence is already queued or running.",
  evidence_purged: "The evidence bytes were deleted by the retention policy, so they cannot be analyzed.",
  rate_limited: "Too many requests. Try again in a moment.",
};

/** The message for a refused memory run (shared texts first, then the analysis ones). */
export function memoryRunErrorText(error: unknown): string {
  const shared = apiErrorText(error);
  if (shared) return shared;
  if (error instanceof ApiError) {
    if (Object.hasOwn(RUN_ERROR_TEXT, error.code)) return RUN_ERROR_TEXT[error.code];
    const known = knownErrorText(error.code);
    if (known) return known;
  }
  return errorMessage(error);
}

/** Default `MEMORY_MAX_BYTES` (the API does not publish its setting; operators may raise it to 16 GiB). */
export const MEMORY_MAX_BYTES_DEFAULT = 8 * 1024 ** 3;

export const UPLOAD_NOTICE =
  "Memory images are TLP:RED material from the upload: restricted (never sent to AI or threat-intel providers) until an admin releases them, and never analyzed automatically. Run the memory analysis from the evidence page.";

/** "N processes · M connections …" headline counts of the summary, in a fixed order. */
const COUNT_LABELS: [string, string][] = [
  ["processes", "processes"],
  ["connections", "connections"],
  ["injections", "memory regions"],
  ["artifacts", "artifacts"],
  ["findings", "findings"],
  ["iocs", "IOCs"],
];

export function summaryCounts(counts: unknown): { key: string; label: string; value: number }[] {
  if (!isRecord(counts)) return [];
  return COUNT_LABELS.flatMap(([key, label]) => {
    const value = finite(counts[key]);
    return value === null ? [] : [{ key, label, value }];
  });
}
