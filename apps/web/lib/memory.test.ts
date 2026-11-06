import { describe, expect, it } from "vitest";

import { ApiError } from "@/lib/api";
import {
  ARTIFACT_FIELDS,
  KERNEL_PDB_NAMES,
  type MemoryProcess,
  TREE_MAX_NODES,
  attributeValue,
  bannerText,
  buildProcessTree,
  completeness,
  flagContext,
  flattenTree,
  formatAddress,
  hexDumpLines,
  memoryJobFacts,
  memoryRunErrorText,
  memoryTabs,
  memoryUploadErrorText,
  otherAttributes,
  parseMemoryTab,
  processFlags,
  searchKeep,
  summaryCounts,
  windowsSymbolsCommand,
} from "@/lib/memory";

let seq = 0;
function proc(over: Partial<MemoryProcess> & { pid: number }): MemoryProcess {
  seq += 1;
  return {
    id: `00000000-0000-4000-8000-${String(seq).padStart(12, "0")}`,
    ppid: null,
    name: `p${over.pid}`,
    offset: null,
    create_time: null,
    exit_time: null,
    threads: 1,
    handles: null,
    session_id: null,
    wow64: null,
    sources: ["pslist"],
    cmdline: null,
    image_path: null,
    children: 0,
    ...over,
  } as MemoryProcess;
}

// The phase-1 Windows fixture's shape (windows_triage.ndjson): System → smss, a reused pid,
// a psscan-only process whose parent exited.
const FIXTURE: MemoryProcess[] = [
  proc({ pid: 4, ppid: 0, name: "System", sources: ["pslist", "psscan"], create_time: "2026-11-01T08:00:00Z" }),
  proc({ pid: 92, ppid: 4, name: "Registry", sources: ["pslist", "psscan"], create_time: "2026-11-01T08:00:01Z" }),
  proc({ pid: 356, ppid: 4, name: "smss.exe", sources: ["pslist", "psscan"], create_time: "2026-11-01T08:00:02Z" }),
  proc({ pid: 468, ppid: 460, name: "csrss.exe", create_time: "2026-11-01T08:00:03Z" }),
  proc({ pid: 6112, ppid: 3040, name: "svch0st.exe", sources: ["psscan"], create_time: "2026-11-01T09:00:00Z" }),
];

describe("memory tabs", () => {
  it("offers OS-specific tabs only for that OS and never a YARA tab", () => {
    const windows = memoryTabs("windows").map(([tab]) => tab);
    const linux = memoryTabs("linux").map(([tab]) => tab);
    expect(windows).toEqual(expect.arrayContaining(["processes", "network", "regions", "modules", "services", "registry", "findings", "iocs", "timeline"]));
    expect(windows).not.toContain("linux");
    expect(linux).toContain("linux");
    expect(linux).not.toContain("registry");
    expect([...windows, ...linux].some((tab) => /yara/i.test(tab))).toBe(false);
    expect(memoryTabs(null).map(([tab]) => tab)).not.toContain("modules");
  });

  it("parses the tab param against the OS", () => {
    expect(parseMemoryTab("registry", "windows")).toBe("registry");
    expect(parseMemoryTab("registry", "linux")).toBe("overview");
    expect(parseMemoryTab("yara", "windows")).toBe("overview");
    expect(parseMemoryTab(null, "linux")).toBe("overview");
  });
});

describe("symbols-missing command (RT12)", () => {
  const pdb = { name: "ntkrnlmp.pdb", guid: "0123456789ABCDEF0123456789ABCDEF", age: 1 };

  it("builds the exact operator command from the three validated fields", () => {
    expect(windowsSymbolsCommand(pdb)).toBe(
      "pnpm memory:symbols -- fetch-windows --pdb ntkrnlmp.pdb --guid 0123456789ABCDEF0123456789ABCDEF --age 1",
    );
    for (const name of KERNEL_PDB_NAMES) expect(windowsSymbolsCommand({ ...pdb, name })).toContain(`--pdb ${name} `);
  });

  it("refuses any field outside its pattern (no command at all)", () => {
    const hostile = [
      { ...pdb, name: "ntkrnlmp.pdb; rm -rf ~" },
      { ...pdb, name: "evil.pdb" },
      { ...pdb, guid: "0123456789abcdef0123456789abcdef" },
      { ...pdb, guid: "0123456789ABCDEF0123456789ABCDE$" },
      { ...pdb, guid: `${pdb.guid}\n` },
      { ...pdb, age: -1 },
      { ...pdb, age: 65_536 },
      { ...pdb, age: 1.5 },
      { ...pdb, age: "1" },
      null,
      "ntkrnlmp.pdb",
    ];
    for (const value of hostile) expect(windowsSymbolsCommand(value)).toBeNull();
  });

  it("never carries extra fields into the command", () => {
    const command = windowsSymbolsCommand({ ...pdb, banner: "$(id)", extra: "`whoami`" });
    expect(command).not.toMatch(/\$\(|`/);
  });

  it("shows a banner as printable text only", () => {
    expect(bannerText("Linux version 6.1.0 $(curl x|sh)")).toBe("Linux version 6.1.0 $(curl x|sh)");
    expect(bannerText("a\u001b[31mb\nc")).toBe("a?[31mb?c");
    expect(bannerText("x".repeat(600))).toHaveLength(512);
    expect(bannerText(null)).toBeNull();
  });
});

describe("addresses and hex", () => {
  it("formats safe, unsafe and text addresses", () => {
    expect(formatAddress("0x400000")).toBe("0x400000");
    expect(formatAddress("0xfffff80012345678")).toBe("0xfffff80012345678");
    expect(formatAddress(4194304)).toBe("0x400000");
    expect(formatAddress(18446639134773608448)).toMatch(/^≈0xffffa/);
    expect(formatAddress("0xFFFFA0000000")).toBe("0xffffa0000000");
    expect(formatAddress("18446639134773608448")).toBe(`0x${BigInt("18446639134773608448").toString(16)}`);
    expect(formatAddress(null)).toBe("—");
    expect(formatAddress(-1)).toBe("—");
    expect(formatAddress("<b>")).toBe("—");
  });

  it("renders a hex head as dump lines and refuses anything that is not hex", () => {
    const lines = hexDumpLines("4d5a90000300000004000000ffff0000b800");
    expect(lines).toHaveLength(2);
    expect(lines[0]).toMatch(/^0000 {2}4d 5a 90 00 /);
    expect(lines[0]).toContain("MZ");
    expect(lines[1]).toMatch(/^0010 {2}b8 00/);
    expect(hexDumpLines("<script>")).toEqual(["<script>"]);
    expect(hexDumpLines("")).toEqual([]);
  });
});

describe("plugin completeness", () => {
  const ok = { plugin: "windows.pslist", status: "ok", rows: 1, truncated: false, duration_ms: 10 } as const;

  it("is complete only when every plugin is ok and nothing was cut", () => {
    expect(completeness({ plugins: [ok], truncated: {} }).complete).toBe(true);
    expect(completeness({ plugins: [], truncated: {} }).complete).toBe(false);
    const failed = completeness({ plugins: [ok, { ...ok, plugin: "windows.netscan", status: "timeout" }], truncated: {} });
    expect(failed.complete).toBe(false);
    expect(failed.incomplete.map((p) => p.plugin)).toEqual(["windows.netscan"]);
    expect(completeness({ plugins: [{ ...ok, truncated: true }], truncated: {} }).complete).toBe(false);
    expect(completeness({ plugins: [ok], truncated: { artifacts: true, iocs: false } }).truncatedKinds).toEqual(["artifacts"]);
  });
});

describe("process flags", () => {
  it("flags scan-only, exited, private-executable and lineage processes", () => {
    const ctx = flagContext(
      [
        { type: "mem_process_lineage", attributes: { pid: 92 } },
        { type: "mem_hidden_process", attributes: { pid: 77 } },
        { type: "mem_suspicious_cmdline", attributes: { pid: 4 } },
        { type: "mem_private_exec_region", attributes: { pid: "6112" } },
      ],
      [{ pid: 6112 }],
    );
    expect(processFlags(FIXTURE[4], ctx)).toEqual(["hidden", "private_exec"]);
    expect(processFlags(FIXTURE[1], ctx)).toEqual(["lineage"]);
    expect(processFlags(FIXTURE[0], ctx)).toEqual([]);
    expect(processFlags(proc({ pid: 77 }), ctx)).toEqual(["hidden"]);
    expect(processFlags(proc({ pid: 5, exit_time: "2026-11-01T09:00:00Z" }))).toEqual(["terminated"]);
  });
});

describe("process tree", () => {
  it("builds the fixture tree with missing parents at the root", () => {
    const roots = buildProcessTree(FIXTURE);
    expect(roots.map((r) => r.process.name)).toEqual(["System", "csrss.exe", "svch0st.exe"]);
    expect(roots[0].children.map((c) => c.process.name)).toEqual(["Registry", "smss.exe"]);
    expect(roots[1].parentMissing).toBe(true);
    expect(roots[0].parentMissing).toBe(false);
  });

  it("breaks cycles and picks the instance of a reused pid started before the child", () => {
    const a = proc({ pid: 10, ppid: 11 });
    const b = proc({ pid: 11, ppid: 10 });
    const roots = buildProcessTree([a, b]);
    expect(roots).toHaveLength(1);
    expect(roots[0].cycle).toBe(true);
    expect(roots[0].children).toHaveLength(1);

    const old = proc({ pid: 20, create_time: "2026-11-01T08:00:00Z" });
    const reused = proc({ pid: 20, create_time: "2026-11-01T10:00:00Z" });
    const child = proc({ pid: 21, ppid: 20, create_time: "2026-11-01T09:00:00Z" });
    const tree = buildProcessTree([reused, old, child]);
    const parent = tree.find((n) => n.process.id === old.id);
    expect(parent?.children.map((c) => c.process.id)).toEqual([child.id]);
    expect(buildProcessTree([proc({ pid: 30, ppid: 30 })])[0].parentMissing).toBe(true);
  });

  it("handles a 5 000-deep chain without recursion", () => {
    const chain = Array.from({ length: TREE_MAX_NODES }, (_, i) => proc({ pid: i + 1, ppid: i }));
    const roots = buildProcessTree(chain);
    expect(roots).toHaveLength(1);
    const rows = flattenTree(roots, new Set());
    expect(rows).toHaveLength(TREE_MAX_NODES);
    expect(rows.at(-1)?.depth).toBe(TREE_MAX_NODES - 1);
  });

  it("collapses subtrees and keeps search matches with their ancestors", () => {
    const roots = buildProcessTree(FIXTURE);
    const system = roots[0].process.id;
    expect(flattenTree(roots, new Set([system])).map((r) => r.node.process.name)).toEqual(["System", "csrss.exe", "svch0st.exe"]);
    const keep = searchKeep(roots, "smss");
    expect(flattenTree(roots, new Set(), keep).map((r) => r.node.process.name)).toEqual(["System", "smss.exe"]);
    expect(searchKeep(roots, "  ")).toBeUndefined();
  });
});

describe("artifacts", () => {
  it("renders scalar attributes as text and moves the rest to the detail", () => {
    const attrs = { name: "Spooler", state: "SERVICE_RUNNING", start: "AUTO", binary: "C:\\x.exe", display: "<b>Print</b>", order: 3 };
    expect(attributeValue(attrs, ARTIFACT_FIELDS.service[0])).toBe("Spooler");
    expect(otherAttributes("service", attrs)).toEqual([
      ["display", "<b>Print</b>"],
      ["order", "3"],
    ]);
    expect(attributeValue({ base: 4194304 }, { key: "base", label: "Base", format: "address" })).toBe("0x400000");
    expect(attributeValue({ base: "0xFFFFF80012345678" }, { key: "base", label: "Base", format: "address" })).toBe("0xfffff80012345678");
    expect(attributeValue({ in_load: false }, { key: "in_load", label: "x", format: "bool" })).toBe("no");
    // Numbers above 2^53 lost precision in JSON.parse: marked approximate, service.start included.
    expect(attributeValue({ start: 2 ** 60 }, ARTIFACT_FIELDS.service[2])).toBe(`≈${2 ** 60}`);
    expect(attributeValue({ size: 2 ** 60 }, { key: "size", label: "Size", format: "bytes" })).toMatch(/^≈/);
    expect(attributeValue({ order: 3 }, { key: "order", label: "x" })).toBe("3");
    expect(otherAttributes("service", { order: 2 ** 55 })).toEqual([["order", `≈${2 ** 55}`]]);
    expect(attributeValue({ nested: { a: 1 } }, { key: "nested", label: "x" })).toBeNull();
  });
});

describe("list facts and errors", () => {
  it("reads OS and symbols from the job summary defensively", () => {
    expect(memoryJobFacts({ summary: { os: "windows", symbols: { status: "resolved" } } })).toEqual({
      os: "windows",
      engine: null,
      symbols: "resolved",
    });
    expect(memoryJobFacts({ summary: null, error_code: "symbols_missing" }).symbols).toBe("missing");
    expect(memoryJobFacts({ summary: { os: "<script>" } }).os).toBeNull();
  });

  it("orders headline counts", () => {
    expect(summaryCounts({ iocs: 2, processes: 41, bogus: 1 }).map((c) => c.key)).toEqual(["processes", "iocs"]);
  });

  it("maps run refusals to messages", () => {
    expect(memoryRunErrorText(new ApiError(413, "memory_image_too_large", "x"))).toMatch(/larger/);
    expect(memoryRunErrorText(new ApiError(429, "analysis_queue_full", "x"))).toMatch(/busy/);
    expect(memoryRunErrorText(new ApiError(410, "evidence_purged", "x"))).toMatch(/retention/);
  });
});

describe("memory upload errors", () => {
  it("explains 413 and 507 for memory images only", () => {
    expect(memoryUploadErrorText(new ApiError(413, "upload_failed", "Upload failed (413)"))).toMatch(/larger than this platform accepts/);
    expect(memoryUploadErrorText(new ApiError(413, "memory_image_too_large", "x"))).toMatch(/MEMORY_MAX_BYTES/);
    expect(memoryUploadErrorText(new ApiError(507, "insufficient_storage", "x"))).toMatch(/free disk space/);
    expect(memoryUploadErrorText(new ApiError(409, "conflict", "x"))).toBeNull();
    expect(memoryUploadErrorText(new Error("x"))).toBeNull();
  });
});
