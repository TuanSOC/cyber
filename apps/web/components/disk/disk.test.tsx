import type { Schemas } from "@cyberlab/contracts";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { IocsTab } from "@/components/analysis/iocs-tab";
import { DerivedBadgeView } from "@/components/disk/derived-evidence-badge";
import { DiskOverview, MediaHashStatusView, StageStrip } from "@/components/disk/disk-overview";
import { ClearFlagsStep, DiskReleaseForm, DiskSensitivityBanner } from "@/components/disk/disk-sensitivity-banner";
import { HourHistogram, TimelineRow } from "@/components/disk/disk-timeline-tab";
import { DiskUploadOption } from "@/components/disk/disk-upload-option";
import { ExportRowView, InteropDownloads } from "@/components/disk/exports-tab";
import { FileDetailView } from "@/components/disk/file-drawer";
import { FileRow } from "@/components/disk/file-row";
import { PartitionTable } from "@/components/disk/partitions-tab";
import { RunDiskForm, SegmentPicker, initialSegments } from "@/components/disk/run-disk-analysis";
import { WindowedRows } from "@/components/disk/windowed-rows";
import { type DiskFile, type DiskFileDetail, type DiskPartition, type DiskSummary, DISK_UPLOAD_NOTICE } from "@/lib/disk";
import type { DiskExport } from "@/lib/disk-exports";
import type { TimelineItem } from "@/lib/disk-timeline";
import { DISK_RELEASE_ACK } from "@/lib/evidence-sensitivity";
import { OrgProvider } from "@/lib/org-context";

const ORG = "11111111-1111-4111-8111-111111111111";
const JOB = "6a1f0c1e-8d6b-4c55-9d9e-0d1b6f5a1001";
const EVIDENCE = "33333333-3333-4333-8333-333333333333";
const INV = "44444444-4444-4444-8444-444444444444";
const noop = () => undefined;

// Attacker-chosen names from the image (paths, EWF values, messages).
const SCRIPT = '<script>alert("x")</script>';
const JS_URL = "javascript:alert(document.cookie)";
const RTLO = "invoice‮fdp.exe";

function render(node: ReactElement, role: "owner" | "admin" | "analyst" | "viewer" = "owner"): string {
  return renderToStaticMarkup(
    <OrgProvider value={{ orgId: ORG, orgName: "Org", role }}>
      <QueryClientProvider client={new QueryClient()}>{node}</QueryClientProvider>
    </OrgProvider>,
  );
}

/** No attacker string became markup or a link target. */
function expectInert(html: string) {
  expect(html).not.toContain("<script>");
  expect(html).not.toMatch(/href="javascript:/i);
  expect(html).not.toContain("‮");
}

const SUMMARY = {
  job_id: JOB,
  profile: "triage",
  format: "ewf",
  segments: [
    { ordinal: 0, evidence_id: EVIDENCE, original_filename: "laptop.E01", size_bytes: 2_000_000_000, sha256: "a".repeat(64) },
    { ordinal: 1, evidence_id: "55555555-5555-4555-8555-555555555555", original_filename: SCRIPT, size_bytes: 1_000, sha256: "b".repeat(64) },
  ],
  media_size: "18446744073709551615",
  sector_size: 512,
  media_sha256: "c".repeat(64),
  ewf_md5: "d".repeat(32),
  ewf_sha1: null,
  media_hash_status: "mismatch",
  ewf_meta: { examiner: SCRIPT, notes: JS_URL, case_number: RTLO },
  volume_system: "dos",
  engine: "tsk",
  timeline_engine: "replay",
  tool_versions: { sleuthkit: "4.14.0", plaso: "20250918" },
  stages: [
    { stage: "download", partition_index: null, status: "ok", reason: null, rows: 0, truncated: false, duration_ms: 1200, error_code: null },
    { stage: "walk", partition_index: 1, status: "truncated", reason: null, rows: 500000, truncated: true, duration_ms: 9000, error_code: null },
    { stage: "timeline", partition_index: 1, status: "skipped", reason: "deadline", rows: 0, truncated: false, duration_ms: 0, error_code: null },
  ],
  artifacts: [{ artifact: "evtx", files: 3, bytes: 100, events_read: 1000, events_stored: 800 }],
  hashsets: [{ name: "nsrl-min", kind: "known_good", count: 1000, manifest_sha256: "e".repeat(64) }],
  counts: { partitions: 2, files: 500000, findings: 3 },
  truncated: true,
} as unknown as DiskSummary;

function file(over: Partial<DiskFileDetail> = {}): DiskFileDetail {
  return {
    id: "66666666-6666-4666-8666-666666666666",
    partition_index: 1,
    meta_addr: "18446744073709551615",
    meta_seq: 2,
    stream: null,
    path: `/Users/${SCRIPT}/${JS_URL}/${RTLO}`,
    parent_addr: "5",
    name: RTLO,
    ext: "exe",
    type: "reg",
    flags: ["allocated", "hard_linked", "name_lossy"],
    size: 1024,
    mtime: "2026-01-01T10:00:00Z",
    atime: null,
    ctime: null,
    crtime: null,
    time_basis: "utc",
    magic: "pe",
    hash_status: "hashed",
    md5: "d".repeat(32),
    sha1: null,
    sha256: "f".repeat(64),
    known: "good",
    known_set: "nsrl-min",
    yara_rules: ["Suspicious_Packer"],
    mode: null,
    uid: null,
    gid: null,
    other_names: [`/Windows/${SCRIPT}`],
    streams: [],
    exportable: false,
    not_exportable_reason: "never_collected",
    ...over,
  } as DiskFileDetail;
}

describe("overview", () => {
  it("labels worker-reported facts and never says verified", () => {
    const html = render(<DiskOverview summary={SUMMARY} />);
    expect(html).toContain("reported by the worker");
    expect(html).toContain("Differs from the hash stored at acquisition");
    expect(html).toContain('data-testid="media-hash-mismatch"');
    expect(html.toLowerCase()).not.toContain("verified the");
    expect(html).not.toMatch(/>\s*Verified\s*</);
    expect(html).toContain("18,446,744,073,709,551,615 bytes");
    expect(html).toContain("timeline_engine: replay");
    expectInert(html);
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("⟨U+202E⟩");
  });

  it("words the media hash states without a verdict", () => {
    expect(render(<MediaHashStatusView status="matched" />)).toContain("Consistent with the hash stored at acquisition");
    expect(render(<MediaHashStatusView status="absent" />)).toContain("corrupted chunks cannot be detected");
    expect(render(<MediaHashStatusView status={null} />)).toContain("Not reported");
  });

  it("shows a partial run as partial, with skip reasons", () => {
    const html = render(<StageStrip summary={SUMMARY} />);
    expect(html).toContain("Partial result");
    expect(html).toContain("not enough job time left");
    expect(html).toContain("Truncated");
    expect(html).toContain("Missing rows are not evidence of absence");
  });
});

describe("partitions", () => {
  it("explains encrypted and unsupported file systems and keeps sectors exact", () => {
    const parts = [
      { id: "p1", index: 1, start_sector: "2048", length_sectors: "36028797018963968", description: SCRIPT, vs_flags: "alloc", fs_type: "ntfs", fs_status: "ok", fs_label: RTLO, fs_uuid: null, block_size: 4096, os: "windows", os_name: JS_URL, error_code: null, counts: { files: 10 } },
      { id: "p2", index: 2, start_sector: "9000", length_sectors: "100", description: null, vs_flags: "alloc", fs_type: null, fs_status: "encrypted", fs_label: null, fs_uuid: null, block_size: null, os: "none", os_name: null, error_code: null, counts: {} },
    ] as unknown as DiskPartition[];
    const html = render(<PartitionTable partitions={parts} sectorSize={512} />);
    expect(html).toContain("looks encrypted");
    expect(html).toContain("2,048");
    expectInert(html);
  });
});

describe("file browser", () => {
  it("renders a hostile file row as inert text", () => {
    const html = render(<FileRow file={file() as DiskFile} onOpen={noop} />);
    expectInert(html);
    expect(html).toContain("⟨U+202E⟩");
    expect(html).toContain("Known (reference set)");
    expect(html).toContain("Hard-linked");
    expect(html).not.toContain("<a ");
  });

  it("labels FAT times as local time with an unknown zone", () => {
    const html = render(<FileRow file={file({ time_basis: "local_unknown" }) as DiskFile} onOpen={noop} />);
    expect(html).toContain("local time, zone unknown");
    expect(html).toContain("2026-01-01 10:00:00");
  });

  it("shows the detail with other names, hashes and a disabled export with the reason", () => {
    const html = render(
      <FileDetailView
        file={file()}
        events={[]}
        findings={[]}
        canExport
        inBatch={false}
        exportPending={false}
        onExport={noop}
        onToggleBatch={noop}
        onSeenIn={noop}
      />,
    );
    expect(html).toContain("Other names (hard links)");
    expect(html).toContain("18,446,744,073,709,551,615-2");
    expect(html).toContain("protected secret store");
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Export this file<\/button>/);
    expect(html).toContain("Known software, not necessarily benign");
    expect(html).toContain("not a conclusion");
    expectInert(html);
  });

  it("offers Export for an exportable file", () => {
    const html = render(
      <FileDetailView
        file={file({ exportable: true, not_exportable_reason: null })}
        events={null}
        findings={[{ id: "f1", title: SCRIPT, severity: "medium" }]}
        canExport
        inBatch
        exportPending={false}
        onExport={noop}
        onToggleBatch={noop}
        onSeenIn={noop}
      />,
    );
    expect(html).toContain("re-downloads and re-verifies the whole image");
    expect(html).toContain("Remove from export batch");
    expect(html).not.toMatch(/<button[^>]*disabled=""[^>]*>Export this file<\/button>/);
    expectInert(html);
  });

  it("renders only a window of a 500 000-row list", () => {
    const items = Array.from({ length: 500_000 }, (_, i) => i);
    const html = render(
      <WindowedRows items={items} rowHeight={40} height={400} label="rows" header={<div />} renderRow={(i) => <span className="r">{i}</span>} />,
    );
    expect((html.match(/class="r"/g) ?? []).length).toBeLessThan(40);
    expect(html).toContain("height:20000000px");
  });
});

describe("timeline", () => {
  it("renders merged rows as text", () => {
    const row = { ts: "2026-01-01T00:00:00Z", source: "event", kind: "evtx", description: SCRIPT, path: JS_URL, file_id: null, event_id: "e1" } as TimelineItem;
    const html = render(<TimelineRow item={row} />);
    expectInert(html);
    expect(html).toContain("Windows event logs");
  });

  it("labels the histogram as covering the loaded rows only", () => {
    const html = render(<HourHistogram items={[{ ts: "2026-01-01T00:00:00Z" }, { ts: "2026-01-01T02:00:00Z" }]} loadedAll={false} />);
    expect(html).toContain("loaded rows");
    expect(html).toContain("scroll to load more");
    expect((html.match(/<li /g) ?? []).length).toBe(3);
  });
});

describe("exports", () => {
  const base = {
    id: "77777777-7777-4777-8777-777777777777",
    export_job_id: JOB,
    source_job_id: JOB,
    file_id: "66666666-6666-4666-8666-666666666666",
    path: `/x/${SCRIPT}`,
    size: 2048,
    worker_sha256: "a".repeat(64),
    evidence_id: null,
    error_code: null,
    created_at: "2026-01-01T00:00:00Z",
    promoted_at: null,
  };

  it("shows a ready export's worker hash as unverified and offers Add to case", () => {
    const html = render(
      <ExportRowView orgId={ORG} item={{ ...base, state: "ready" } as DiskExport} canPromote promotePending={false} promoteError={null} onPromote={noop} />,
    );
    expect(html).toContain("sha256 reported by the worker (unverified)");
    expect(html).toContain("Add to case as evidence");
    expectInert(html);
  });

  it("says an expired export was deleted after its TTL, and links promoted evidence", () => {
    expect(
      render(<ExportRowView orgId={ORG} item={{ ...base, state: "expired" } as DiskExport} canPromote promotePending={false} promoteError={null} onPromote={noop} />),
    ).toContain("deleted after its retention period");
    const promoted = render(
      <ExportRowView
        orgId={ORG}
        item={{ ...base, state: "promoted", evidence_id: EVIDENCE } as DiskExport}
        canPromote
        promotePending={false}
        promoteError={null}
        onPromote={noop}
      />,
    );
    expect(promoted).toContain(`href="/o/${ORG}/evidence/${EVIDENCE}"`);
  });

  it("labels the interop downloads TLP:RED while restricted, without links built from rows", () => {
    const html = render(<InteropDownloads restricted pending={null} onDownload={noop} />);
    expect(html).toContain('data-testid="interop-tlp"');
    expect(html).toContain("for mactime");
    expect(html).toContain("Timesketch");
    expect(html).toContain("Autopsy hash-set import");
    expect(html).not.toContain("href=");
    expect(render(<InteropDownloads restricted={false} pending={null} onDownload={noop} />)).not.toContain("interop-tlp");
  });
});

describe("sensitivity", () => {
  const segments = [
    { evidenceId: EVIDENCE, filename: "laptop.E01" },
    { evidenceId: "55555555-5555-4555-8555-555555555555", filename: SCRIPT },
  ];

  it("offers the batch release to admins and tells others to ask an admin", () => {
    const props = { orgId: ORG, jobId: JOB, evidenceId: EVIDENCE, investigationId: INV, segments, restriction: "restricted" as const };
    const admin = render(<DiskSensitivityBanner {...props} canRelease />);
    expect(admin).toContain("Release…");
    expect(admin).toContain("Restricted disk image");
    const analyst = render(<DiskSensitivityBanner {...props} canRelease={false} />, "analyst");
    expect(analyst).not.toContain("Release…");
    expect(analyst).toContain("ask an admin");
    expect(render(<DiskSensitivityBanner {...props} restriction="none" canRelease />)).toBe("");
  });

  it("asks for the acknowledgement and a reason, naming the segment count", () => {
    const html = render(<DiskReleaseForm segments={segments} pending={false} error={null} onSubmit={noop} onCancel={noop} />);
    expect(html).toContain(DISK_RELEASE_ACK);
    expect(html).toContain("Release all 2 segments");
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Release all 2 segments<\/button>/);
  });

  it("offers clearing the flags segment by segment after a release", () => {
    const html = render(<ClearFlagsStep orgId={ORG} segments={segments} investigationId={INV} />);
    expect((html.match(/Clear AI \/ TI exclusions/g) ?? []).length).toBe(2);
    expectInert(html);
  });

  it("hides Enrich on the IOC tab while restricted", () => {
    const reason = "Threat-intel enrichment is off: this disk image is restricted.";
    const html = render(<IocsTab orgId={ORG} jobId={JOB} source="disk image" enrichDisabledReason={reason} />);
    expect(html).not.toContain(">Enrich<");
  });
});

describe("upload option and run dialog", () => {
  it("explains the TLP:RED default and that no analysis runs automatically", () => {
    const on = render(<DiskUploadOption value onChange={noop} />);
    expect(on).toContain("Disk image (segment)");
    expect(on).toContain(DISK_UPLOAD_NOTICE.slice(0, 40));
    expect(on).toContain("No analysis runs automatically");
    expect(render(<DiskUploadOption value={false} onChange={noop} />)).toContain("restricted from the start");
  });

  const evidence = (id: string, name: string, size = 1_000_000) =>
    ({
      id,
      investigation_id: INV,
      original_filename: name,
      detected_mime: "application/octet-stream",
      detected_description: "data",
      size_bytes: size,
      status: "stored",
      description: "",
      uploaded_by: ORG,
      uploaded_by_name: "A",
      uploaded_at: "2026-01-01T00:00:00Z",
      hashes: {},
      purged_at: null,
    }) as unknown as Schemas["EvidenceOut"];

  it("pre-selects the sibling segments in natural order, this evidence first", () => {
    const current = evidence("e1", "disk.E01");
    const all = [evidence("e10", "disk.E10"), current, evidence("e2", "disk.E02"), evidence("x", "notes.txt")];
    expect(initialSegments(current, all).map((e) => e.original_filename)).toEqual(["disk.E01", "disk.E02", "disk.E10"]);
    const html = render(<RunDiskForm evidence={current} candidates={all} pending={false} error={null} onSubmit={noop} onCancel={noop} />);
    expect(html.indexOf("disk.E02")).toBeLessThan(html.indexOf("disk.E10"));
    expect(html).toContain("Move segment 2 down");
    expect(html).toContain("re-verifies the whole segment set");
    expect(html).toContain("All selected segments become restricted");
    expect(html).toContain("Order matters for split raw");
  });

  it("blocks a set above the image limit", () => {
    const current = evidence("e1", "disk.001", 9 * 1024 ** 3);
    const html = render(
      <SegmentPicker currentId="e1" candidates={[current]} selected={[current, evidence("e2", "disk.002", 9 * 1024 ** 3)]} onChange={noop} />,
    );
    expect(html).toContain("too large");
    const form = render(
      <RunDiskForm
        evidence={current}
        candidates={[current, evidence("e2", "disk.002", 9 * 1024 ** 3)]}
        pending={false}
        error={null}
        onSubmit={noop}
        onCancel={noop}
      />,
    );
    expect(form).toMatch(/<button[^>]*disabled=""[^>]*>Run disk analysis<\/button>/);
  });

  it("renders hostile segment names inert", () => {
    const current = evidence("e1", RTLO);
    const html = render(<SegmentPicker currentId="e1" candidates={[current, evidence("e2", SCRIPT)]} selected={[current]} onChange={noop} />);
    expectInert(html);
  });
});

describe("derived evidence badge", () => {
  it("links back to the source job with inert path text", () => {
    const html = render(<DerivedBadgeView orgId={ORG} sourceEvidenceId={EVIDENCE} origin={{ jobId: JOB, partition: 1, path: `${JS_URL}/${SCRIPT}` }} />);
    expect(html).toContain(`href="/o/${ORG}/forensics/${JOB}?tab=exports"`);
    expect(html).toContain("partition 1");
    expectInert(html);
    const fallback = render(<DerivedBadgeView orgId={ORG} sourceEvidenceId={EVIDENCE} origin={null} />);
    expect(fallback).toContain(`href="/o/${ORG}/evidence/${EVIDENCE}"`);
  });
});
