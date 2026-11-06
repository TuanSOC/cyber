import { describe, expect, it } from "vitest";

import { ApiError } from "@/lib/api";
import {
  DISK_MAX_IMAGE_BYTES_DEFAULT,
  checkSegments,
  diskEnrichDisabledReason,
  diskJobFacts,
  diskRestriction,
  diskRunErrorText,
  diskSummaryCounts,
  diskUploadErrorText,
  exportRefusalText,
  extTerm,
  fileQuery,
  formatU64,
  formatU64Bytes,
  hasHiddenCharacters,
  hashTerm,
  inertText,
  isSegmentName,
  moveSegment,
  naturalCompare,
  nextOffset,
  parseDiskTab,
  parseU64,
  pastOffsetCap,
  pathMarkers,
  sectorBytes,
  segmentsInvalidText,
  siblingSegments,
  sortByName,
  stageCompleteness,
  stageReasonText,
  visibleFlags,
  windowRange,
} from "@/lib/disk";

const ev = (id: string, name: string, size = 100) => ({ id, original_filename: name, size_bytes: size });
const names = (items: readonly { original_filename: string }[]) => items.map((i) => i.original_filename);

describe("natural segment order", () => {
  it("orders EWF segments numerically, then the letter extensions after .E99", () => {
    const sorted = sortByName([ev("a", "case.E10"), ev("b", "case.E02"), ev("c", "case.EAA"), ev("d", "case.E01"), ev("e", "case.E99")]);
    expect(names(sorted)).toEqual(["case.E01", "case.E02", "case.E10", "case.E99", "case.EAA"]);
  });

  it("orders split raw by number and split suffixes alphabetically", () => {
    expect(names(sortByName([ev("1", "disk.010"), ev("2", "disk.002"), ev("3", "disk.001")]))).toEqual(["disk.001", "disk.002", "disk.010"]);
    expect(names(sortByName([ev("1", "x.ba"), ev("2", "x.ab"), ev("3", "x.aa")]))).toEqual(["x.aa", "x.ab", "x.ba"]);
  });

  it("is total and case-insensitive on mixed names (ties by raw name)", () => {
    expect(naturalCompare("Image.e01", "image.E02")).toBeLessThan(0);
    expect(naturalCompare("a.E01", "a.E01")).toBe(0);
    expect(naturalCompare("A.E01", "a.E01")).not.toBe(0);
    expect(naturalCompare("disk.001", "disk.aa")).toBeLessThan(0);
    // Digit runs longer than 2^53 do not overflow.
    expect(naturalCompare("x.99999999999999999999", "x.100000000000000000000")).toBeLessThan(0);
  });

  it("recognizes segment names", () => {
    expect(isSegmentName("case.E01")).toBe(true);
    expect(isSegmentName("disk.001")).toBe(true);
    expect(isSegmentName("disk.aa")).toBe(true);
    expect(isSegmentName("report.pdf")).toBe(false);
  });

  it("guesses the sibling segments of the same set, current included", () => {
    const current = ev("1", "laptop.E01");
    const all = [current, ev("3", "laptop.E03"), ev("2", "laptop.E02"), ev("4", "laptop.001"), ev("5", "other.E02"), ev("6", "notes.txt")];
    expect(names(siblingSegments(current, all))).toEqual(["laptop.E01", "laptop.E02", "laptop.E03"]);
    expect(names(siblingSegments(ev("9", "single.raw"), all))).toEqual(["single.raw"]);
  });

  it("moves segments with the first one pinned", () => {
    const list = ["first", "b", "c"];
    expect(moveSegment(list, 2, -1)).toEqual(["first", "c", "b"]);
    expect(moveSegment(list, 1, -1)).toEqual(list); // cannot replace the pinned first segment
    expect(moveSegment(list, 0, 1)).toEqual(list);
    expect(moveSegment(list, 2, 1)).toEqual(list);
  });
});

describe("segment set checks", () => {
  it("blocks a set above DISK_MAX_IMAGE_BYTES and one not starting with this evidence", () => {
    const big = DISK_MAX_IMAGE_BYTES_DEFAULT / 2 + 1;
    const over = checkSegments([ev("1", "a.E01", big), ev("2", "a.E02", big)], "1");
    expect(over.overSet).toBe(true);
    expect(over.ok).toBe(false);
    expect(checkSegments([ev("2", "a.E02"), ev("1", "a.E01")], "1").ok).toBe(false);
    const fine = checkSegments([ev("1", "a.E01"), ev("2", "a.E02")], "1");
    expect(fine).toMatchObject({ ok: true, total: 200, notFirstByName: false });
  });

  it("flags a current evidence that is not first by name", () => {
    expect(checkSegments([ev("2", "a.E02"), ev("1", "a.E01")], "2").notFirstByName).toBe(true);
  });

  it("explains disk_segments_invalid reasons with the offending segment", () => {
    expect(segmentsInvalidText("other_investigation", 1, ["a.E01", "b.E02"])).toBe(
      "A segment belongs to another case: every segment must be evidence of this case. (segment 2: b.E02)",
    );
    expect(segmentsInvalidText("weird", null)).toBe("The segment set was refused.");
    const error = new ApiError(422, "disk_segments_invalid", "x", undefined, undefined, { reason: "purged", ordinal: 0 });
    expect(diskRunErrorText(error, ["case.E01"])).toContain("retention policy. (segment 1: case.E01)");
    expect(diskRunErrorText(new ApiError(413, "disk_image_set_too_large", "x"))).toContain("DISK_MAX_IMAGE_BYTES");
    expect(diskRunErrorText(new ApiError(409, "analysis_active", "x"))).toContain("already queued or running");
  });

  it("maps the disk upload refusals", () => {
    expect(diskUploadErrorText(new ApiError(413, "disk_image_too_large", "x"))).toContain("DISK_MAX_UPLOAD_BYTES");
    expect(diskUploadErrorText(new ApiError(507, "insufficient_storage", "x"))).toContain("free space");
    expect(diskUploadErrorText(new ApiError(400, "other", "x"))).toBeNull();
    expect(diskUploadErrorText(new Error("x"))).toBeNull();
  });
});

describe("inert text", () => {
  it("makes bidi and control characters visible", () => {
    const rtlo = "invoice‮txt.exe";
    expect(inertText(rtlo)).toBe("invoice⟨U+202E⟩txt.exe");
    expect(hasHiddenCharacters(rtlo)).toBe(true);
    expect(hasHiddenCharacters("plain.txt")).toBe(false);
    expect(inertText("a\u0000b\nc")).toBe("a⟨U+0000⟩b⟨U+000A⟩c");
    expect(inertText("x".repeat(10), 4)).toBe("xxxx…");
    expect(inertText(null)).toBe("");
  });
});

describe("unsigned 64-bit text", () => {
  it("parses and formats exactly above 2^53", () => {
    expect(parseU64("18446744073709551615")).toBe(BigInt("18446744073709551615"));
    expect(parseU64("18446744073709551616")).toBeNull();
    expect(parseU64("-1")).toBeNull();
    expect(parseU64(2 ** 60)).toBeNull(); // an unsafe JSON number is not trusted
    expect(formatU64("9007199254740993")).toBe("9,007,199,254,740,993");
    expect(formatU64(undefined)).toBe("—");
  });

  it("formats byte counts and sector products", () => {
    expect(formatU64Bytes("17179869184")).toBe("16.0 GiB");
    expect(formatU64Bytes("18446744073709551615")).toMatch(/EiB$/);
    expect(sectorBytes("2048", 512)).toBe("1048576");
    expect(sectorBytes("36028797018963968", 4096)).toBe((BigInt("36028797018963968") * BigInt(4096)).toString());
    expect(sectorBytes("x", 512)).toBeNull();
  });
});

describe("file filters", () => {
  it("hides known files by default and drops invalid hashes", () => {
    expect(fileQuery({ hideKnown: true })).toEqual({ include_known: false });
    expect(fileQuery({ hideKnown: false, hash: "zz" })).toEqual({ include_known: true });
    expect(fileQuery({ hideKnown: true, hash: "D41D8CD98F00B204E9800998ECF8427E", flag: "deleted", partition: 2 })).toEqual({
      include_known: false,
      hash: "d41d8cd98f00b204e9800998ecf8427e",
      flag: "deleted",
      partition: 2,
    });
    expect(hashTerm("a".repeat(40))).toBe("a".repeat(40));
    expect(hashTerm("a".repeat(41))).toBeNull();
    expect(extTerm(" .exe ")).toBe("exe");
    expect(extTerm("")).toBeUndefined();
  });

  it("marks lossy and cut paths and hides the allocated flag", () => {
    expect(pathMarkers({ flags: ["allocated", "name_lossy", "path_truncated"] })).toHaveLength(2);
    expect(visibleFlags(["allocated", "deleted"])).toEqual(["deleted"]);
  });

  it("explains why a file cannot be exported", () => {
    expect(exportRefusalText("never_collected")).toContain("never exported");
    expect(exportRefusalText("too_large")).toContain("64");
    expect(exportRefusalText(null)).toBe("This file cannot be exported.");
  });
});

describe("windowing and paging", () => {
  it("renders only the visible slice with overscan", () => {
    expect(windowRange(0, 400, 40, 500_000, 2)).toEqual({ start: 0, end: 13 });
    expect(windowRange(40 * 1000, 400, 40, 500_000, 2)).toEqual({ start: 998, end: 1013 });
    expect(windowRange(0, 400, 40, 0)).toEqual({ start: 0, end: 0 });
  });

  it("pages by offset up to the API's offset cap", () => {
    expect(nextOffset(100, 250)).toBe(100);
    expect(nextOffset(250, 250)).toBeUndefined();
    expect(nextOffset(10_000, 500_000)).toBe(10_000);
    expect(nextOffset(10_100, 500_000)).toBeUndefined();
    expect(pastOffsetCap(10_100, 500_000)).toBe(true);
    expect(pastOffsetCap(200, 200)).toBe(false);
  });
});

describe("summary facts and stages", () => {
  it("reads the job summary defensively", () => {
    const facts = diskJobFacts({
      summary: { image: { format: "ewf", segments: 3, media_size: 17179869184, media_hash_status: "matched" }, counts: { partitions: 2, findings: 4 } },
    });
    expect(facts).toMatchObject({ format: "ewf", segments: 3, mediaSize: "17179869184", partitions: 2, findings: 4, mediaHashStatus: "matched" });
    expect(diskJobFacts({ summary: { image: { format: "<script>", media_hash_status: "verified" } } })).toMatchObject({
      format: null,
      mediaHashStatus: null,
    });
    expect(diskJobFacts({ summary: null }).segments).toBeNull();
    expect(diskSummaryCounts({ files: 10, partitions: 1, bogus: 3 }).map((c) => c.key)).toEqual(["partitions", "files"]);
  });

  it("never shows a partial run as complete", () => {
    const stages = [
      { stage: "walk", status: "ok", rows: 1, truncated: false, duration_ms: 1 },
      { stage: "timeline", status: "skipped", reason: "deadline", rows: 0, truncated: false, duration_ms: 0 },
    ];
    const state = stageCompleteness({ stages, truncated: false } as never);
    expect(state.complete).toBe(false);
    expect(state.incomplete).toHaveLength(1);
    expect(stageReasonText("deadline")).toBe("not enough job time left");
    expect(stageCompleteness({ stages: [stages[0]], truncated: true } as never).complete).toBe(false);
    expect(stageCompleteness({ stages: [stages[0]], truncated: false } as never).complete).toBe(true);
  });

  it("parses the tab param", () => {
    expect(parseDiskTab("files")).toBe("files");
    expect(parseDiskTab("processes")).toBe("overview");
    expect(parseDiskTab(null)).toBe("overview");
  });
});

describe("sensitivity of a disk job", () => {
  it("is restricted when any segment is, unknown while any is loading", () => {
    expect(diskRestriction(["released", "restricted"])).toBe("restricted");
    expect(diskRestriction(["released", undefined])).toBeNull();
    expect(diskRestriction(["released", "none"])).toBe("released");
    expect(diskRestriction(["none", "none"])).toBe("none");
    expect(diskRestriction([])).toBeNull();
  });

  it("hides Enrich while restricted, TI-excluded or unknown", () => {
    expect(diskEnrichDisabledReason("restricted", false)).toContain("restricted");
    expect(diskEnrichDisabledReason("released", true)).toContain("share policy");
    expect(diskEnrichDisabledReason(null, false)).toContain("unavailable");
    expect(diskEnrichDisabledReason("released", false)).toBeUndefined();
  });
});

describe("segment names that are not segments", () => {
  it("does not take common file types for segments", () => {
    expect(isSegmentName("setup.exe")).toBe(false);
    expect(isSegmentName("backup.gz")).toBe(false);
  });
});
