import { describe, expect, it } from "vitest";

import { ApiError } from "@/lib/api";
import {
  INTEROP_EXPORTS,
  derivedOrigin,
  exportSelection,
  fileExportErrorText,
  interopExportPath,
  isInteropExport,
  rememberExports,
  rememberedExports,
} from "@/lib/disk-exports";

const ORG = "11111111-1111-4111-8111-111111111111";
const JOB = "6a1f0c1e-8d6b-4c55-9d9e-0d1b6f5a1001";
const ID = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;

function memoryStore() {
  const data = new Map<string, string>();
  return { getItem: (k: string) => data.get(k) ?? null, setItem: (k: string, v: string) => void data.set(k, v), data };
}

describe("interop downloads", () => {
  it("builds paths from UUIDs and the fixed catalog only", () => {
    expect(interopExportPath(ORG, JOB, "bodyfile")).toBe(`/api/v1/orgs/${ORG}/analyses/${JOB}/disk/exports/bodyfile`);
    expect(interopExportPath(ORG, JOB, "../../evidence")).toBeNull();
    expect(interopExportPath(ORG, JOB, "javascript:alert(1)")).toBeNull();
    expect(interopExportPath(ORG, "not-a-uuid", "bodyfile")).toBeNull();
    expect(INTEROP_EXPORTS.map((e) => e.name)).toEqual(["bodyfile", "timeline.csv", "timeline.jsonl", "notable-hashes.txt"]);
    expect(isInteropExport("timeline.csv")).toBe(true);
  });

  it("says what each download is for", () => {
    const purpose = Object.fromEntries(INTEROP_EXPORTS.map((e) => [e.name, e.purpose]));
    expect(purpose.bodyfile).toContain("mactime");
    expect(purpose["timeline.csv"]).toContain("Timesketch");
    expect(purpose["notable-hashes.txt"]).toContain("one per line");
  });
});

describe("file export requests", () => {
  it("keeps distinct UUIDs, at most 20", () => {
    const ids = Array.from({ length: 25 }, (_, i) => ID(i));
    expect(exportSelection([ID(1), ID(1), "x", ID(2)])).toEqual([ID(1), ID(2)]);
    expect(exportSelection(ids)).toHaveLength(20);
  });

  it("explains refusals and failed rows", () => {
    expect(fileExportErrorText(new ApiError(409, "disk_export_expired", "x"))).toContain("expired");
    expect(fileExportErrorText(new ApiError(501, "not_implemented", "x"))).toContain("not available");
    expect(fileExportErrorText("export_hash_mismatch")).toContain("did not match");
    expect(fileExportErrorText("odd_code")).toBe("Failed (odd_code).");
  });

  it("remembers the requested export ids per job (best effort)", () => {
    const store = memoryStore();
    expect(rememberedExports(JOB, store)).toEqual([]);
    rememberExports(JOB, [ID(1)], store);
    expect(rememberExports(JOB, [ID(2), ID(1), "nope"], store)).toEqual([ID(2), ID(1)]);
    store.setItem(`cyberlab:disk-exports:${JOB}`, "{not json");
    expect(rememberedExports(JOB, store)).toEqual([]);
    expect(rememberedExports(JOB, null)).toEqual([]);
    const throwing = { getItem: () => { throw new Error("blocked"); }, setItem: () => { throw new Error("blocked"); } };
    expect(rememberedExports(JOB, throwing)).toEqual([]);
    expect(rememberExports(JOB, [ID(3)], throwing)).toEqual([ID(3)]);
  });
});

describe("derived evidence origin", () => {
  it("reads the derived_from custody event defensively", () => {
    expect(
      derivedOrigin([
        { action: "uploaded", details: {} },
        { action: "derived_from", details: { source_job_id: JOB, partition_index: 2, path: "/Users/x/evil.exe" } },
      ]),
    ).toEqual({ jobId: JOB, partition: 2, path: "/Users/x/evil.exe" });
    expect(derivedOrigin([{ action: "derived_from", details: { source_job_id: "javascript:alert(1)", partition_index: -1 } }])).toEqual({
      jobId: null,
      partition: null,
      path: null,
    });
    expect(derivedOrigin([{ action: "uploaded" }])).toBeNull();
    expect(derivedOrigin(undefined)).toBeNull();
  });
});
