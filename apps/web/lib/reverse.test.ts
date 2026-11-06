import { describe, expect, it } from "vitest";

import { deepLinkHref } from "@/lib/ai";
import { ApiError } from "@/lib/api";
import {
  EMPTY_FILTERS,
  HEAVY_BUSY,
  type ReFunction,
  compareAddress,
  decompileReason,
  formatAddress,
  functionHref,
  functionQuery,
  parseAddress,
  parseReLocation,
  reJobFacts,
  reOffered,
  reRunErrorText,
  sortFunctions,
} from "@/lib/reverse";

const ORG = "11111111-1111-4111-8111-111111111111";
const JOB = "6a1f0c1e-8d6b-4c55-9d9e-0d1b6f5a1001";

function fn(over: Partial<ReFunction>): ReFunction {
  return {
    id: "f",
    entry: "0x1000",
    rva: "0x1000",
    name: "f",
    name_source: "symbol",
    size: 10,
    is_thunk: false,
    is_external: false,
    is_library: false,
    signature: null,
    calling_convention: null,
    instructions: 1,
    callers: 0,
    callees: 0,
    decompile_status: "not_selected",
    priority_rank: null,
    priority_reason: null,
    capabilities: 0,
    ...over,
  };
}

const params = (query: string) => new URLSearchParams(query);

describe("addresses (BigInt, never Number)", () => {
  it("keeps 64-bit precision", () => {
    expect(formatAddress("0xFFFFFFFFFFFFFFFF")).toBe("0xffffffffffffffff");
    expect(formatAddress("18446744073709551615")).toBe("0xffffffffffffffff");
    // 2**53 + 1 would be rounded by Number.
    expect(formatAddress("9007199254740993")).toBe("0x20000000000001");
    expect(parseAddress("0x1_000")).toBeNull();
    expect(parseAddress("18446744073709551616")).toBeNull();
    expect(formatAddress("not an address")).toBe("—");
    expect(compareAddress("0xffffffffffffff00", "0xffffffffffffff01")).toBe(-1);
  });
});

describe("location and deep links", () => {
  it("opens a function from ?fn=&tab=facts|code", () => {
    expect(parseReLocation(params("tab=code&fn=0x1400011E0"))).toEqual({
      tab: "functions",
      fn: "0x1400011e0",
      functionTab: "code",
      ref: null,
    });
    expect(parseReLocation(params("fn=0x10")).functionTab).toBe("facts");
    expect(parseReLocation(params("tab=strings&ref=abc")).tab).toBe("strings");
    expect(parseReLocation(params("tab=<script>")).tab).toBe("overview");
    expect(parseReLocation(params("fn=javascript:alert(1)")).fn).toBeNull();
  });

  it("builds function links from ids and hex only", () => {
    expect(functionHref(`/o/${ORG}`, JOB, "0x1400011E0", "code")).toBe(
      `/o/${ORG}/reverse-engineering/${JOB}?tab=code&fn=0x1400011e0`,
    );
    expect(functionHref(`/o/${ORG}`, "../x", "0x1")).toBeNull();
    expect(functionHref(`/o/${ORG}`, JOB, "main")).toBeNull();
  });

  it("maps G / Q citation descriptors to the function view", () => {
    expect(deepLinkHref(ORG, { route: "reverse-engineering", job_id: JOB, tab: "facts", ref: "0x1400011e0" } as never)).toBe(
      `/o/${ORG}/reverse-engineering/${JOB}?fn=0x1400011e0&tab=facts`,
    );
    expect(deepLinkHref(ORG, { route: "reverse-engineering", job_id: JOB, tab: "code", ref: "0x10" } as never)).toBe(
      `/o/${ORG}/reverse-engineering/${JOB}?fn=0x10&tab=code`,
    );
    // A ref that is not a hex entry never becomes a link.
    expect(deepLinkHref(ORG, { route: "reverse-engineering", job_id: JOB, tab: "code", ref: "x&y=1" } as never)).toBeNull();
    expect(deepLinkHref(ORG, { route: "reverse-engineering", job_id: JOB, tab: "findings", ref: null } as never)).toBe(
      `/o/${ORG}/reverse-engineering/${JOB}?tab=findings`,
    );
  });
});

describe("filters, sort and wording", () => {
  it("sends only the set filters", () => {
    expect(functionQuery(EMPTY_FILTERS)).toEqual({});
    expect(
      functionQuery({ ...EMPTY_FILTERS, q: "  inject ", decompiled: false, hasCapability: true, referencesIocString: true }),
    ).toEqual({ q: "inject", decompiled: false, has_capability: true, references_ioc_string: true });
  });

  it("sorts loaded rows by rank, address, size or name", () => {
    const rows = [
      fn({ id: "a", entry: "0x30", size: 5, name: "b", priority_rank: 2 }),
      fn({ id: "b", entry: "0x10", size: 50, name: "c", priority_rank: null }),
      fn({ id: "c", entry: "0x20", size: 20, name: "a", priority_rank: 1 }),
    ];
    expect(sortFunctions(rows, "rank").map((r) => r.id)).toEqual(["c", "a", "b"]);
    expect(sortFunctions(rows, "entry").map((r) => r.id)).toEqual(["b", "c", "a"]);
    expect(sortFunctions(rows, "size").map((r) => r.id)).toEqual(["b", "c", "a"]);
    expect(sortFunctions(rows, "name").map((r) => r.id)).toEqual(["c", "a", "b"]);
  });

  it("explains why a function was (not) decompiled", () => {
    expect(decompileReason(fn({ decompile_status: "ok", priority_reason: "capability" }), "full")).toContain("capa capability");
    expect(decompileReason(fn({ decompile_status: "not_selected", is_thunk: true }), "full")).toContain("thunks");
    expect(decompileReason(fn({ decompile_status: "not_selected" }), "full")).toContain("Decompile this function");
    expect(decompileReason(fn({ decompile_status: "not_selected" }), "quick")).toContain("never decompiles");
  });

  it("offers RE for succeeded full static jobs of PE / ELF only", () => {
    const base = { analyzer: "static", status: "succeeded", profile: "full" };
    expect(reOffered({ ...base, summary: { file_format: "pe" } })).toBe(true);
    expect(reOffered({ ...base, summary: { file_format: "elf" } })).toBe(true);
    expect(reOffered({ ...base, summary: { file_format: "other" } })).toBe(false);
    expect(reOffered({ ...base, profile: "av", summary: { file_format: "pe" } })).toBe(false);
    expect(reOffered({ ...base, status: "running", summary: { file_format: "pe" } })).toBe(false);
    expect(reOffered({ ...base, analyzer: "reverse", summary: { file_format: "pe" } })).toBe(false);
  });

  it("explains a busy heavy-analysis slot without a queue position (RT2)", () => {
    const busy = new ApiError(429, "too_many_active_jobs", "x", undefined, 60, { reason: "heavy_analysis_busy" });
    expect(reRunErrorText(busy)).toBe(HEAVY_BUSY);
    expect(reRunErrorText(busy)).not.toMatch(/queue|position/i);
    expect(reRunErrorText(new ApiError(409, "static_analysis_required", "x"))).toContain("static analysis");
  });

  it("reads job facts defensively", () => {
    expect(reJobFacts({ summary: { counts: { functions: 31 }, engine: "ghidra" } })).toEqual({ functions: 31, engine: "ghidra" });
    expect(reJobFacts({ summary: { counts: { functions: "31" }, engine: "<b>" } })).toEqual({ functions: null, engine: null });
    expect(reJobFacts({})).toEqual({ functions: null, engine: null });
  });
});
