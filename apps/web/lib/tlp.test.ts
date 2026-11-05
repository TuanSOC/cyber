import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

import { TLP_COLOURS, TLP_LABELS, TLP_ORDER, TLP_VALUES, isDowngrade, isTlp, needsDistribution } from "@/lib/tlp";

const OPENAPI = path.resolve(__dirname, "../../../packages/contracts/openapi.json");

describe("tlp", () => {
  it("matches the OpenAPI enum and the contract order", () => {
    const spec = JSON.parse(readFileSync(OPENAPI, "utf8"));
    expect(spec.components.schemas.TLP.enum).toEqual([...TLP_VALUES]);
    expect(TLP_VALUES.map((t) => TLP_ORDER[t])).toEqual([0, 1, 2, 3, 4]);
  });

  it("labels and colours", () => {
    expect(TLP_LABELS.amber_strict).toBe("TLP:AMBER+STRICT");
    expect(TLP_COLOURS.red).toBe("#FF2B2B");
    expect(TLP_COLOURS.amber_strict).toBe(TLP_COLOURS.amber);
  });

  it("downgrades and distribution", () => {
    expect(isDowngrade("green", "amber")).toBe(true);
    expect(isDowngrade("red", "amber")).toBe(false);
    expect(isDowngrade("amber", "amber")).toBe(false);
    expect(needsDistribution("red")).toBe(true);
    expect(needsDistribution("amber_strict")).toBe(true);
    expect(needsDistribution("amber")).toBe(false);
    expect(isTlp("amber+strict")).toBe(false);
    expect(isTlp("amber_strict")).toBe(true);
  });
});

describe("vis rules", () => {
  it("is a byte-identical copy of the py-jobs table (RT24)", () => {
    const web = readFileSync(path.resolve(__dirname, "vis-rules.json"));
    const jobs = readFileSync(path.resolve(__dirname, "../../../packages/py-jobs/src/cyberlab_jobs/vis_rules.json"));
    expect(web.equals(jobs)).toBe(true);
    const rules = JSON.parse(web.toString("utf8"));
    const covered = (cp: number) => rules.ranges.some(([a, b]: [number, number]) => a <= cp && cp <= b);
    expect(covered(0x202e)).toBe(true);
    expect(covered(0x200b)).toBe(true);
    expect(covered(0x0a)).toBe(false);
    expect(covered(0x41)).toBe(false);
  });
});
