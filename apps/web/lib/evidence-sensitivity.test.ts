import { describe, expect, it } from "vitest";

import { SOURCE_LABELS, genericSensitivity } from "./evidence-sensitivity";

describe("generic evidence sensitivity (M9, RT2)", () => {
  it("shows disk and derived evidence only (memory keeps the M8 badge)", () => {
    expect(genericSensitivity({ state: "restricted", source: "disk" })).toEqual({ state: "restricted", source: "disk" });
    expect(genericSensitivity({ state: "released", source: "derived" })).toEqual({ state: "released", source: "derived" });
    expect(genericSensitivity({ state: "restricted", source: "memory" })).toBeNull();
    expect(genericSensitivity({ state: "none", source: "disk" })).toBeNull();
    expect(genericSensitivity(null)).toBeNull();
    expect(genericSensitivity(undefined)).toBeNull();
  });

  it("labels every source", () => {
    expect(Object.keys(SOURCE_LABELS).sort()).toEqual(["derived", "disk", "memory"]);
  });
});
