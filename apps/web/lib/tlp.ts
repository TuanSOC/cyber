/**
 * TLP 2.0 (FIRST) for the case and report views (M6, shared by phases 6 and 7). Mirrors
 * `cyberlab_jobs.report` (TLP, TLP_ORDER, TLP_LABELS, TLP_COLOURS, TLP_DEFINITIONS); a test
 * keeps the values in sync with the OpenAPI enum. The API enforces every rule; the UI only
 * explains them (a downgrade needs `org.update` and an explicit acknowledgement).
 */
import type { Schemas } from "@cyberlab/contracts";

export type Tlp = Schemas["TLP"];

/** Least to most restrictive. */
export const TLP_VALUES = ["clear", "green", "amber", "amber_strict", "red"] as const satisfies readonly Tlp[];

export const TLP_ORDER: Record<Tlp, number> = {
  clear: 0,
  green: 1,
  amber: 2,
  amber_strict: 3,
  red: 4,
};

export const TLP_LABELS: Record<Tlp, string> = {
  clear: "TLP:CLEAR",
  green: "TLP:GREEN",
  amber: "TLP:AMBER",
  amber_strict: "TLP:AMBER+STRICT",
  red: "TLP:RED",
};

/** FIRST colours, always shown on black. */
export const TLP_BACKGROUND = "#000000";
export const TLP_COLOURS: Record<Tlp, string> = {
  clear: "#FFFFFF",
  green: "#33FF00",
  amber: "#FFC000",
  amber_strict: "#FFC000",
  red: "#FF2B2B",
};

/** The FIRST one-line definitions (RT23), shown next to the label. */
export const TLP_DEFINITIONS: Record<Tlp, string> = {
  clear: "Recipients can spread this to the world, there is no limit on disclosure.",
  green: "Limited disclosure, recipients can spread this within their community.",
  amber:
    "Limited disclosure, recipients can only spread this on a need-to-know basis within their organization and its clients.",
  amber_strict:
    "Limited disclosure, recipients can only spread this on a need-to-know basis within their organization only.",
  red: "For the eyes and ears of individual recipients only, no further disclosure.",
};

export function isTlp(value: unknown): value is Tlp {
  return typeof value === "string" && (TLP_VALUES as readonly string[]).includes(value);
}

/** True when `next` is less restrictive than `current` (needs `org.update` + the ack). */
export function isDowngrade(next: Tlp, current: Tlp): boolean {
  return TLP_ORDER[next] < TLP_ORDER[current];
}

/** TLP:RED and TLP:AMBER+STRICT reports need a distribution statement on the cover. */
export function needsDistribution(tlp: Tlp): boolean {
  return tlp === "red" || tlp === "amber_strict";
}
