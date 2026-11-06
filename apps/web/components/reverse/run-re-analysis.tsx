"use client";

import type { Schemas } from "@cyberlab/contracts";

type AnalysisJob = Schemas["AnalysisJobOut"];

/**
 * "Reverse engineer" on a static job (M10 phase 1 SLOT, mounted once in the Malware Lab job
 * header; phase 10 fills it): offered for a succeeded static `full` job that identified a PE /
 * ELF file; profile `full` (Ghidra) or `quick` (radare2, when the platform enables it), never
 * automatic; a `429 too_many_active_jobs` (`heavy_analysis_busy`, RT2) is shown as "try again".
 * Renders nothing until phase 10.
 */
export function RunReAnalysis(_props: { orgId: string; job: AnalysisJob }) {
  return null;
}
