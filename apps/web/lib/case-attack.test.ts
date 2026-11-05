import { describe, expect, it } from "vitest";

import type { JobRoute } from "@/lib/ai";
import {
  type SourceDescriptor,
  mitreHref,
  parseTechniqueId,
  parseTechniqueIds,
  sourceHref,
  tacticLabel,
  techniqueText,
  techniqueWarning,
  toSourceRefs,
} from "@/lib/case-attack";

const ORG = "11111111-1111-4111-8111-111111111111";
const JOB = "22222222-2222-4222-8222-222222222222";
const ROW = "33333333-3333-4333-8333-333333333333";
const RUN = "44444444-4444-4444-8444-444444444444";
const routes = new Map<string, JobRoute>([[JOB, "pcap"]]);

function src(over: Partial<SourceDescriptor>): SourceDescriptor {
  return { kind: "finding", ref_id: ROW, job_id: JOB, run_id: null, path: null, citation_status: null, ...over };
}

describe("technique ids", () => {
  it("validates the ATT&CK shape", () => {
    expect(parseTechniqueId(" t1059.001 ")).toBe("T1059.001");
    expect(parseTechniqueId("T1059")).toBe("T1059");
    expect(parseTechniqueId("T105")).toBeNull();
    expect(parseTechniqueId("TA0001")).toBeNull();
    expect(parseTechniqueIds("T1055, t1055 x1 T1027.002")).toEqual({ ids: ["T1055", "T1027.002"], invalid: ["x1"] });
  });

  it("labels and warnings", () => {
    expect(techniqueText({ technique_id: "T1055", name: "Process Injection" })).toBe("T1055 · Process Injection");
    expect(techniqueText({ technique_id: "T9999", name: null })).toBe("T9999");
    expect(techniqueWarning({ revoked: true, deprecated: false })).toContain("revoked");
    expect(techniqueWarning({ revoked: false, deprecated: false })).toBeNull();
    expect(tacticLabel("command-and-control")).toBe("Command and Control");
    expect(tacticLabel("Defense Evasion")).toBe("Defense Evasion");
  });

  it("links only https MITRE pages", () => {
    expect(mitreHref("https://attack.mitre.org/techniques/T1055/")).toBe("https://attack.mitre.org/techniques/T1055/");
    expect(mitreHref("http://attack.mitre.org/techniques/T1055/")).toBeNull();
    expect(mitreHref("https://evil.example/T1055")).toBeNull();
    expect(mitreHref("javascript:alert(1)")).toBeNull();
  });
});

describe("source links", () => {
  it("accepts only internal paths of this org", () => {
    const ok = `/o/${ORG}/pcap/${JOB}?tab=findings&ref=${ROW}`;
    expect(sourceHref(ORG, src({ path: ok }), routes)).toBe(ok);
    for (const path of ["https://evil.example/x", `//evil.example/o/${ORG}/x`, `/o/${ORG}/../x`, `/o/${RUN}/pcap/x`]) {
      // Falls back to the built link (never the given path).
      expect(sourceHref(ORG, src({ path }), routes)).toBe(`/o/${ORG}/pcap/${JOB}?tab=findings&ref=${ROW}`);
    }
  });

  it("builds links per kind", () => {
    expect(sourceHref(ORG, src({ kind: "capability" }), routes)).toBe(
      `/o/${ORG}/malware/${JOB}?tab=capabilities&ref=${ROW}`,
    );
    expect(sourceHref(ORG, src({ kind: "ai_run", run_id: RUN, job_id: null }), routes)).toBe(`/o/${ORG}/ai-analyst/${RUN}`);
    expect(sourceHref(ORG, src({ kind: "ai_run", run_id: "x", job_id: null }), routes)).toBeNull();
    expect(sourceHref(ORG, src({ job_id: RUN }), routes)).toBeNull();
  });

  it("maps descriptors to create refs", () => {
    expect(toSourceRefs([src({})])).toEqual([{ kind: "finding", ref_id: ROW, job_id: JOB, run_id: null }]);
  });
});
