import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { TimelineRow } from "@/components/timeline/timeline-parts";
import type { JobRoute } from "@/lib/ai";
import type { TimelineEntry } from "@/lib/case";

const ORG = "11111111-1111-4111-8111-111111111111";
const JOB = "22222222-2222-4222-8222-222222222222";
const EV = "33333333-3333-4333-8333-333333333333";
const REF = "44444444-4444-4444-8444-444444444444";
const INV = "55555555-5555-4555-8555-555555555555";
const routes = new Map<string, JobRoute>([[JOB, "pcap"]]);

function entry(over: Partial<TimelineEntry>): TimelineEntry {
  return {
    evidence_id: EV,
    job_id: JOB,
    kind: "alert",
    ref_id: REF,
    ref_kind: "alert",
    severity: "high",
    title: "ET TROJAN beacon",
    ts: "2026-11-05T10:00:00Z",
    ts_source: "capture",
    ...over,
  };
}

describe("timeline rows", () => {
  it("links evidence entries to the evidence and the analysis", () => {
    const html = renderToStaticMarkup(<ul><TimelineRow orgId={ORG} entry={entry({})} routes={routes} /></ul>);
    expect(html).toContain(`href="/o/${ORG}/evidence/${EV}"`);
    expect(html).toContain(`href="/o/${ORG}/pcap/${JOB}?tab=alerts&amp;ref=${REF}"`);
  });

  it("shows note and status entries as case events without an evidence link (RT10)", () => {
    for (const kind of ["note", "status"] as const) {
      const html = renderToStaticMarkup(
        <ul>
          <TimelineRow
            orgId={ORG}
            routes={routes}
            entry={entry({ evidence_id: null, job_id: null, ref_kind: kind, kind, severity: null, ts_source: "recorded", title: "Closed: <b>done</b>" })}
          />
        </ul>,
      );
      expect(html).toContain("case event");
      expect(html).not.toContain("href=");
      expect(html).not.toContain("<b>");
      expect(html).toContain(kind === "note" ? "Note" : "Status change");
    }
  });

  it("offers \"Add to report\" for citable rows only, and only with citeIn", () => {
    const render = (over: Partial<TimelineEntry>, citeIn?: string) =>
      renderToStaticMarkup(
        <QueryClientProvider client={new QueryClient()}>
          <ul>
            <TimelineRow orgId={ORG} routes={routes} entry={entry(over)} citeIn={citeIn} />
          </ul>
        </QueryClientProvider>,
      );
    expect(render({}, INV)).toContain("Add to report");
    expect(render({ ref_kind: "finding", kind: "finding" }, INV)).toContain("Add to report");
    expect(render({})).not.toContain("Add to report");
    expect(render({ ref_kind: "status", kind: "status", evidence_id: null, job_id: null }, INV)).not.toContain("Add to report");
  });
});
