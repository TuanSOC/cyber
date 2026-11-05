import type { Schemas } from "@cyberlab/contracts";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { EvidenceAnalysesCard, PURGED_NOTE } from "@/components/analysis/evidence-analyses-card";
import { RUN_KINDS } from "@/lib/analysis";

const ORG = "11111111-1111-4111-8111-111111111111";

function render(node: ReactElement): string {
  return renderToStaticMarkup(<QueryClientProvider client={new QueryClient()}>{node}</QueryClientProvider>);
}

function evidence(over: Partial<Schemas["EvidenceOut"]> = {}): Schemas["EvidenceOut"] {
  return {
    id: "33333333-3333-4333-8333-333333333333",
    investigation_id: "22222222-2222-4222-8222-222222222222",
    original_filename: "sample.exe",
    description: "",
    detected_mime: "application/x-dosexec",
    detected_description: "PE32 executable",
    hashes: { sha256: "a".repeat(64) },
    size_bytes: 1024,
    status: "active",
    uploaded_at: "2026-11-01T12:00:00Z",
    uploaded_by: "u1",
    uploaded_by_name: "Alice",
    ai_excluded: false,
    ti_excluded: false,
    legal_hold: false,
    purged_at: null,
    declared_type: null,
    type_mismatch: null,
    ...over,
  } as Schemas["EvidenceOut"];
}

function card(e: Schemas["EvidenceOut"]): string {
  return render(<EvidenceAnalysesCard orgId={ORG} evidence={e} canWrite investigationArchived={false} />);
}

describe("evidence analyses card", () => {
  it("offers analysis runs on evidence with bytes", () => {
    const html = card(evidence());
    expect(html).toContain(RUN_KINDS.static_full.label);
    expect(html).toContain("Other analyses");
    expect(html).not.toContain(PURGED_NOTE);
  });

  it("hides the run buttons and explains why on purged evidence", () => {
    const html = card(evidence({ purged_at: "2026-11-05T02:31:00Z" }));
    expect(html).toContain(PURGED_NOTE);
    expect(PURGED_NOTE).toContain("Evidence purged by retention");
    expect(html).not.toContain(RUN_KINDS.static_full.label);
    expect(html).not.toContain(RUN_KINDS.static_av.label);
    expect(html).not.toContain("Other analyses");
    expect(html).not.toMatch(/<button/);
  });
});
