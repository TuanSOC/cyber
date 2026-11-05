import type { Schemas } from "@cyberlab/contracts";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { EvidenceActions } from "@/components/evidence/evidence-actions";
import {
  EvidenceIntegrityStrip,
  EvidenceIntegrityStripView,
  MISMATCH_TOOLTIP,
  declaredTypeLabel,
  detectedTypeLabel,
  isPurgedError,
  mismatchText,
  runLabel,
} from "@/components/evidence/evidence-integrity-strip";
import { ApiError } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { apiErrorText } from "@/lib/http-errors";
import { OrgProvider } from "@/lib/org-context";

const ORG = "11111111-1111-4111-8111-111111111111";
const noop = () => undefined;

const RUN = "55555555-5555-4555-8555-555555555555";

function render(node: ReactElement, role: "owner" | "viewer" = "owner"): string {
  return renderToStaticMarkup(
    <OrgProvider value={{ orgId: ORG, orgName: "Org", role }}>
      <QueryClientProvider client={new QueryClient()}>{node}</QueryClientProvider>
    </OrgProvider>,
  );
}

function evidence(over: Partial<Schemas["EvidenceOut"]> = {}): Schemas["EvidenceOut"] {
  return {
    id: "33333333-3333-4333-8333-333333333333",
    investigation_id: "22222222-2222-4222-8222-222222222222",
    original_filename: "invoice.pdf",
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

describe("evidence integrity strip", () => {
  it("renders nothing for ordinary evidence", () => {
    expect(render(<EvidenceIntegrityStrip evidence={evidence()} />)).toBe("");
  });

  it("explains purged bytes with the date and the retained hashes and custody", () => {
    const html = render(<EvidenceIntegrityStrip evidence={evidence({ purged_at: "2026-11-05T02:31:00Z" })} />);
    expect(html).toContain(`Bytes purged on ${formatDate("2026-11-05T02:31:00Z").local}`);
    expect(html).toContain("hashes and custody retained");
    expect(html).toContain("Download, verification and new analyses are unavailable.");
  });

  it("names the purging run, linked for audit readers only (M7 follow-up)", () => {
    const purged = evidence({ purged_at: "2026-11-05T02:31:00Z", purged_by_run_id: RUN });
    const owner = render(<EvidenceIntegrityStrip evidence={purged} />);
    expect(owner).toContain(`href="/o/${ORG}/settings/retention/runs/${RUN}"`);
    expect(owner).toContain(runLabel(RUN));
    const viewer = render(<EvidenceIntegrityStrip evidence={purged} />, "viewer");
    expect(viewer).toContain(runLabel(RUN));
    expect(viewer).not.toContain("settings/retention/runs");
    expect(runLabel(RUN)).toBe("run 55555555");
    expect(runLabel("<b>x</b>")).toBe("run bb");
    // No run id (older servers): no run line.
    expect(render(<EvidenceIntegrityStrip evidence={evidence({ purged_at: "2026-11-05T02:31:00Z" })} />)).not.toContain(
      "purged-by-run",
    );
  });

  it("shows the same message after a 410 from an action", () => {
    const html = render(<EvidenceIntegrityStripView evidence={evidence()} purgedError />);
    expect(html).toContain("The evidence bytes were purged.");
    expect(html).toContain(apiErrorText(new ApiError(410, "evidence_purged", "gone")) ?? "missing");
    expect(isPurgedError(new ApiError(410, "evidence_purged", "gone"))).toBe(true);
    expect(isPurgedError(new ApiError(404, "not_found", "x"))).toBe(false);
    expect(isPurgedError(new Error("410"))).toBe(false);
  });

  it("disables download and verify on purged evidence", () => {
    const html = render(
      <EvidenceActions
        orgId={ORG}
        evidence={evidence({ purged_at: "2026-11-05T02:31:00Z" })}
        canWrite
        investigationArchived={false}
        onVerified={noop}
      />,
    );
    const buttons = [...html.matchAll(/<button[^>]*>/g)].map((m) => m[0]);
    expect(buttons.slice(0, 2).every((b) => b.includes('disabled=""'))).toBe(true);
  });

  it("shows the declared vs detected type badge with its tooltip", () => {
    const e = evidence({ type_mismatch: true, declared_type: "pdf" });
    expect(mismatchText(e)).toBe("Declared type (.pdf) differs from detected type (PE)");
    const html = render(<EvidenceIntegrityStrip evidence={e} />);
    expect(html).toContain("Declared type (.pdf) differs from detected type (PE)");
    expect(html).toContain(MISMATCH_TOOLTIP);
    expect(MISMATCH_TOOLTIP).toContain("accepted");
    expect(MISMATCH_TOOLTIP).toContain("detected type");
  });

  it("labels types safely", () => {
    expect(detectedTypeLabel("application/x-executable")).toBe("ELF");
    expect(detectedTypeLabel("application/vnd.tcpdump.pcap")).toBe("PCAP");
    expect(detectedTypeLabel("application/<x>")).toBe("application/x");
    expect(declaredTypeLabel("README", "text")).toBe("text");
    expect(declaredTypeLabel("a.PDF", null)).toBe(".pdf");
    expect(declaredTypeLabel("<b>.exe\u202e", "pe")).toBe("PE");
    const hostile = render(
      <EvidenceIntegrityStrip
        evidence={evidence({ type_mismatch: true, original_filename: "<script>.pdf", detected_mime: "<img src=x>" })}
      />,
    );
    expect(hostile).not.toContain("<script>");
    expect(hostile).not.toContain("<img");
  });

  it("shows the legal hold of the evidence", () => {
    expect(render(<EvidenceIntegrityStrip evidence={evidence({ legal_hold: true })} />)).toContain("Legal hold");
  });
});
