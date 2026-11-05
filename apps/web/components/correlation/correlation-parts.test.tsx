import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { OccurrenceList, RelatedCasesList, SeenInList } from "@/components/correlation/correlation-parts";
import type { Occurrence, RelatedCase, SeenIn } from "@/lib/correlation";

const ORG = "11111111-1111-4111-8111-111111111111";
const INV = "22222222-2222-4222-8222-222222222222";
const EVI = "33333333-3333-4333-8333-333333333333";
const JOB = "44444444-4444-4444-8444-444444444444";
const noop = () => undefined;

function seen(over: Partial<SeenIn> = {}): SeenIn {
  return {
    kind: "url",
    value: "https://evil.example/<img src=x>",
    key: "k".repeat(64),
    other_jobs: 3,
    other_cases: 2,
    first_seen: null,
    last_seen: null,
    common: false,
    top_cases: [],
    ...over,
  };
}

describe("also seen in chips", () => {
  it("one chip per key, the value defanged text and never a link", () => {
    const html = renderToStaticMarkup(
      <SeenInList items={[seen(), seen({ kind: "domain", value: "b.example", key: "b".repeat(64), common: true, other_jobs: 60 })]} onOpen={noop} />,
    );
    expect(html.match(/<li/g)).toHaveLength(2);
    expect(html).toContain("seen in 2 other cases");
    expect(html).toContain("hxxps[:]//evil[.]example/");
    expect(html).not.toContain("<img");
    expect(html).not.toContain("href=");
    expect(html).toContain("common across 61 jobs; excluded from related cases");
  });

  it("limits the collapsed list", () => {
    const items = Array.from({ length: 7 }, (_, i) => seen({ key: `${i}`.repeat(64), value: `h${i}.example` }));
    expect(renderToStaticMarkup(<SeenInList items={items} onOpen={noop} limit={5} />).match(/<li/g)).toHaveLength(5);
  });
});

describe("key drawer occurrences", () => {
  it("links case, evidence and job; hostile names stay text", () => {
    const occurrence: Occurrence = {
      job_id: JOB,
      analyzer: "static",
      investigation_id: INV,
      case_ref: "CASE-00007",
      title: "Phish ‮wave",
      evidence_id: EVI,
      evidence_filename: "<svg onload=x>.exe",
      first_seen: "2026-11-01T10:00:00Z",
      last_seen: "2026-11-02T10:00:00Z",
    };
    const html = renderToStaticMarkup(<OccurrenceList orgId={ORG} items={[occurrence]} />);
    expect(html).toContain(`href="/o/${ORG}/investigations/${INV}"`);
    expect(html).toContain(`href="/o/${ORG}/evidence/${EVI}"`);
    expect(html).toContain(`href="/o/${ORG}/malware/${JOB}?tab=iocs"`);
    expect(html).not.toContain("<svg");
    expect(html).toContain("⟨U+202E⟩");
    expect(html).toContain("first seen");
  });
});

describe("related cases", () => {
  it("ranks as given, labels archived cases and shows the kinds", () => {
    const items: RelatedCase[] = [
      { investigation_id: INV, case_ref: "CASE-00003", title: "A", status: "archived", shared_keys: 4, kinds: { domain: 3, ipv4: 1 }, last_seen: null },
      { investigation_id: EVI, case_ref: "CASE-00004", title: "B", status: "open", shared_keys: 1, kinds: { sha256: 1 }, last_seen: null },
    ];
    const html = renderToStaticMarkup(<RelatedCasesList orgId={ORG} items={items} />);
    expect(html.indexOf("CASE-00003")).toBeLessThan(html.indexOf("CASE-00004"));
    expect(html).toContain("Archived");
    expect(html.match(/Archived/g)).toHaveLength(1);
    expect(html).toContain("4 shared observables");
    expect(html).toContain("3 domain, 1 IPv4");
  });

  it("shows the sample shared keys as defanged text, never links (M7 follow-up)", () => {
    const items: RelatedCase[] = [
      {
        investigation_id: INV,
        case_ref: "CASE-00003",
        title: "A",
        status: "open",
        shared_keys: 2,
        kinds: { url: 1, ipv4: 1 },
        last_seen: null,
        sample_keys: [
          { kind: "url", value: "https://evil.example/<img src=x>", key: "u".repeat(64) },
          { kind: "ipv4", value: "192.0.2.10", key: "i".repeat(64) },
        ],
      },
    ];
    const html = renderToStaticMarkup(<RelatedCasesList orgId={ORG} items={items} />);
    expect(html).toContain("Sample shared observables");
    expect(html).toContain("hxxps[:]//evil[.]example/");
    expect(html).not.toContain("<img");
    expect(html).not.toContain('href="https');
    expect(html.match(/href=/g)).toHaveLength(1); // the case link only
  });
});

describe("rows on screen", () => {
  it("marks the keys carried by the visible IOC rows", () => {
    const items = [seen({ key: "a".repeat(64), value: "a.example" }), seen({ key: "b".repeat(64), value: "b.example" })];
    const html = renderToStaticMarkup(<SeenInList items={items} onOpen={noop} onPageCount={1} />);
    expect(html.match(/data-on-page/g)).toHaveLength(1);
    expect(html).toContain("in the rows below");
  });
});
