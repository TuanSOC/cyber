import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { Highlighted, SearchSection, TypeChips } from "@/components/search/search-results";
import type { SearchHit, SectionState } from "@/lib/search";

const ORG = "11111111-1111-4111-8111-111111111111";
const INV = "22222222-2222-4222-8222-222222222222";

function hit(over: Partial<SearchHit> = {}): SearchHit {
  return {
    type: "note",
    id: "n1",
    title: "Analyst note",
    snippet: null,
    match: "fts",
    investigation_id: INV,
    case_ref: "CASE-00012",
    job_id: null,
    evidence_id: null,
    kind: null,
    href: `/investigations/${INV}?tab=notes`,
    ...over,
  };
}

describe("hit text is inert", () => {
  it("renders hostile snippet text as text with marks built from ranges", () => {
    const html = renderToStaticMarkup(<Highlighted text={'see <img src=x onerror=alert(1)> beacon "x"'} q="beacon" />);
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(html).toMatch(/<mark[^>]*>beacon<\/mark>/);
    expect(html.match(/<mark/g)).toHaveLength(1);
  });

  it("makes bidi overrides visible (M6 vis rule)", () => {
    const html = renderToStaticMarkup(<Highlighted text={"invoice‮fdp.exe"} q="invoice" />);
    expect(html).not.toContain("‮");
    expect(html).toContain("⟨U+202E⟩");
  });

  it("a hit links internally and shows the case number", () => {
    const section: SectionState = {
      type: "note",
      status: "ok",
      hits: [hit({ title: "<b>bold</b>", snippet: "text ‮ <script>x</script>", href: "javascript:alert(1)" })],
      nextCursor: "c1",
    };
    const html = renderToStaticMarkup(<SearchSection orgId={ORG} section={section} q="bold" onLoadMore={() => undefined} />);
    expect(html).not.toContain("<b>");
    expect(html).not.toContain("<script");
    expect(html).not.toContain("javascript:");
    expect(html).toContain(`href="/o/${ORG}/investigations/${INV}"`);
    expect(html).toContain("CASE-00012");
    expect(html).toContain("1+ results");
    expect(html).toContain("Load more notes");
  });

  it("shows the case TLP and marks the server's snippet ranges (M7 follow-up)", () => {
    const section: SectionState = {
      type: "note",
      status: "ok",
      hits: [hit({ tlp: "red", snippet: "a quokka and a wombat", snippet_ranges: [{ start: 15, end: 21 }] })],
      nextCursor: null,
    };
    const html = renderToStaticMarkup(<SearchSection orgId={ORG} section={section} q="quokka" />);
    expect(html).toContain("TLP:RED");
    // The server's range wins over client matching of the query.
    expect(html).toMatch(/<mark[^>]*>wombat<\/mark>/);
    expect(html).not.toMatch(/<mark[^>]*>quokka<\/mark>/);
    const plain = renderToStaticMarkup(
      <SearchSection orgId={ORG} section={{ ...section, hits: [hit({ tlp: null })] }} q="quokka" />,
    );
    expect(plain).not.toContain("TLP:");
  });
});

describe("sections", () => {
  it("a timed-out type shows its notice and no hits", () => {
    const html = renderToStaticMarkup(
      <SearchSection orgId={ORG} section={{ type: "alert", status: "timeout", hits: [], nextCursor: null }} q="ab" />,
    );
    expect(html).toContain("This type timed out");
    expect(html).toContain("timed out");
    expect(html).not.toContain("<li");
  });

  it("an empty type says so", () => {
    const html = renderToStaticMarkup(
      <SearchSection orgId={ORG} section={{ type: "evidence", status: "ok", hits: [], nextCursor: null }} q="ab" />,
    );
    expect(html).toContain("No evidence match.");
    expect(html).toContain("0 results");
  });

  it("type chips expose their pressed state", () => {
    const html = renderToStaticMarkup(<TypeChips selected={["case"]} onToggle={() => undefined} />);
    expect(html.match(/aria-pressed="true"/g)).toHaveLength(1);
    expect(html.match(/aria-pressed="false"/g)).toHaveLength(5);
  });
});
