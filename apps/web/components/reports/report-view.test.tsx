import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { PreviewPanel } from "@/components/reports/preview-panel";
import { OPEN_RECORD_LABEL, TOC } from "@/components/reports/report-sections";
import { PREVIEW_WATERMARK, ReportView } from "@/components/reports/report-view";
import type { ReportPreview, ReportSnapshot } from "@/lib/reports";

const ORG = "11111111-1111-4111-8111-111111111111";
const FIXTURES = path.resolve(__dirname, "fixtures");
const API_FIXTURES = path.resolve(__dirname, "../../../api/tests/fixtures/report");

function load(name: string): ReportSnapshot {
  return JSON.parse(readFileSync(path.join(FIXTURES, name), "utf8")) as ReportSnapshot;
}

const OK = { snapshotOk: true, signatureValid: true, kid: "dev-report-1", sha256: "a".repeat(64) };

function render(snapshot: ReportSnapshot, extra: Partial<Parameters<typeof ReportView>[0]> = {}): string {
  return renderToStaticMarkup(<ReportView orgId={ORG} snapshot={snapshot} integrity={OK} {...extra} />);
}

const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
/** Every href the viewer may emit: the TOC anchors and internal record routes built from ids. */
const HREF_ALLOWED = [
  /^#rs-[a-z]+$/,
  new RegExp(`^/o/${UUID}/(evidence|investigations)/${UUID}$`),
  new RegExp(`^/o/${UUID}/(pcap|malware)/${UUID}(\\?tab=[a-z]+(&amp;ref=[A-Za-z0-9%._:-]+)?)?$`),
];
const TAGS_ALLOWED = new Set([
  "article", "section", "header", "nav", "div", "span", "p", "h1", "h2", "h3", "h4", "ol", "ul", "li", "dl", "dt", "dd",
  "table", "caption", "thead", "tbody", "tr", "th", "td", "sup", "button", "a", "details", "summary", "code", "br", "svg",
  "path", "circle", "line", "polyline", "rect",
]);
const ATTRS_ALLOWED = new Set([
  "class", "id", "href", "type", "role", "dir", "tabindex", "title", "scope", "disabled", "style",
  "xmlns", "width", "height", "viewbox", "fill", "stroke", "stroke-width", "stroke-linecap", "stroke-linejoin", "d", "cx", "cy", "r",
  "x1", "x2", "y1", "y2", "points", "x", "y", "rx", "ry",
]);
const STYLE_ALLOWED = /^(background-color:#000000|color:#[0-9A-F]{6}|background-color:#000000;color:#[0-9A-F]{6})$/;

type Tag = { name: string; attrs: [string, string][] };

function tags(markup: string): Tag[] {
  const out: Tag[] = [];
  for (const match of markup.matchAll(/<([a-zA-Z][a-zA-Z0-9-]*)((?:\s[^>]*)?)\/?>/g)) {
    const attrs: [string, string][] = [];
    for (const attr of match[2].matchAll(/\s([^\s=/>]+)(?:="([^"]*)")?/g)) attrs.push([attr[1].toLowerCase(), attr[2] ?? ""]);
    out.push({ name: match[1].toLowerCase(), attrs });
  }
  return out;
}

describe("fixtures", () => {
  it("are byte-identical copies of the API fixtures (when the API tree is mounted)", () => {
    for (const name of ["golden_snapshot.json", "hostile_snapshot.json"]) {
      const api = path.join(API_FIXTURES, name);
      if (!existsSync(api)) continue; // the web container mounts apps/web and packages only
      expect(readFileSync(path.join(FIXTURES, name)).equals(readFileSync(api))).toBe(true);
    }
  });
});

describe("ReportView: golden snapshot", () => {
  const golden = load("golden_snapshot.json");
  const markup = render(golden);

  it("renders every section in snapshot order with a matching heading hierarchy", () => {
    let last = -1;
    for (const entry of TOC) {
      const at = markup.indexOf(`<h2 id="${entry.id}"`);
      expect(at, entry.id).toBeGreaterThan(last);
      expect(markup).toContain(`href="#${entry.id}"`);
      last = at;
    }
    expect(markup.match(/<h1 /g)).toHaveLength(1);
    for (const label of ["Executive summary", "Root cause", "Lessons learned", "Evidence inventory", "Chain of custody", "Threat intelligence"]) {
      expect(markup).toContain(`>${label}</h3>`);
    }
  });

  it("shows the cover facts, document control and every section's data as text", () => {
    for (const text of [
      "Beaconing from FIN workstation",
      "CASE-00012 · Suspicious beaconing",
      "SOC team and IT management",
      "Added the static analysis of the dropper.",
      "Document control",
      "v1",
      "0123456789ab",
      "Initial report.",
      "A workstation beaconed to evil[.]example every 60 seconds.",
      "capture.pcap",
      "3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f",
      "Hashes verified",
      "zeek 7.0.5",
      "Periodic beacon to evil[.]example",
      "ET MALWARE Generic beacon",
      "evil[.]example",
      "Reported by 3 sources (attributed to the provider).",
      "T1071.001",
      "Web Protocols",
      "command and control",
      "First beacon",
      "The interval matches the known loader.",
      "The host contacted evil[.]example every 60 seconds.",
      "This may be a commodity loader.",
      "Hypothesis",
      "1 statement omitted: not supported by verified evidence.",
      "AI-generated, verify before acting.",
      "Signature valid (Ed25519, key dev-report-1).",
    ]) {
      expect(markup, text).toContain(text);
    }
  });

  it("shows TLP banners at the top (sticky) and the bottom with the FIRST definition", () => {
    const banners = tags(markup).filter((t) => t.attrs.some(([k, v]) => k === "data-tlp" && v === "amber"));
    expect(banners).toHaveLength(2);
    expect(banners[0].attrs.find(([k]) => k === "class")?.[1]).toContain("sticky");
    expect(markup.match(/>TLP:AMBER</g)?.length).toBeGreaterThanOrEqual(3); // banners + cover badge
    expect(markup).toContain("need-to-know basis within their organization and its clients.");
  });

  it("citations are buttons that open the appendix, which links to the live record by id", () => {
    expect(markup).toContain('data-cite="2"');
    expect(markup).toMatch(/<button type="button" data-cite="2"[^>]*aria-label="Citation 2"[^>]*>\[C<!-- -->2<!-- -->\]<\/button>|>\[C2\]<\/button>/);
    expect(markup).toContain('id="rs-cite-1"');
    expect(markup).toContain('id="rs-cite-3"');
    expect(markup).toContain(`href="/o/${ORG}/pcap/55555555-5555-4555-8555-555555555555?tab=findings&amp;ref=99999999-9999-4999-8999-999999999991"`);
    expect(markup).toContain(`href="/o/${ORG}/evidence/44444444-4444-4444-8444-444444444444"`);
    expect(markup.split(OPEN_RECORD_LABEL).length - 1).toBe(3);
  });
});

describe("ReportView: hostile snapshot renders inert", () => {
  const hostile = load("hostile_snapshot.json");
  // Also hostile paths: they must never become hrefs.
  hostile.citations.items[0].path = "javascript:alert(1)";
  hostile.citations.items[1].path = "//attacker.example/x";
  const markup = render(hostile, { preview: true });
  const all = tags(markup);

  it("produces no element from data", () => {
    for (const tag of all) expect(TAGS_ALLOWED.has(tag.name), tag.name).toBe(true);
    expect(markup).not.toMatch(/<(img|script|style|iframe|object|embed|link|meta|form|input|svg[^>]*onload)\b/i);
    expect(markup).toContain("&lt;img src=http://attacker.example/x.png onerror=&quot;alert(2)&quot;&gt;");
    expect(markup).toContain("&lt;/style&gt;&lt;script&gt;alert(1)&lt;/script&gt;");
  });

  it("produces no attribute from data and no external link", () => {
    for (const tag of all) {
      for (const [name, value] of tag.attrs) {
        const known = ATTRS_ALLOWED.has(name) || name.startsWith("aria-") || name.startsWith("data-");
        expect(known, `${tag.name}[${name}]`).toBe(true);
        expect(name.startsWith("on"), name).toBe(false);
        expect(value).not.toMatch(/attacker|alert\(|passwd|javascript:|<|>/i);
        if (name === "style") expect(value).toMatch(STYLE_ALLOWED);
        if (name === "href") {
          expect(HREF_ALLOWED.some((re) => re.test(value)), value).toBe(true);
        }
      }
    }
  });

  it("makes bidi and zero-width characters visible and keeps long values whole", () => {
    expect(markup).toContain("evil⟨U+202E⟩gnp.exe");
    expect(markup).not.toContain("‮");
    expect(markup).toContain("A".repeat(4000));
  });

  it("Markdown in text stays literal", () => {
    expect(markup).toContain("# heading\n&gt; quote\n- item\n1. list\n[link](http://attacker.example)\n![img](x.png)");
  });

  it("shows the preview watermark", () => {
    expect(markup).toContain(PREVIEW_WATERMARK);
    expect(markup).toContain('data-report-view="preview"');
  });
});

describe("ReportView: integrity and profile", () => {
  const golden = load("golden_snapshot.json");

  it("an integrity failure is visible as text and as an alert", () => {
    const markup = render(golden, { integrity: { ...OK, snapshotOk: false } });
    expect(markup).toContain('data-integrity="failed"');
    expect(markup).toContain('role="alert"');
    expect(markup).toContain("Integrity check failed: the stored snapshot does not match its recorded SHA-256.");
    const bad = render(golden, { integrity: { ...OK, signatureValid: false } });
    expect(bad).toContain("Integrity check failed: the signature does not verify with key dev-report-1.");
    expect(render(golden)).toContain('data-integrity="ok"');
  });

  it("external snapshots carry no record links", () => {
    const external = load("golden_snapshot.json");
    external.report.profile = "external";
    external.report.base_url = null;
    for (const citation of external.citations.items) citation.path = null;
    const markup = render(external);
    expect(markup).not.toContain(OPEN_RECORD_LABEL);
    expect(markup).toContain("Analyst notes are left out of external reports.");
    for (const tag of tags(markup)) {
      const href = tag.attrs.find(([k]) => k === "href")?.[1];
      if (href !== undefined) expect(href).toMatch(/^#rs-/);
    }
  });
});

describe("PreviewPanel", () => {
  it("shows size, budget, truncation notes and per-section hints, then the watermarked viewer", () => {
    const golden = load("golden_snapshot.json");
    const preview: ReportPreview = {
      snapshot: golden as unknown as ReportPreview["snapshot"],
      section_counts: { findings: { included: 500, total: 3412 }, ai: { included: 1, total: 1 } },
      snapshot_bytes: 2 * 1024 * 1024,
      max_snapshot_bytes: 8 * 1024 * 1024,
      render_units: 900_000,
      max_render_units: 750_000,
      section_units: { findings: 700_000, citations: 150_000, report: 50_000 },
      over_budget: true,
    };
    const markup = renderToStaticMarkup(<PreviewPanel orgId={ORG} preview={preview} />);
    expect(markup).toContain("2.0 MiB of 8.0 MiB (25 %)");
    expect(markup).toContain("900,000 of 750,000 render units (120 %)");
    expect(markup).toContain("Showing 500 of 3,412.");
    expect(markup).toContain("over the render budget");
    expect(markup).toContain("Raise the minimum severity or lower the maximum of findings.");
    expect(markup).toContain(PREVIEW_WATERMARK);
  });

  it("refuses an unknown snapshot format", () => {
    const preview = {
      snapshot: { schema_version: "other" },
      section_counts: {},
      snapshot_bytes: 1,
      max_snapshot_bytes: 2,
      render_units: 1,
      max_render_units: 2,
      section_units: {},
      over_budget: false,
    } satisfies ReportPreview;
    expect(renderToStaticMarkup(<PreviewPanel orgId={ORG} preview={preview} />)).toContain("unknown snapshot format");
  });
});
