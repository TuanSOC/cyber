"""The HTML of `incident_v1`: every section of the golden snapshot, every hostile payload
as inert visible text, only fixed classes, only in-document anchors and platform links,
document structure (lang, title, headings, `th scope`) and the meta CSP (RT19)."""

import hashlib
import re
from html.parser import HTMLParser

import pytest
from cyberlab_jobs.report import HTML_HEAD, ReportSnapshot, canonical_json

from report_worker import render_html, text

ALLOWED_TAGS = {
    "html",
    "head",
    "meta",
    "title",
    "style",
    "body",
    "main",
    "section",
    "nav",
    "div",
    "p",
    "h1",
    "h2",
    "h3",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "ol",
    "li",
    "a",
    "sup",
    "span",
    "strong",
    "code",
    "br",
    "wbr",
}
ALLOWED_ATTRS = {
    "lang",
    "charset",
    "http-equiv",
    "content",
    "name",
    "class",
    "id",
    "href",
    "scope",
    "aria-labelledby",
}
FIXED_CLASSES = {
    "cover",
    "tlp-banner",
    "tlp-label",
    "tlp-definition",
    "caseref",
    "meta",
    "docref",
    "code",
    "prose",
    "muted",
    "shown",
    "toc",
    "sev",
    "cite",
    "ai-run",
    "ai-box",
    "ai-warning",
    "claim",
    "flag",
    "note",
    "citation",
    "cite-head",
    "field",
    "name",
    "value",
    "ioc",
    *text.SEVERITY_CLASSES.values(),
    "sev-unknown",
    *text.TLP_CLASSES.values(),
    *(f"w{n}" for n in (6, 8, 10, 12, 14, 16, 18, 20, 22, 26, 30, 40)),
}


class Collect(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def parse(html: str) -> Collect:
    parser = Collect()
    parser.feed(html)
    parser.close()
    return parser


def render(snapshot: ReportSnapshot, mode: str = "pdf") -> str:
    sha = hashlib.sha256(canonical_json(snapshot)).hexdigest()
    return render_html.render(snapshot, sha256=sha, mode=mode)  # type: ignore[arg-type]


def test_the_golden_snapshot_renders_every_section(golden: ReportSnapshot) -> None:
    html = render(golden)
    ids = {attrs.get("id") for _, attrs in parse(html).tags}
    expected = {
        "cover",
        "contents",
        "document-control",
        "case",
        "evidence",
        "custody",
        "jobs",
        "findings",
        "alerts",
        "iocs",
        "ti",
        "attack",
        "timeline",
        "notes",
        "ai",
        "citations",
        "integrity",
        "executive-summary",
    }
    assert expected <= ids, expected - ids
    for c in golden.citations.items:
        assert f'id="c{c.cite_no}"' in html
    for f in golden.findings.items:
        assert text.vis(f.title).replace("&", "&amp;") in html
    assert "AI-generated interpretation: observations to verify, not verdicts." in html
    assert golden.ai.items[0].prompt_version in html


def test_the_document_structure(golden: ReportSnapshot) -> None:
    html = render(golden)
    assert html.startswith('<!DOCTYPE html>\n<html lang="en">')
    # The constant head (CSP meta included) the output check and the ingest require.
    for mode in ("pdf", "html"):
        assert render(golden, mode).encode().startswith(HTML_HEAD)
    tags = parse(html).tags
    names = [t for t, _ in tags]
    assert names.count("h1") == 1 and "h2" in names and "h3" in names
    assert re.search(r"<title>CASE-\d+ v\d+ [^<]+</title>", html)
    assert all(attrs.get("scope") in {"col", "row"} for t, attrs in tags if t == "th")
    # DOM order = reading order: cover, contents, analyst sections, data, appendix.
    order = [a["id"] for t, a in tags if t in {"section", "nav"} and "id" in a]
    assert order.index("cover") < order.index("contents") < order.index("executive-summary")
    assert order.index("case") < order.index("findings") < order.index("citations")
    assert order[-1] == "integrity"


def test_the_cover_shows_tlp_identification_and_document_control(golden: ReportSnapshot) -> None:
    html = render(golden)
    cover = html[html.index('<section class="cover"') : html.index("</section>")]
    assert 'class="tlp-banner tlp-amber"' in cover
    assert "TLP:AMBER" in cover and "need-to-know" in cover
    assert golden.case.case_ref in cover
    assert f"v{golden.report.version} (this)" in cover
    for d in golden.report.document_control:
        assert f"v{d.version}" in cover and d.snapshot_sha256_short in cover
    sha = hashlib.sha256(canonical_json(golden)).hexdigest()
    assert (
        sha in cover and text.case_footer(golden.case.case_ref, golden.report.version, sha) in cover
    )


def test_the_meta_csp_is_in_the_head(golden: ReportSnapshot) -> None:
    for mode in ("pdf", "html"):
        html = render(golden, mode)
        head = html[: html.index("</head>")]
        assert (
            '<meta http-equiv="Content-Security-Policy" '
            "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        ) in head


def test_the_html_artifact_inlines_exactly_the_constant_css(golden: ReportSnapshot) -> None:
    html = render(golden, "html")
    assert html.count("<style") == 1 and html.count("</style>") == 1
    head = html[: html.index("</head>")]
    assert render_html.REPORT_CSS_TEXT in head
    pdf_html = render(golden, "pdf")
    assert "<style" not in pdf_html


HOSTILE_MARKUP = ("<img", "<script", "</style>", "<link", "<iframe", "<svg", "<object")


def test_hostile_payloads_are_inert_visible_text(hostile: ReportSnapshot) -> None:
    for mode in ("pdf", "html"):
        html = render(hostile, mode)
        body = html[html.index("<body>") :]
        for needle in HOSTILE_MARKUP:
            assert needle not in body.lower(), needle
        # CSS payloads are visible text, never CSS: no style element or attribute in the
        # body at all.
        assert "<style" not in body and "style=" not in body
        assert "url(file:///etc/" in body.replace("<wbr>", "")
        assert "‮" not in html and "​" not in html and "\U000e0041" not in html
        assert "⟨U+202E⟩" in html and "⟨U+200B⟩" in html and "⟨U+E0041⟩" in html
        # The payloads are there, escaped.
        assert "&lt;/style&gt;&lt;script&gt;alert(1)&lt;/script&gt;" in html.replace("<wbr>", "")
        assert "onerror=&#34;alert(2)&#34;" in html.replace("<wbr>", "")


def test_only_known_tags_attributes_classes_and_links(hostile: ReportSnapshot) -> None:
    for snapshot_mode in ("pdf", "html"):
        html = render(hostile, snapshot_mode)
        for tag, attrs in parse(html).tags:
            assert tag in ALLOWED_TAGS, tag
            assert set(attrs) <= ALLOWED_ATTRS, (tag, attrs)
            for cls in (attrs.get("class") or "").split():
                assert cls in FIXED_CLASSES, cls
            href = attrs.get("href")
            if href is not None:
                assert re.fullmatch(
                    r"#c\d+|#[a-z-]+|https://cyberlab\.example\.org/[^\s\"<>]*", href
                ), href


def test_platform_links_only_with_a_base_url(golden: ReportSnapshot) -> None:
    internal = render(golden)
    base = golden.report.base_url
    assert base is not None
    links = [
        a.get("href") or ""
        for t, a in parse(internal).tags
        if t == "a" and (a.get("href") or "").startswith("http")
    ]
    assert links and all(link.startswith(base + "/") for link in links)
    external = golden.model_copy(
        update={
            "report": golden.report.model_copy(update={"base_url": None}),
            "citations": golden.citations.model_copy(
                update={
                    "items": [c.model_copy(update={"path": None}) for c in golden.citations.items]
                }
            ),
        }
    )
    html = render(external)
    assert not [
        a for t, a in parse(html).tags if t == "a" and not (a.get("href") or "").startswith("#")
    ]
    assert base not in html


@pytest.mark.parametrize(
    ("path", "linked"),
    [
        ("/o/1/pcap/2?tab=findings&ref=3", True),
        ("//evil.example/x", False),
        ("/o/../../x", False),
        ("/o/a/..", False),
    ],
)
def test_platform_links_refuse_odd_paths(golden: ReportSnapshot, path: str, linked: bool) -> None:
    c = golden.citations.items[0].model_copy(update={"path": path})
    snapshot = golden.model_copy(
        update={"citations": golden.citations.model_copy(update={"items": [c]})}
    )
    assert (c.cite_no in render_html.platform_links(snapshot)) is linked


def test_long_unbroken_runs_get_break_opportunities_and_keep_their_text() -> None:
    n = text.RUN_CHARS
    value = "A" * (3 * n + 7) + " short " + "é" * 5 + "B" * (n + 1)
    pieces = text.runs(value)
    assert "".join(pieces) == value
    assert len(pieces) == 5
    assert all(len(run) <= n for p in pieces for run in re.findall(r"\S+", p))
    assert text.runs("short") == ["short"]
    combining = "x" * (n - 1) + "é" + "y" * n
    assert all(not p.startswith("́") for p in text.runs(combining))
    assert "".join(text.runs("‮" * 40)) == "⟨U+202E⟩" * 40


def test_shown_counts_and_ai_flags(golden: ReportSnapshot) -> None:
    findings = golden.findings.model_copy(update={"total": 3412})
    html = render(golden.model_copy(update={"findings": findings}))
    assert f"Showing {len(golden.findings.items)} of 3 412." in html
    claim = golden.ai.items[0].claims[0].model_copy(update={"flags": ["verdict_language"]})
    run = golden.ai.items[0].model_copy(update={"claims": [claim]})
    ai = golden.ai.model_copy(update={"items": [run]})
    html = render(golden.model_copy(update={"ai": ai}))
    assert '<span class="flag">verdict_language</span>' in html


def test_severity_and_tlp_classes_are_fixed() -> None:
    assert text.sev_class("HIGH") == "sev-high"
    assert text.sev_class('x" onmouseover="y') == "sev-unknown"
    assert text.sev_class(None) == "sev-unknown"
    assert text.tlp_class("amber_strict") == "tlp-amber-strict"
