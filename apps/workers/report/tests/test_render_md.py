"""The Markdown escaper and document: nothing from the snapshot becomes a link, an image,
raw HTML, a heading, a list, a quote or a table break, in CommonMark and in GFM with
linkify (markdown-it-py, tests only); `&#x202E;` entities stay inert text; a newline or
`|` in a table cell cannot end its row (RT19)."""

import hashlib
import html
import random
import re

import pytest
from cyberlab_jobs.report import ReportSnapshot, canonical_json
from markdown_it import MarkdownIt

from report_worker import render_md
from report_worker.text import vis

PARSERS = {
    "commonmark": MarkdownIt("commonmark"),
    "gfm": MarkdownIt("gfm-like", {"linkify": True}).enable(["linkify", "table", "strikethrough"]),
}
HOSTILE = [
    "</style><script>alert(1)</script>",
    '<img src=http://attacker.example/x.png onerror="alert(2)">',
    "[link](http://attacker.example)",
    "![img](x.png)",
    "<http://attacker.example>",
    "http://attacker.example/path?x=1",
    "www.attacker.example",
    "user@attacker.example",
    "# heading",
    "## also",
    "> quote",
    "- item",
    "+ item",
    "* item",
    "1. list",
    "1) list",
    "===",
    "---",
    "    indented code",
    "\tTabbed",
    "```fence```",
    "~~~tilde~~~",
    "**bold** _em_ ~~strike~~",
    "a | b | c",
    "&#x202E; &amp; &lt;b&gt;",
    "evil‮gnp.exe",
    "zero​width",
    "back\\slash \\[x\\]",
    "line\nbreak\n# heading after newline\n> quote after newline",
    "`code` ``double``",
    "[x]: http://attacker.example",
    "<!-- comment -->",
    "<div>block</div>",
    "trailing  ",
    '=HYPERLINK("http://attacker.example","click")',
]
ALPHABET = "abc <>[]()!#*_`~|\\/:.@&;=+-'\"\n\t‮1234567890xyz{}^$%?"


def render(name: str, source: str) -> str:
    return str(PARSERS[name].render(source))


def tokens(name: str, source: str) -> list[str]:
    out: list[str] = []
    for token in PARSERS[name].parse(source):
        out.append(token.type)
        out += [child.type for child in token.children or []]
    return out


def visible(rendered: str) -> str:
    """The text a reader sees (tags removed, entities decoded)."""
    return html.unescape(re.sub(r"<[^>]+>", "", rendered))


def _random_values(n: int) -> list[str]:
    rng = random.Random(20261106)
    return ["".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, 40))) for _ in range(n)]


CASES = HOSTILE + _random_values(300)
INERT_TOKENS = {
    "paragraph_open",
    "paragraph_close",
    "inline",
    "text",
    "softbreak",
    "hardbreak",
    "code_inline",
    "text_special",
}


@pytest.mark.parametrize("parser", list(PARSERS))
@pytest.mark.parametrize("value", CASES)
def test_text_is_inert_and_shows_exactly_the_value(parser: str, value: str) -> None:
    source = render_md.md_text(value)
    assert set(tokens(parser, source)) <= INERT_TOKENS, (value, tokens(parser, source))
    out = render(parser, source)
    assert "<a " not in out and "<img" not in out and "<script" not in out
    expected = vis(value).replace("\r", "").replace("\n", render_md.NEWLINE_MARK)
    shown = visible(out).strip()
    assert shown.replace(" ", " ") == expected.strip().replace(" ", " ") or (
        # CommonMark strips leading / trailing spaces of a paragraph line.
        shown.replace(" ", " ").strip() == expected.replace(" ", " ").strip()
    ), (value, source, out)


@pytest.mark.parametrize("parser", list(PARSERS))
@pytest.mark.parametrize("value", CASES)
def test_code_spans_are_literal(parser: str, value: str) -> None:
    source = render_md.md_code(value)
    assert set(tokens(parser, source)) <= INERT_TOKENS
    out = render(parser, source)
    assert out.count("<code>") == 1
    inner = html.unescape(re.search(r"<code>(.*)</code>", out, re.S).group(1))  # type: ignore[union-attr]
    assert inner == vis(value).replace("\n", render_md.NEWLINE_MARK)


@pytest.mark.parametrize("value", CASES)
def test_table_cells_cannot_break_their_row(value: str) -> None:
    rows = [
        [render_md.md_cell(value), render_md.md_code(value, cell=True), "x"],
        ["y", render_md.md_cell(value + "|" + value), render_md.md_code("|", cell=True)],
    ]
    source = render_md.table(["A", "B", "C"], rows)
    out = render("gfm", source)
    assert out.count("<tr>") == 3, (value, source)
    assert out.count("<td>") + out.count("<td ") == 6
    assert "<a " not in out and "<img" not in out
    body = out[out.index("<tbody>") :]
    assert visible(body).count(render_md.NEWLINE_MARK.strip()) >= 3 * value.count("\n")


def test_paragraphs_keep_lines_but_no_syntax() -> None:
    value = "First line\n# not a heading\n\n> not a quote\n- not a list\n    not code"
    for parser in PARSERS:
        source = render_md.md_paragraphs(value)
        kinds = set(tokens(parser, source))
        assert kinds <= INERT_TOKENS, kinds
        out = render(parser, source)
        assert out.count("<p>") == 2 and "<br" in out
        assert "# not a heading" in visible(out)
        assert "    not code" in visible(out)


def test_entities_stay_inert() -> None:
    for parser in PARSERS:
        out = render(parser, render_md.md_text("&#x202E;&#8238;&amp;"))
        assert "‮" not in out
        assert visible(out).strip() == "&#x202E;&#8238;&amp;"


def test_the_fence_is_longer_than_any_backtick_run() -> None:
    assert render_md.md_code("a ``` b") == "```` a ``` b ````"
    assert render_md.md_code("`") == "`` ` ``"
    assert render_md.md_code(None) == render_md.md_text(None) == "—"


def _doc(snapshot: ReportSnapshot) -> str:
    sha = hashlib.sha256(canonical_json(snapshot)).hexdigest()
    return render_md.render(snapshot, sha256=sha)


@pytest.mark.parametrize("parser", list(PARSERS))
def test_the_hostile_document_has_no_links_images_or_html(
    parser: str, hostile: ReportSnapshot
) -> None:
    source = _doc(hostile)
    kinds = set(tokens(parser, source))
    assert not kinds & {"html_block", "html_inline", "image", "fence", "code_block"}, kinds
    out = render(parser, source)
    assert "<img" not in out and "<script" not in out and "<style" not in out
    hrefs = re.findall(r'<a href="([^"]*)"', out)
    assert hrefs and all(re.fullmatch(r"#c\d+", h) for h in hrefs), hrefs
    assert "‮" not in out and "⟨U+202E⟩" in out
    headings = re.findall(r"<h([1-6])>(.*?)</h\1>", out)
    assert [text for level, text in headings if level == "1"] == [
        html.escape(vis(hostile.report.title), quote=False)
    ]


def test_the_document_opens_and_closes_with_the_tlp(golden: ReportSnapshot) -> None:
    source = _doc(golden)
    lines = [line for line in source.splitlines() if line.strip()]
    assert lines[0].startswith("**TLP\\:AMBER**") and lines[-1] == lines[0]
    out = render("gfm", source)
    assert visible(out).count("TLP:AMBER") >= 3


def test_the_golden_document_has_every_section(golden: ReportSnapshot) -> None:
    out = render("gfm", _doc(golden))
    for title in (
        "Executive summary",
        "Case",
        "Evidence",
        "Chain of custody",
        "Analysis jobs",
        "Findings",
        "Alerts",
        "Indicators of compromise",
        "Threat intelligence",
        "MITRE ATT&amp;CK mapping",
        "Timeline",
        "Analyst notes",
        "AI-assisted analysis",
        "Citation appendix",
        "Integrity",
        "Document control",
    ):
        assert f"<h2>{title}</h2>" in out, title
    for c in golden.citations.items:
        assert f"<h3>C{c.cite_no}</h3>" in out
        assert f'<a href="#c{c.cite_no}">[C{c.cite_no}]</a>' in out
    assert "AI-generated interpretation: observations to verify, not verdicts." in visible(out)
