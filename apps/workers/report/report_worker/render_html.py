"""Snapshot -> HTML (`incident_v1`), for the PDF and for the HTML artifact.

- `jinja2.sandbox.SandboxedEnvironment(autoescape=True, undefined=StrictUndefined)`: every
  value from the snapshot is escaped text. The escape hatches do not exist in it: the
  `safe`, `urlize` and `xmlattr` filters are removed (a template using one fails to compile,
  or to render inside a conditional) and the `{% autoescape %}` statement is a syntax error
  (`_Parser`); `tests/test_template_lint.py` also greps the templates and this package.
  Class names come only from the fixed `sev_class` / `tlp_class` filters.
- The only text rule is `vis` (RT24): bidi, zero-width, control and tag characters become
  `⟨U+XXXX⟩`. Defanging already happened in the snapshot builder.
- Links: in-document anchors built from integers (`#c12`, section ids), and in the appendix
  the platform path behind the snapshot's `base_url` (PUBLIC_BASE_URL, internal profile
  only; `external` carries no `base_url` or paths, RT8).
- The HTML artifact carries the trusted constant CSS inline and the meta CSP
  `default-src 'none'; style-src 'unsafe-inline'` (RT19). The CSS is inserted by replacing
  the template's own empty `<style id="report-css"></style>` element in the head: the
  autoescaped data can never produce that markup.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from cyberlab_jobs.report import AiClaim, AiSection, ReportSnapshot
from jinja2 import FileSystemLoader, StrictUndefined, TemplateSyntaxError, nodes
from jinja2.parser import Parser
from jinja2.sandbox import SandboxedEnvironment

from report_worker import text

_PACKAGE_ROOT = Path(__file__).resolve().parents[1]


def _installed(path: str, fallback: str) -> Path:
    """The image paths (root-owned, read-only); the source tree when run from a checkout."""
    installed = Path(path)
    return installed if installed.exists() else _PACKAGE_ROOT / fallback


TEMPLATES_DIR = _installed("/app/templates", "templates")
CSS_FILE = _installed("/app/assets/report.css", "assets/report.css")
TEMPLATE = "incident_v1/report.html.j2"
CSS_PLACEHOLDER = '<style id="report-css"></style>'
# Anything that could reference a resource or end the inline <style> element.
_CSS_FORBIDDEN = re.compile(r"url\s*\(|@import|@font-face|</|<!--|image-set\s*\(", re.I)


def _load_css() -> str:
    css = CSS_FILE.read_text(encoding="utf-8")
    if _CSS_FORBIDDEN.search(css):
        raise RuntimeError("report.css must not reference resources (RT16)")
    return css


# Read once at import: the stylesheet is a trusted constant (RT16).
REPORT_CSS_TEXT = _load_css()

ANALYST_SECTIONS: tuple[tuple[str, str], ...] = (
    ("executive_summary", "Executive summary"),
    ("scope", "Scope"),
    ("methodology", "Methodology"),
    ("impact", "Impact"),
    ("root_cause", "Root cause"),
    ("actions_taken", "Actions taken"),
    ("recommendations", "Recommendations"),
    ("lessons_learned", "Lessons learned"),
)
# (attribute, anchor, contents title) of the data sections, in reading order.
DATA_SECTIONS: tuple[tuple[str, str, str], ...] = (
    ("evidence", "evidence", "Evidence"),
    ("custody", "custody", "Chain of custody"),
    ("jobs", "jobs", "Analysis jobs"),
    ("findings", "findings", "Findings"),
    ("alerts", "alerts", "Alerts"),
    ("iocs", "iocs", "Indicators of compromise"),
    ("ti", "ti", "Threat intelligence"),
    ("attack", "attack", "MITRE ATT&CK mapping"),
    ("timeline", "timeline", "Timeline"),
    ("notes", "notes", "Analyst notes"),
    ("ai", "ai", "AI-assisted analysis"),
    ("citations", "citations", "Citation appendix"),
)
AI_GROUPS: tuple[tuple[str, str], ...] = (
    ("observed", "Observed"),
    ("interpretation", "Interpretation"),
    ("hypotheses", "Hypotheses"),
    ("next_steps", "Suggested next steps"),
    ("limitations", "Limitations"),
)
_SAFE_PATH = re.compile(r"^/(?!/)[A-Za-z0-9/_.?=&%-]*$")


@dataclass(frozen=True)
class TocEntry:
    anchor: str
    title: str


@dataclass(frozen=True)
class AnalystBlock:
    anchor: str
    title: str
    text: str


@dataclass(frozen=True)
class AiGroup:
    title: str
    claims: list[AiClaim]


@dataclass(frozen=True)
class AiEntry:
    run: AiSection
    groups: list[AiGroup]


def _num(value: int) -> str:
    """`3 412` (no-break space as the thousands separator)."""
    return f"{int(value):,}".replace(",", " ")


# Built-in filters that produce markup Jinja does not escape again (RT19): gone.
REMOVED_FILTERS = ("safe", "urlize", "xmlattr")


class _Parser(Parser):
    """Jinja's parser without the `{% autoescape %}` statement (a syntax error)."""

    def parse_autoescape(self) -> nodes.Scope:
        raise TemplateSyntaxError(
            "the autoescape statement is disabled", self.stream.current.lineno, self.name
        )


class ReportEnvironment(SandboxedEnvironment):
    """The sandboxed, autoescaping environment whose templates cannot turn escaping off."""

    def _parse(self, source: str, name: str | None, filename: str | None) -> nodes.Template:
        return _Parser(self, source, name, filename).parse()


def _environment() -> SandboxedEnvironment:
    env = ReportEnvironment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        auto_reload=False,
    )
    env.filters.update(
        vis=text.vis,
        runs=text.runs,
        ts=text.ts,
        opt=text.opt,
        num=_num,
        tlp_label=text.tlp_label,
        tlp_class=text.tlp_class,
        tlp_definition=text.tlp_definition,
        sev_class=text.sev_class,
        short_sha=text.short_sha,
    )
    for name in REMOVED_FILTERS:
        env.filters.pop(name, None)
    return env


ENV = _environment()


def platform_links(snapshot: ReportSnapshot) -> dict[int, str]:
    """`{cite_no: base_url + path}` for the internal profile; empty without a base_url."""
    base = snapshot.report.base_url
    if not base:
        return {}
    links: dict[int, str] = {}
    for c in snapshot.citations.items:
        path = c.path
        if path and _SAFE_PATH.match(path) and "/../" not in f"{path}/":
            links[c.cite_no] = f"{base}{path}"
    return links


def _ai_entries(snapshot: ReportSnapshot) -> list[AiEntry]:
    entries = []
    for run in snapshot.ai.items:
        groups = [
            AiGroup(title, [c for c in run.claims if c.section == key]) for key, title in AI_GROUPS
        ]
        entries.append(AiEntry(run, [g for g in groups if g.claims]))
    return entries


def context(snapshot: ReportSnapshot, sha256: str) -> dict[str, Any]:
    analyst = [
        AnalystBlock(name.replace("_", "-"), title, getattr(snapshot.sections, name))
        for name, title in ANALYST_SECTIONS
        if getattr(snapshot.sections, name)
    ]
    present = {name: bool(getattr(snapshot, name).items) for name, _, _ in DATA_SECTIONS}
    toc = [TocEntry(a.anchor, a.title) for a in analyst]
    toc.append(TocEntry("case", "Case"))
    toc += [TocEntry(anchor, title) for name, anchor, title in DATA_SECTIONS if present[name]]
    toc.append(TocEntry("integrity", "Integrity"))
    return {
        "s": snapshot,
        "sha256": sha256,
        "footer": text.case_footer(snapshot.case.case_ref, snapshot.report.version, sha256),
        "finalized_w3c": snapshot.report.finalized_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "analyst": analyst,
        "present": present,
        "toc": toc,
        "links": platform_links(snapshot),
        "ioc_values": {i.ioc_key: i.value for i in snapshot.iocs.items},
        "ai_runs": _ai_entries(snapshot),
    }


def render(snapshot: ReportSnapshot, *, sha256: str, mode: Literal["pdf", "html"]) -> str:
    """The document. `mode="html"` inlines the constant CSS for the HTML artifact; the PDF
    gets the same CSS as a separate constant stylesheet (`render_pdf.REPORT_CSS`)."""
    html = ENV.get_template(TEMPLATE).render(**context(snapshot, sha256), inline_css=mode == "html")
    if mode == "html":
        head_end = html.index("</head>")
        at = html.find(CSS_PLACEHOLDER)
        if not 0 <= at < head_end:
            raise RuntimeError("the template's style placeholder is missing")
        html = (
            html[:at]
            + f'<style id="report-css">\n{REPORT_CSS_TEXT}</style>'
            + html[at + len(CSS_PLACEHOLDER) :]
        )
    return html
