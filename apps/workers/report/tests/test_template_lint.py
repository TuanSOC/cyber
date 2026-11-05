"""CI lint of the renderer's trust boundary: no escape hatch out of autoescaping anywhere.

Templates: no `|safe`, `Markup`, `{% autoescape false %}`, `{% raw %}`, inline `style=`,
resource references (`<img`, `<link`, `<script`, `url(`, `@import`, `src=`) or class names
built from data (a `class="…{{ … }}…"` may only use the fixed `sev_class` / `tlp_class`
filters). Template comments are ignored.

Python: no `Markup` / `markupsafe` / `escape`-bypass names, no `autoescape=False`, and the
environment is the sandboxed, autoescaping, StrictUndefined one. The grep is not the only
line: the environment itself has no `safe` / `urlize` / `xmlattr` filter and refuses the
`{% autoescape %}` statement, so a template that slips past the grep still fails.
"""

import ast
import re
from pathlib import Path

import pytest
from jinja2 import StrictUndefined, TemplateError
from jinja2.sandbox import SandboxedEnvironment

from report_worker import render_html

PACKAGE = Path(__file__).resolve().parents[1] / "report_worker"
TEMPLATES = render_html.TEMPLATES_DIR
COMMENT = re.compile(r"\{#.*?#\}", re.S)
BANNED_IN_TEMPLATES = {
    "safe filter": re.compile(r"\|\s*safe\b"),
    "Markup": re.compile(r"\bMarkup\b"),
    "autoescape off": re.compile(r"autoescape\s+(false|off)", re.I),
    "raw block": re.compile(r"\{%-?\s*raw\b"),
    "inline style": re.compile(r"\bstyle\s*=", re.I),
    "image": re.compile(r"<\s*img\b", re.I),
    "link element": re.compile(r"<\s*link\b", re.I),
    "script": re.compile(r"<\s*script\b", re.I),
    "src attribute": re.compile(r"\bsrc\s*=", re.I),
    "css url": re.compile(r"url\s*\(", re.I),
    "css import": re.compile(r"@import", re.I),
    "embed": re.compile(r"<\s*(iframe|object|embed|svg)\b", re.I),
}
CLASS_WITH_EXPR = re.compile(r'class="([^"]*\{\{[^"]*)"')
FIXED_CLASS_EXPR = re.compile(r"\{\{\s*[\w.]+\s*\|\s*(sev_class|tlp_class)\s*\}\}")


def _templates() -> list[Path]:
    paths = sorted(TEMPLATES.rglob("*.j2"))
    assert len(paths) >= 10
    return paths


def test_templates_have_no_escape_hatch_or_resource_reference() -> None:
    offenders = []
    for path in _templates():
        source = COMMENT.sub("", path.read_text(encoding="utf-8"))
        for name, pattern in BANNED_IN_TEMPLATES.items():
            if pattern.search(source):
                offenders.append(f"{path.name}: {name}")
    assert offenders == []


def test_class_names_come_only_from_the_fixed_filters() -> None:
    offenders = []
    for path in _templates():
        source = COMMENT.sub("", path.read_text(encoding="utf-8"))
        for match in CLASS_WITH_EXPR.finditer(source):
            rest = FIXED_CLASS_EXPR.sub("", match.group(1))
            if "{{" in rest or "{%" in rest:
                offenders.append(f"{path.name}: {match.group(0)}")
    assert offenders == []


def test_hrefs_are_anchors_or_the_platform_links() -> None:
    allowed = {
        'href="#c{{ n }}"',
        'href="#{{ entry.anchor }}"',
        'href="{{ links[c.cite_no] }}"',
    }
    for path in _templates():
        source = COMMENT.sub("", path.read_text(encoding="utf-8"))
        for href in re.findall(r'href="[^"]*"', source):
            assert href in allowed, (path.name, href)


def _python_names(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.alias):
            names.add(node.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
        elif isinstance(node, ast.keyword) and node.arg == "autoescape":
            if not (isinstance(node.value, ast.Constant) and node.value.value is True):
                names.add("autoescape=<not True>")
    return names


def test_python_never_bypasses_autoescaping() -> None:
    banned = {"Markup", "markupsafe", "escape_silent", "soft_str", "autoescape=<not True>"}
    offenders = {
        path.name: sorted(_python_names(path) & banned) for path in sorted(PACKAGE.glob("*.py"))
    }
    assert {k: v for k, v in offenders.items() if v} == {}


def test_the_environment_is_sandboxed_autoescaping_and_strict() -> None:
    env = render_html.ENV
    assert isinstance(env, SandboxedEnvironment)
    assert env.autoescape is True
    assert env.undefined is StrictUndefined
    for name in ("safe", "urlize", "xmlattr"):
        assert name not in env.filters
    assert not env.extensions


@pytest.mark.parametrize(
    "source",
    [
        "{{ x|safe }}",
        "{{ x | safe }}",
        "{% if x %}{{ x|safe }}{% endif %}",  # deferred to render time inside a conditional
        "{% filter safe %}{{ x }}{% endfilter %}",
        "{{ x|urlize }}",
        "{{ {'href': x}|xmlattr }}",
        "{% autoescape false %}{{ x }}{% endautoescape %}",
        "{% autoescape true %}{{ x }}{% endautoescape %}",
        "{%- autoescape false -%}{{ x }}{%- endautoescape -%}",
    ],
)
def test_templates_that_turn_escaping_off_fail(source: str) -> None:
    with pytest.raises(TemplateError):
        render_html.ENV.from_string(source).render(x="<script>")


def test_plain_output_is_still_escaped() -> None:
    assert render_html.ENV.from_string("{{ x }}").render(x="<b>") == "&lt;b&gt;"


def test_the_css_is_constant_and_references_nothing() -> None:
    css = render_html.REPORT_CSS_TEXT
    assert not re.search(r"url\s*\(|@import|@font-face|</", css, re.I)
    assert "string-set: tlp content()" in css
