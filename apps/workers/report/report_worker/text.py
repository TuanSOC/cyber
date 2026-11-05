"""Value formatting shared by the HTML and Markdown renderers (pure, no I/O).

Every function returns plain text; escaping is the caller's job (Jinja2 autoescape for HTML,
`render_md` for Markdown). `vis` is the only text rule (RT24): the snapshot already holds the
defanged form, so nothing here defangs.
"""

import re
import unicodedata
from datetime import UTC, datetime

from cyberlab_jobs.report import TLP, TLP_DEFINITIONS, TLP_LABELS
from cyberlab_jobs.vis import vis

__all__ = [
    "SEVERITY_CLASSES",
    "TLP_CLASSES",
    "case_footer",
    "opt",
    "runs",
    "sev_class",
    "short_sha",
    "tlp_class",
    "tlp_definition",
    "tlp_label",
    "ts",
    "vis",
]

# Fixed CSS classes: nothing from the data ever becomes a class name or a style.
SEVERITY_CLASSES: dict[str, str] = {
    "critical": "sev-critical",
    "high": "sev-high",
    "medium": "sev-medium",
    "low": "sev-low",
    "info": "sev-info",
}
TLP_CLASSES: dict[TLP, str] = {
    TLP.CLEAR: "tlp-clear",
    TLP.GREEN: "tlp-green",
    TLP.AMBER: "tlp-amber",
    TLP.AMBER_STRICT: "tlp-amber-strict",
    TLP.RED: "tlp-red",
}
EMPTY = "—"
# A break opportunity at least every RUN_CHARS characters of an unbroken run (see `runs`).
RUN_CHARS = 512
_LONG_RUN = re.compile(rf"\S{{{RUN_CHARS + 1},}}")


def ts(value: datetime | None) -> str:
    """`2026-11-06 09:00:00 UTC` (seconds precision), or an em dash."""
    if value is None:
        return EMPTY
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def opt(value: object) -> str:
    """None or an empty string as an em dash; anything else as visible text."""
    if value is None or value == "":
        return EMPTY
    return vis(str(value))


def sev_class(severity: str | None) -> str:
    return SEVERITY_CLASSES.get((severity or "").lower(), "sev-unknown")


def tlp_label(tlp: TLP | str) -> str:
    return TLP_LABELS[TLP(tlp)]


def tlp_class(tlp: TLP | str) -> str:
    return TLP_CLASSES[TLP(tlp)]


def tlp_definition(tlp: TLP | str) -> str:
    return TLP_DEFINITIONS[TLP(tlp)]


def short_sha(sha256: str) -> str:
    return sha256[:12]


def case_footer(case_ref: str, version: int, sha256: str) -> str:
    """The footer line of every page: `CASE-00012 v2 sha256:0123456789ab…`."""
    return f"{case_ref} v{version} sha256:{short_sha(sha256)}…"


def runs(value: str) -> list[str]:
    """`vis(value)` cut into pieces: inside every unbroken run (no whitespace) longer than
    `RUN_CHARS`, a cut every `RUN_CHARS` characters (never before a combining mark).

    The HTML templates join the pieces with `<wbr>`, a break opportunity that adds no
    character. WeasyPrint lays out the whole rest of an unbroken run for every line it
    breaks (`overflow-wrap: anywhere`), which is quadratic in the run's length; with these
    breaks a 20 000-character run costs as much as 20 000 characters of prose (RT1).
    `"".join(runs(v)) == vis(v)`.
    """
    shown = vis(value)
    if len(shown) <= RUN_CHARS:
        return [shown]
    pieces: list[str] = []
    last = 0
    for match in _LONG_RUN.finditer(shown):
        cut, end = match.start() + RUN_CHARS, match.end()
        while cut < end:
            while cut < end and unicodedata.combining(shown[cut]):
                cut += 1
            if cut >= end:
                break
            pieces.append(shown[last:cut])
            last = cut
            cut += RUN_CHARS
    pieces.append(shown[last:])
    return pieces
