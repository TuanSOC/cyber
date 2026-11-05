"""Post-processing of model free text (M5 phase 5). Pure functions, no I/O.

`clean_text` turns any model string into display-safe plain text:
1. `text.sanitize` (C0/C1 controls, bidi, zero-width and tag characters), then NFC;
2. markup stripped into plain text: markdown links and images `[x](y)` / `![x](y)` become
   `x y`, autolinks `<scheme:...>` lose their brackets, HTML-like tags are removed, any other
   `<` / `>` becomes `‹` / `›`, backticks and `**` / `~~` emphasis go, and a `](` that is
   still left is split, so no link syntax survives;
3. `text.defang` for URLs and domains, plus a catch-all for any remaining `scheme://` (also
   glued to a preceding word) and `javascript:` / `vbscript:` / `data:<mime>` schemes;
4. whitespace collapsed to single spaces, then the length cap.
It is idempotent (`clean_text(clean_text(x)) == clean_text(x)`, property-tested).

The flag scanners work on the sanitized text before markup stripping:
- `verdict_language`: clean / benign / safe / harmless / malicious used as a conclusion;
- `command_like`: shell prompts, `sudo`, `powershell -`, `cmd /c`, `curl … | sh`, `rm -rf`,
  `Invoke-*`, … (next steps only);
- `find_urls`: scheme URLs (and `www.` hosts) in refanged text, for the `external_url` flag.
They only flag; content is never dropped because of them.
"""

import re
from dataclasses import dataclass, field

from app.modules.ai import text as ai_text
from app.modules.ai.text import StripCounts

# --- markup ------------------------------------------------------------------------------

_MD_LINK = re.compile(r"!?\[([^\[\]]*)\]\(([^()]*)\)")
_AUTOLINK = re.compile(r"<((?:[A-Za-z][A-Za-z0-9+.-]{1,31}):[^<>\s]*)>")
_TAG = re.compile(r"</?[A-Za-z!?][^<>]{0,256}>")
_EMPHASIS = re.compile(r"\*\*|~~|`+")
# Any scheme separator left after `text.defang` (which needs a word boundary before `http`).
_SCHEME_ANY = re.compile(r"(h)(tt)(ps?)://|(f)(t)(p)://", re.IGNORECASE)
_SEPARATOR = re.compile(r"://")
# No word boundary: `éjavascript:` must not survive either.
_SCRIPT_SCHEME = re.compile(r"(javascript|vbscript)\s*:", re.IGNORECASE)
_DATA_SCHEME = re.compile(r"(data)\s*:(?=\s*[a-z]+/)", re.IGNORECASE)
_T_TO_X = str.maketrans("tT", "xX")


def _scheme_sub(match: re.Match[str]) -> str:
    head, mid, tail = match.group(1, 2, 3) if match.group(1) else match.group(4, 5, 6)
    return f"{head}{mid.translate(_T_TO_X)}{tail}[:]//"


def strip_markup(value: str) -> tuple[str, int]:
    """Markup characters into plain text; returns the text and the number of rewrites."""
    count = 0
    while True:
        value, n = _MD_LINK.subn(lambda m: f"{m.group(1)} {m.group(2)}", value)
        count += n
        if n == 0:
            break
    value, n = _AUTOLINK.subn(r"\1", value)
    count += n
    value, n = _TAG.subn(" ", value)
    count += n
    count += value.count("<") + value.count(">")
    value = value.replace("<", "‹").replace(">", "›")
    while True:
        # Removing a backtick can join two `*` into a new `**`: repeat to a fixed point.
        value, n = _EMPHASIS.subn("", value)
        count += n
        if n == 0:
            break
    count += value.count("](")
    value = value.replace("](", "] (")
    return value, count


def defang_all(value: str) -> str:
    value = ai_text.defang(value)
    value = _SCHEME_ANY.sub(_scheme_sub, value)
    value = _SEPARATOR.sub("[:]//", value)
    value = _SCRIPT_SCHEME.sub(lambda m: f"{m.group(1)}[:]", value)
    return _DATA_SCHEME.sub(lambda m: f"{m.group(1)}[:]", value)


@dataclass
class CleanStats:
    """Strip counts over every string of one output (`RunMetrics.strip_counts`)."""

    strip: StripCounts = field(default_factory=StripCounts)
    markup: int = 0
    capped: int = 0

    def as_dict(self) -> dict[str, int]:
        return {**self.strip.as_dict(), "markup": self.markup, "capped": self.capped}


def sanitized(value: str) -> tuple[str, StripCounts]:
    """`text.sanitize` then NFC (the order keeps a removed joiner from changing NFC)."""
    clean, counts = ai_text.sanitize(value)
    return ai_text.nfc(clean), counts


_MAX_PASSES = 6


def _clean_once(value: str, limit: int) -> tuple[str, int, bool]:
    clean, markup = strip_markup(value)
    # Defanging a script scheme can glue `[:]` to a `(`: split any `](` once more.
    clean = ai_text.collapse_ws(defang_all(clean).replace("](", "] ("))
    capped = len(clean) > limit
    if capped:
        clean = clean[:limit].rstrip()
    return clean, markup, capped


def clean_text(value: str, limit: int, stats: CleanStats | None = None) -> str:
    """Display-safe plain text of at most `limit` characters (see the module docstring).

    The steps run to a fixed point: a cut at `limit` can expose a token (`a.b` at the very
    end) that the next pass would defang, so the result is idempotent by construction."""
    clean, counts = sanitized(value)
    markup = 0
    capped = False
    for _ in range(_MAX_PASSES):
        cleaned, n, cut = _clean_once(clean, limit)
        markup += n
        capped = capped or cut
        if cleaned == clean:
            break
        clean = cleaned
    if stats is not None:
        stats.strip.add(counts)
        stats.markup += markup
        stats.capped += int(capped)
    return clean


# --- flags --------------------------------------------------------------------------------

_VERDICT_WORDS = r"(?:clean|benign|safe|harmless|malicious|malware[- ]free|non[- ]malicious)"
_QUALIFIERS = (
    r"(?:(?:not|probably|likely|very likely|almost certainly|certainly|definitely|clearly|"
    r"entirely|completely|totally|fully|most likely|highly|confirmed|considered|deemed|"
    r"assessed as|classified as|determined to be)\s+)*"
)
_VERDICT = re.compile(
    r"\b(?:is|are|was|were|be|been|being|appears?(?: to be)?|seems?(?: to be)?|looks?|"
    r"remains?|considered|deemed|classified as|assessed as|determined to be|confirmed|"
    r"verdict(?:\s+is)?\s*[:=-]?|conclusion\s*[:=-]?|overall\s*[:=-]?)\s+"
    + _QUALIFIERS
    + _VERDICT_WORDS
    + r"\b(?!\s+to\b)"
    + r"|\b"
    + _VERDICT_WORDS
    + r"\s+(?:verdict|conclusion|file|sample|binary|executable|host|traffic|capture)\b",
    re.IGNORECASE,
)

_COMMAND = re.compile(
    r"(?:^|\s)(?:\$|#|PS(?:\s+[A-Za-z]:\\[^>\s]*)?>|[A-Za-z]:\\[^>\s]*>)\s*"
    r"(?:sudo|rm|ls|cat|curl|wget|chmod|chown|bash|sh|zsh|python3?|perl|nc|ncat|ssh|scp|cd|"
    r"echo|kill|pkill|systemctl|service|iptables|netstat|tcpdump|dd|mv|cp|net|reg|sc|"
    r"taskkill|powershell|cmd|Get-|Set-|Remove-|Stop-|Start-|Invoke-)"
    r"|\bsudo\s+\S"
    r"|\bpowershell(?:\.exe)?\s+-"
    r"|\bpwsh(?:\.exe)?\s+-"
    r"|\bcmd(?:\.exe)?\s+/[ck]\b"
    r"|\b(?:curl|wget)\b[^|\n]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"
    r"|\brm\s+-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r)[a-zA-Z]*\b"
    r"|\bInvoke-[A-Za-z]+"
    r"|\b(?:iex|IEX)\s*\("
    r"|\bchmod\s+(?:\+x|[0-7]{3,4})\b"
    r"|\bbase64\s+-d\b"
    r"|\breg(?:\.exe)?\s+(?:add|delete)\b"
    r"|\bschtasks(?:\.exe)?\s+/create\b",
    re.IGNORECASE | re.MULTILINE,
)

_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`]+|\bwww\.[^\s<>\"'`]+", re.IGNORECASE)
_URL_TRAIL = ".,;:!?)]}'\""


def has_verdict_language(value: str) -> bool:
    return _VERDICT.search(sanitized(value)[0]) is not None


def is_command_like(value: str) -> bool:
    return _COMMAND.search(sanitized(value)[0]) is not None


def find_urls(value: str) -> list[str]:
    """URLs in `value` after sanitize + refang (defanged spellings count), trailing
    punctuation trimmed."""
    text = ai_text.refang(sanitized(value)[0])
    return [m.group(0).rstrip(_URL_TRAIL) for m in _URL.finditer(text)]
