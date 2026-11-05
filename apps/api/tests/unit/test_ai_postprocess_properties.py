"""Property tests of `postprocess.clean_text` (M5 phase 5, hypothesis).

Whatever the model writes, the stored text:
- carries no link or markup syntax (`](`, `<a`, `<`, `>`, `![`, `javascript:`) and no live
  `http://` / `https://` / `ftp://` / `://` (only the defanged spellings);
- contains no C0/C1 control, bidi, zero-width or tag character, and no newline or tab
  (whitespace is collapsed);
- fits its cap and is idempotent.
"""

import re
import unicodedata

from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st

from app.modules.ai.postprocess import clean_text
from app.modules.ai.text import refang

PROFILE = settings(
    max_examples=500,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
    derandomize=True,
)

FRAGMENTS = [
    "[",
    "]",
    "(",
    ")",
    "](",
    "![",
    "<",
    ">",
    "<a href=",
    "</a>",
    "<script>",
    "http://",
    "https://",
    "HTTP://",
    "hTtPs://",
    "ftp://",
    "://",
    "javascript:",
    "JaVaScRiPt :",
    "vbscript:",
    "data:text/html,",
    "www.",
    "evil.example",
    ".com",
    "a.b",
    "[.]",
    "[:]",
    "hxxp[:]//",
    "`",
    "**",
    "~~",
    "*",
    " ",
    "\n",
    "\t",
    "\u202e",
    "\u2066",
    "\u200b",
    "\u200d",
    "\ufeff",
    "\U000e0041",
    "\x00",
    "\x1b",
    "\x85",
    "\x7f",
    "é",
    "x",
    "1",
    ".",
    ":",
    "/",
    # Format characters the first sanitizer missed (security review): ALM, soft hyphen,
    # Mongolian vowel separator, word joiner, invisible operators, annotation anchor, ...
    *(chr(c) for c in (0x061C, 0x00AD, 0x180E, 0x2060, 0x2061, 0x2064, 0xFFF9, 0x110BD)),
]

text_strategy = st.lists(
    st.one_of(st.sampled_from(FRAGMENTS), st.text(max_size=8)), max_size=40
).map("".join)
limit_strategy = st.sampled_from([16, 64, 256, 600])

_FORBIDDEN_CHARS = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff\U000e0000-\U000e007f]"
)
_LIVE_SCHEME = re.compile(r"(?:https?|ftp)://|://|javascript\s*:|vbscript\s*:", re.IGNORECASE)


def _assert_display_safe(out: str, limit: int) -> None:
    assert len(out) <= limit
    assert "](" not in out
    assert "<" not in out and ">" not in out
    assert not _LIVE_SCHEME.search(out), out
    assert not _FORBIDDEN_CHARS.search(out), repr(out)
    # No control (Cc) or format (Cf) character at all.
    assert not [c for c in out if unicodedata.category(c) in ("Cc", "Cf")], repr(out)
    assert "\n" not in out and "\t" not in out
    assert out == out.strip()


@PROFILE
@given(text_strategy, limit_strategy)
@example("[x](javascript:alert(1))", 600)
@example("xhttp://glued", 600)
@example("<a href='https://e.example'>e</a>", 600)
@example("*`*", 600)
@example("javascript:(", 600)
@example("éjavascript:", 16)
@example("x" * 13 + " a.bc_d", 16)
def test_clean_text_is_display_safe(raw: str, limit: int) -> None:
    _assert_display_safe(clean_text(raw, limit), limit)


@PROFILE
@given(text_strategy, limit_strategy)
def test_clean_text_is_idempotent(raw: str, limit: int) -> None:
    once = clean_text(raw, limit)
    assert clean_text(once, limit) == once


@PROFILE
@given(st.from_regex(r"[a-z]{1,10}(\.[a-z]{2,6}){1,3}/[a-z0-9]{0,8}", fullmatch=True))
def test_urls_survive_as_defanged_text(host_path: str) -> None:
    out = clean_text(f"see https://{host_path} now", 600)
    _assert_display_safe(out, 600)
    assert refang(out) == f"see https://{host_path} now"
