"""Text normalization shared by the context builder, the verifier and post-processing
(M5 phase 1, FROZEN). Pure functions, no I/O.

- `sanitize` strips invisible and control characters (C0 except `\\n` `\\t`, DEL, C1,
  U+200B-200F, U+202A-202E, U+2066-2069, U+061C, U+FEFF, U+E0000-E007F, and every other
  format character of category Cf such as U+00AD, U+180E, U+2060-2064) and counts them;
- `defang` / `refang`: `http(s)://` -> `hxxp(s)[:]//`, `ftp` -> `fxp`, and the dots of
  domain-like tokens -> `[.]` (IP addresses stay plain); `refang` is the exact inverse;
- `canonical_ip` / `canonical_hash` give one spelling for comparisons;
- `truncate(text, n)` keeps n characters plus an explicit `…[truncated k]` marker.
"""

import ipaddress
import re
import unicodedata
from dataclasses import dataclass

TRUNCATION_MARK = "…[truncated {n}]"


@dataclass
class StripCounts:
    control: int = 0
    bidi: int = 0
    zero_width: int = 0
    tag: int = 0

    @property
    def total(self) -> int:
        return self.control + self.bidi + self.zero_width + self.tag

    def add(self, other: "StripCounts") -> None:
        self.control += other.control
        self.bidi += other.bidi
        self.zero_width += other.zero_width
        self.tag += other.tag

    def as_dict(self) -> dict[str, int]:
        return {
            "control": self.control,
            "bidi": self.bidi,
            "zero_width": self.zero_width,
            "tag": self.tag,
        }


def _category(cp: int) -> str | None:
    if cp in (0x09, 0x0A):
        return None
    if cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F:
        return "control"
    if (
        0x200E <= cp <= 0x200F
        or 0x202A <= cp <= 0x202E
        or 0x2066 <= cp <= 0x2069
        or cp == 0x061C  # ARABIC LETTER MARK (M5 phase-5 security review)
    ):
        return "bidi"
    if 0x200B <= cp <= 0x200D or cp == 0xFEFF:
        return "zero_width"
    if 0xE0000 <= cp <= 0xE007F:
        return "tag"
    if cp < 0xAD:
        return None
    # Every other format character (Cf: soft hyphen U+00AD, Mongolian vowel separator
    # U+180E, word joiner and invisible operators U+2060-2064, interlinear annotation, ...)
    # is invisible too and counted with the zero-width characters.
    if unicodedata.category(chr(cp)) == "Cf":
        return "zero_width"
    return None


# Invisible or blank-looking characters that are not `Cf` and stay in sanitized AI text,
# but the report "make visible" table (`vis_category`, M6 review L7) marks them: combining
# grapheme joiner, Hangul fillers, line / paragraph separators, variation selectors
# (including the supplement).
VIS_EXTRA_RANGES: tuple[tuple[int, int], ...] = (
    (0x034F, 0x034F),
    (0x115F, 0x1160),
    (0x2028, 0x2029),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFFA0, 0xFFA0),
    (0xE0100, 0xE01EF),
)


def vis_category(cp: int) -> str | None:
    """The category of `cp` in the materialized vis table (`scripts/gen_vis_rules.py`):
    `_category`, plus `invisible` for `VIS_EXTRA_RANGES`. Display only: `sanitize` keeps
    using `_category`, so M5 context text is unchanged."""
    category = _category(cp)
    if category is None and any(start <= cp <= end for start, end in VIS_EXTRA_RANGES):
        return "invisible"
    return category


def sanitize(text: str) -> tuple[str, StripCounts]:
    counts = StripCounts()
    kept: list[str] = []
    for ch in text:
        category = _category(ord(ch))
        if category is None:
            kept.append(ch)
        else:
            setattr(counts, category, getattr(counts, category) + 1)
    return "".join(kept), counts


def nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)


_WS = re.compile(r"\s+")


def collapse_ws(text: str) -> str:
    return _WS.sub(" ", text).strip()


def truncate(text: str, n: int) -> str:
    if n < 0:
        raise ValueError("n must be >= 0")
    if len(text) <= n:
        return text
    return text[:n] + TRUNCATION_MARK.format(n=len(text) - n)


# --- defang / refang -----------------------------------------------------------------------

_SCHEME = re.compile(r"\b(h)(tt)(ps?)://|\b(f)(t)(p)://", re.IGNORECASE)
# A domain-like token: labels separated by dots, ending in a letter-led TLD (so dotted IPs
# never match). Already-defanged `[.]` is not a dot, so defang is idempotent.
_DOMAIN = re.compile(
    r"(?<![\w.-])((?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{0,62})(?![\w-])",
    re.IGNORECASE,
)
_REFANG_SCHEME = re.compile(r"\b(h)(xx)(ps?)\[:\]//|\b(f)(x)(p)\[:\]//", re.IGNORECASE)
_T_TO_X = str.maketrans("tT", "xX")
_X_TO_T = str.maketrans("xX", "tT")


def _scheme_sub(match: re.Match[str]) -> str:
    head, mid, tail = match.group(1, 2, 3) if match.group(1) else match.group(4, 5, 6)
    return f"{head}{mid.translate(_T_TO_X)}{tail}[:]//"


def _refang_scheme_sub(match: re.Match[str]) -> str:
    head, mid, tail = match.group(1, 2, 3) if match.group(1) else match.group(4, 5, 6)
    return f"{head}{mid.translate(_X_TO_T)}{tail}://"


def defang(text: str) -> str:
    text = _SCHEME.sub(_scheme_sub, text)
    return _DOMAIN.sub(lambda m: m.group(1).replace(".", "[.]"), text)


def refang(text: str) -> str:
    text = _REFANG_SCHEME.sub(_refang_scheme_sub, text)
    return text.replace("[.]", ".").replace("[:]", ":")


# --- canonical forms -----------------------------------------------------------------------

_HASH = re.compile(r"[0-9a-fA-F]+")
_HASH_LENGTHS = frozenset({32, 40, 64, 128})


def canonical_ip(text: str) -> str | None:
    """`10.0.0.1`, `::ffff:10.0.0.1` -> `10.0.0.1`; IPv6 compressed lowercase; else None."""
    candidate = text.strip().strip("[]")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return address.compressed


def canonical_hash(text: str) -> str | None:
    """A hex md5 / sha1 / sha256 / sha512 in lowercase; else None."""
    candidate = text.strip()
    if len(candidate) in _HASH_LENGTHS and _HASH.fullmatch(candidate):
        return candidate.lower()
    return None
