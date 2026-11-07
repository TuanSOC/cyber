"""A linear-time scanner for decompiled C (M10 phase 9; the Python twin of the web
`lib/c-tokenizer.ts`, reduced to what the `Q.code` transforms need).

`scan(text)` splits a text into lossless, contiguous spans (`"".join(text[s.start:s.end])
== text`): string literals (`"…"`, with an optional `L` / `u` / `U` / `u8` prefix), char
literals (`'…'`), comments (`//…` and `/*…*/`), identifiers and everything else (`code`).
One pass, no regular expression: each character is looked at a bounded number of times, so
1 MiB of quotes, backslashes or `/*` costs the same as 1 MiB of letters. A literal or line
comment never crosses a line break (an unterminated literal ends before the newline); an
unterminated block comment runs to the end.

`cut(text)` applies the RT16 bounds before the M5 transforms: each literal's content is cut
to `MAX_LITERAL_CHARS` and each identifier to `MAX_IDENTIFIER_CHARS`, with an explicit
`…[cut n]` marker (kept inside the quotes, so the literal stays a literal), and counted.
Decompiled code is attacker-influenced text: exported and symbol names reach it verbatim
and string literals carry whatever the binary stores.
"""

from dataclasses import dataclass
from typing import Literal

SpanKind = Literal["code", "identifier", "string", "char", "comment"]

MAX_LITERAL_CHARS = 96
MAX_IDENTIFIER_CHARS = 64
CUT_MARK = "…[cut {n}]"
_PREFIXES = frozenset({"L", "u", "U", "u8"})
# Kinds whose text can carry free text (URLs, hosts, paths): the value transforms apply.
TEXT_KINDS: frozenset[SpanKind] = frozenset({"string", "char", "comment"})


@dataclass(frozen=True, slots=True)
class Span:
    kind: SpanKind
    start: int
    end: int


def _ident_start(ch: str) -> bool:
    # Non-ASCII letters count: homoglyph identifiers (a Cyrillic `а`) are identifiers too.
    return ch == "_" or ch == "$" or ch.isalpha()


def _ident_char(ch: str) -> bool:
    return ch == "_" or ch == "$" or ch.isalnum()


def _literal_end(text: str, quote_at: int) -> int:
    """The end (exclusive) of the literal whose opening quote is at `quote_at`."""
    quote = text[quote_at]
    n = len(text)
    j = quote_at + 1
    while j < n:
        ch = text[j]
        if ch == "\\":
            j += 2  # an escape (a backslash-newline continuation keeps the literal open)
            continue
        if ch == quote:
            return j + 1
        if ch == "\n":
            return j  # unterminated: ends before the line break
        j += 1
    return n


def scan(text: str) -> list[Span]:
    spans: list[Span] = []
    n = len(text)
    code_start = 0
    i = 0

    def emit(kind: SpanKind, start: int, end: int) -> None:
        nonlocal code_start
        if start > code_start:
            spans.append(Span("code", code_start, start))
        spans.append(Span(kind, start, end))
        code_start = end

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            end = text.find("\n", i + 2)
            end = n if end < 0 else end
            emit("comment", i, end)
            i = end
        elif ch == "/" and nxt == "*":
            close = text.find("*/", i + 2)
            end = n if close < 0 else close + 2
            emit("comment", i, end)
            i = end
        elif ch == '"' or ch == "'":
            end = _literal_end(text, i)
            emit("string" if ch == '"' else "char", i, end)
            i = end
        elif ch.isdigit():
            # A number (`0x5a`, `1e3`, `10u`) is code: its letters never start an identifier.
            j = i + 1
            while j < n and (text[j] == "_" or text[j] == "." or text[j].isalnum()):
                j += 1
            i = j
        elif _ident_start(ch):
            j = i + 1
            while j < n and _ident_char(text[j]):
                j += 1
            if j < n and text[j] in "\"'" and text[i:j] in _PREFIXES:
                end = _literal_end(text, j)
                emit("string" if text[j] == '"' else "char", i, end)
                i = end
            else:
                emit("identifier", i, j)
                i = j
        else:
            i += 1
    if code_start < n:
        spans.append(Span("code", code_start, n))
    return spans


@dataclass(frozen=True, slots=True)
class Segment:
    kind: SpanKind
    text: str


@dataclass(frozen=True, slots=True)
class CutResult:
    segments: tuple[Segment, ...]
    literals_cut: int
    identifiers_cut: int

    @property
    def text(self) -> str:
        return "".join(s.text for s in self.segments)


def _cut_literal(raw: str) -> str | None:
    """`raw` with its content cut to MAX_LITERAL_CHARS, or None when it fits."""
    quote_at = 0
    while quote_at < len(raw) and raw[quote_at] not in "\"'":
        quote_at += 1
    if quote_at >= len(raw):
        return None
    quote = raw[quote_at]
    closed = len(raw) - quote_at >= 2 and raw.endswith(quote) and not _escaped_end(raw)
    content = raw[quote_at + 1 : len(raw) - 1] if closed else raw[quote_at + 1 :]
    if len(content) <= MAX_LITERAL_CHARS:
        return None
    head = content[:MAX_LITERAL_CHARS]
    # Never end on a lone backslash (it would escape the marker or the closing quote).
    trailing = len(head) - len(head.rstrip("\\"))
    if trailing % 2:
        head = head[:-1]
    marker = CUT_MARK.format(n=len(content) - len(head))
    return raw[: quote_at + 1] + head + marker + (quote if closed else "")


def _escaped_end(raw: str) -> bool:
    """The final quote is preceded by an odd number of backslashes (so it is escaped)."""
    k = len(raw) - 2
    count = 0
    while k >= 0 and raw[k] == "\\":
        count += 1
        k -= 1
    return count % 2 == 1


def cut(text: str) -> CutResult:
    segments: list[Segment] = []
    literals = 0
    identifiers = 0
    for span in scan(text):
        raw = text[span.start : span.end]
        if span.kind in ("string", "char"):
            shorter = _cut_literal(raw)
            if shorter is not None:
                raw = shorter
                literals += 1
        elif span.kind == "identifier" and len(raw) > MAX_IDENTIFIER_CHARS:
            raw = raw[:MAX_IDENTIFIER_CHARS] + CUT_MARK.format(
                n=len(raw) - MAX_IDENTIFIER_CHARS
            )
            identifiers += 1
        segments.append(Segment(span.kind, raw))
    return CutResult(tuple(segments), literals, identifiers)
