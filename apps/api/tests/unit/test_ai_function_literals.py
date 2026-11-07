"""The linear C scanner behind the `Q.code` cuts (M10 phase 9, `ai/context/c_literals.py`):
lossless, contiguous spans; literals, comments and identifiers recognized; linear time on
hostile inputs (1 MiB of quotes, backslashes and comment openers); RT16 cuts counted."""

import random
import time

import pytest

from app.modules.ai.context import c_literals as C

SAMPLE = (
    'int f(char *s) {\n  // a "comment"\n  puts(L"wide \\" quote");\n  c = \'\\\'\';\n'
    "  /* block 'x' */ x = 0x5a + 1e3 + u8\"utf\";\n}\n"
)


def _kinds(text: str) -> list[tuple[str, str]]:
    return [(s.kind, text[s.start : s.end]) for s in C.scan(text) if s.kind != "code"]


def _lossless(text: str) -> None:
    spans = C.scan(text)
    assert "".join(text[s.start : s.end] for s in spans) == text
    position = 0
    for span in spans:
        assert span.start == position and span.end > span.start
        position = span.end
    assert position == len(text)


def test_literals_comments_and_identifiers_are_recognized() -> None:
    found = _kinds(SAMPLE)
    assert ("comment", '// a "comment"') in found
    assert ("string", 'L"wide \\" quote"') in found
    assert ("char", "'\\''") in found
    assert ("comment", "/* block 'x' */") in found
    assert ("string", 'u8"utf"') in found
    idents = [t for k, t in found if k == "identifier"]
    assert "puts" in idents and "x5a" not in idents and "e3" not in idents
    _lossless(SAMPLE)


@pytest.mark.parametrize(
    "text",
    [
        "",
        '"',
        "'",
        "\\",
        '"abc',
        '"abc\nnext"',
        "/*",
        "/* never closed",
        "//",
        '"\\',
        "'\\\n'",
        "раyload_init(сount)",
        "L",
        'u8"',
    ],
)
def test_edge_cases_stay_lossless(text: str) -> None:
    _lossless(text)


def test_an_unterminated_literal_ends_at_the_line_break() -> None:
    text = 'puts("open\nreturn;'
    spans = [(s.kind, text[s.start : s.end]) for s in C.scan(text)]
    assert ("string", '"open') in spans
    assert ("identifier", "return") in spans


def test_non_ascii_identifiers_are_identifiers() -> None:
    text = "void раyload_init(void)"
    assert ("identifier", "раyload_init") in _kinds(text)


def test_random_input_is_lossless() -> None:
    rng = random.Random(1010)
    alphabet = 'ab_ 0x9"\'\\/*\n\t;{}()L8uU‮а'
    for _ in range(500):
        _lossless("".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 200))))


@pytest.mark.parametrize("unit", ['"', "\\", "/*", "'", '"\\', "//\n", "a", "‮"])
def test_hostile_megabyte_inputs_scan_in_linear_time(unit: str) -> None:
    text = unit * (1_048_576 // len(unit))
    started = time.perf_counter()
    spans = C.scan(text)
    elapsed = time.perf_counter() - started
    assert sum(s.end - s.start for s in spans) == len(text)
    # One pass: a 1 MiB input takes well under a few seconds even on a slow CI host
    # (a quadratic scanner would take hours).
    assert elapsed < 10, elapsed


def test_long_literals_and_identifiers_are_cut_with_markers_and_counted() -> None:
    literal = "A" * 300
    ident = "b" * 255
    text = f'puts("{literal}");\n{ident}();\nputs("short");'
    result = C.cut(text)
    assert result.literals_cut == 1 and result.identifiers_cut == 1
    out = result.text
    assert '"' + "A" * C.MAX_LITERAL_CHARS + "…[cut 204]" + '"' in out
    assert "b" * C.MAX_IDENTIFIER_CHARS + "…[cut 191]" in out
    assert 'puts("short")' in out
    # The cut literal is still one literal: the closing quote survives.
    assert [s.kind for s in C.scan(out)].count("string") == 2


def test_a_cut_never_leaves_a_dangling_backslash() -> None:
    content = "x" * (C.MAX_LITERAL_CHARS - 1) + "\\n" + "y" * 50
    result = C.cut(f'"{content}"')
    out = result.text
    assert result.literals_cut == 1
    head = out[1 : out.index("…[cut")]
    assert (len(head) - len(head.rstrip("\\"))) % 2 == 0
    assert out.endswith('"')


def test_short_text_is_unchanged() -> None:
    result = C.cut(SAMPLE)
    assert result.text == SAMPLE and result.literals_cut == 0 and result.identifiers_cut == 0
