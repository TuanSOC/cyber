"""Unit tests for the allowlist User-Agent parser (M11 phase 4)."""

import pytest

from app.modules.identity.ua import parse_user_agent


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, "Unknown"),
        ("", "Unknown"),
        ("   ", "Unknown"),
        ("CustomAttackerTool/1.0", "Unknown"),
        ("<script>alert(1)</script>", "Unknown"),
        ("' OR '1'='1", "Unknown"),
        ("x" * 1000, "Unknown"),
        # Standard browsers
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
            "Firefox on Windows",
        ),
        (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Chrome on macOS",
        ),
        (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Safari on macOS",
        ),
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Edge on Windows",
        ),
        (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Chrome on Linux",
        ),
        (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            "Safari on iOS",
        ),
        (
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Chrome on Android",
        ),
        # Command line tools
        ("curl/7.88.1", "Curl on Unknown OS"),
        ("python-requests/2.31.0", "Python on Unknown OS"),
        ("python-httpx/0.27.0", "Python on Unknown OS"),
    ],
)
def test_parse_user_agent(raw: str | None, expected: str) -> None:
    assert parse_user_agent(raw) == expected

