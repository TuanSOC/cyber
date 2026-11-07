"""Allowlist-based coarse User-Agent parser (M11 phase 4).

Extracts only safe browser and OS family summaries (e.g. "Firefox on Windows") to prevent
attacker-controlled strings from entering the UI or enabling fingerprinting.
"""

from __future__ import annotations

import re

# Browser patterns evaluated in specific order (e.g. Edge before Chrome, Chrome before Safari).
_BROWSERS = (
    ("Edge", re.compile(r"\b(?:edg|edge|edga|edgios)\b", re.IGNORECASE)),
    ("Opera", re.compile(r"\b(?:opera|opr)\b", re.IGNORECASE)),
    ("Chrome", re.compile(r"\b(?:chrome|crios)\b", re.IGNORECASE)),
    ("Firefox", re.compile(r"\b(?:firefox|fxios)\b", re.IGNORECASE)),
    ("Safari", re.compile(r"\b(?:safari|version\/[\d\.]+.*safari)\b", re.IGNORECASE)),
    ("Curl", re.compile(r"\bcurl\b", re.IGNORECASE)),
    ("Python", re.compile(r"\b(?:python-requests|python-httpx|python|aiohttp)\b", re.IGNORECASE)),
)

# OS patterns evaluated in order (Android before Linux, iOS before macOS).
_OS = (
    ("Android", re.compile(r"\bandroid\b", re.IGNORECASE)),
    ("iOS", re.compile(r"\b(?:iphone|ipad|ipod|cpu iphone os)\b", re.IGNORECASE)),
    ("Windows", re.compile(r"\b(?:windows|win32|win64)\b", re.IGNORECASE)),
    ("macOS", re.compile(r"\b(?:macintosh|mac os x|macos)\b", re.IGNORECASE)),
    ("Linux", re.compile(r"\b(?:linux|x11)\b", re.IGNORECASE)),
)


def parse_user_agent(raw: str | None) -> str:
    """Return a coarse summary like 'Firefox on Windows', or 'Unknown'.

    Never echoes the raw User-Agent or any unapproved tokens.
    """
    if not raw or not isinstance(raw, str):
        return "Unknown"

    browser_family: str | None = None
    for name, pattern in _BROWSERS:
        if pattern.search(raw):
            browser_family = name
            break

    os_family: str | None = None
    for name, pattern in _OS:
        if pattern.search(raw):
            os_family = name
            break

    if browser_family and os_family:
        return f"{browser_family} on {os_family}"
    if browser_family:
        return f"{browser_family} on Unknown OS"
    if os_family:
        return f"Unknown browser on {os_family}"
    return "Unknown"

