"""Deterministic secret masker (RT13).

Every text quoted from a command line or a bash history line into a shared surface (finding
title / description, IOC values, timeline titles) passes `mask()` first: those surfaces reach
the M7 search index, reports, correlation and, after release, AI context. The raw text stays
only in the job's own records (`memory_processes.cmdline`, `memory_artifacts`).

A masked value keeps its first 2 characters and its length: `P@ssw0rd12` -> `P@********(10)`.
Values of 4 characters or fewer keep nothing (`****(4)`): two kept characters would reveal
half of them.

Spans are collected from every rule on the original text, merged, then replaced once, so a
value matched by two rules is never masked twice. Every pattern is linear (no nested
quantifiers) and the input is at most 4 096 characters (the contract's cmdline bound).
"""

import re
from collections.abc import Iterator

KEEP = 2
SHORT = 4  # values this short keep no character
MASKED = re.compile(r"[^*]{0,2}\*+\(\d{1,4}\)")

# A value: double- or single-quoted, or a run of non-space characters without shell
# separators. Group "v" is what gets masked (the quotes stay visible).
_VALUE = r"""(?:"(?P<dq>[^"\n]{1,512})"|'(?P<sq>[^'\n]{1,512})'|(?P<bare>[^\s"'&;|]{1,512}))"""

# password= / pwd= / passwd= / pass= and the `name:value` switch form (wmic /password:x),
# also as the end of an env-style name (security review): `DB_PASSWORD=`, `MY_DB_PASSWORD=`,
# `MYSQL_PWD=`, `ADMIN_PASS=` (any prefix ending in `_`) and upper-case glued names such as
# `PGPASSWORD=`. A lower-case glued word (`bypass:`, `compass:`) is not a key, and the keyword
# must be followed by `=` / `:` (`PGPASSWORD_FILE=` names a file, not a secret).
_KEY_NAME = (
    r"(?:[A-Za-z0-9]*_(?i:password|passwd|pwd|pass)"
    r"|[A-Z0-9]*(?:PASSWORD|PASSWD|PWD|PASS)"
    r"|(?i:password|passwd|pwd|pass))"
)
_KEY_VALUE = re.compile(r"(?<![A-Za-z0-9])" + _KEY_NAME + r"\s*[=:]\s*" + _VALUE)
# Secret-bearing URL query parameters (security review): the value up to the next `&`, `#`,
# quote or space, so an IOC URL never carries it (the `?password=` form is `_KEY_VALUE`'s).
_URL_QUERY = re.compile(
    r"(?i)[?&;](?:access_token|refresh_token|id_token|auth_token|token|api_key|apikey|key|"
    r"sig|signature|secret|client_secret|x-amz-signature|x-amz-credential|"
    r"x-amz-security-token)=(?P<bare>[^\s&#\"'<>]{1,512})"
)
# PowerShell / CLI `-Password <value>` (space separated).
_DASH_PASSWORD = re.compile(r"(?i)(?<![a-z0-9_-])-(?:password|passwd)\s+" + _VALUE)
# --token / --secret / --api-key (and close relatives), `=` or space separated.
_LONG_FLAG = re.compile(
    r"(?i)--(?:token|secret|api[-_]?key|access[-_]token|auth[-_]token|client[-_]secret|"
    r"password)(?:=|\s+)" + _VALUE
)
# `-p<value>` (mysql family, glued) and `-p <value>` (sshpass) after the tool name, within
# one shell segment.
_MYSQL_TOOL = re.compile(r"(?i)(?<![\w.-])(?:mysql|mysqldump|mysqladmin|mariadb)(?:\.exe)?\b")
_MYSQL_P = re.compile(r"(?<!\S)-p(?P<bare>[^\s\"'&;|]{1,512})")
_SSHPASS_TOOL = re.compile(r"(?i)(?<![\w.-])sshpass\b")
_SSHPASS_P = re.compile(r"(?<!\S)-p\s*" + _VALUE)
_SEGMENT_END = re.compile(r"[;&|\n]")
# net use ... /user:<u> <password>  (the token after the user, unless it is a switch or `*`;
# only after `net use`: `runas /user:<u> <program>` names a program, not a password).
_NET_USE_TOOL = re.compile(r"(?i)(?<![\w.-])net1?(?:\.exe)?\s+use\b")
_NET_USE = re.compile(r"(?i)/user:[^\s/]{1,256}\s+(?P<bare>[^\s/*][^\s&;|]{0,511})")
# net user <name> <password> [/add]
_NET_USER = re.compile(
    r"(?i)(?<![\w.-])net1?(?:\.exe)?\s+user\s+[^\s/]{1,256}\s+(?P<bare>[^\s/*][^\s&;|]{0,511})"
)
# Authorization: Bearer / Basic <credential>
_AUTH_HEADER = re.compile(
    r"(?i)authorization:\s*(?:bearer|basic)\s+(?P<bare>[A-Za-z0-9._~+/=-]{1,2048})"
)
# scheme://user:password@host
_URL_USERINFO = re.compile(
    r"(?i)[a-z][a-z0-9+.-]{0,15}://[^\s/:@]{1,256}:(?P<bare>[^\s/@]{1,256})@"
)
# AWS access key ids (whole match) and 40-character secret-key shapes (mixed case + digit or
# `/` `+`, so hex digests and long base64 payloads do not match).
_AWS_KEY_ID = re.compile(r"(?<![A-Z0-9])(?P<bare>(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16})(?![A-Z0-9])")
_AWS_SECRET = re.compile(r"(?<![A-Za-z0-9/+])(?P<bare>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])")
# PEM private keys: everything between the BEGIN line and the END line (or the text's end).
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----")

_SIMPLE_RULES = (
    _KEY_VALUE,
    _URL_QUERY,
    _DASH_PASSWORD,
    _LONG_FLAG,
    _NET_USER,
    _AUTH_HEADER,
    _URL_USERINFO,
    _AWS_KEY_ID,
)


def mask_value(value: str) -> str:
    keep = KEEP if len(value) > SHORT else 0
    return f"{value[:keep]}{'*' * (len(value) - keep)}({len(value)})"


def _group_span(match: re.Match[str]) -> tuple[int, int] | None:
    for name in ("dq", "sq", "bare"):
        if name in match.re.groupindex and match.group(name) is not None:
            return match.span(name)
    return None


def _tool_spans(
    text: str, tool: re.Pattern[str], flag: re.Pattern[str]
) -> Iterator[tuple[int, int]]:
    for found in tool.finditer(text):
        end = _SEGMENT_END.search(text, found.end())
        segment_end = end.start() if end else len(text)
        # The flag must start in the tool's segment; its quoted value may hold `&` or `;`.
        for match in flag.finditer(text, found.end()):
            if match.start() >= segment_end:
                break
            if (span := _group_span(match)) is not None:
                yield span


def _aws_secret_spans(text: str) -> Iterator[tuple[int, int]]:
    for match in _AWS_SECRET.finditer(text):
        value = match.group("bare")
        if (
            any(c.islower() for c in value)
            and any(c.isupper() for c in value)
            and any(c.isdigit() or c in "/+" for c in value)
        ):
            yield match.span("bare")


def _pem_spans(text: str) -> Iterator[tuple[int, int]]:
    pos = 0
    while (begin := _PEM_BEGIN.search(text, pos)) is not None:
        end = _PEM_END.search(text, begin.end())
        stop = end.start() if end else len(text)
        if stop > begin.end():
            yield begin.end(), stop
        pos = end.end() if end else len(text)


def secret_spans(text: str) -> list[tuple[int, int]]:
    """The merged (start, end) spans of every secret value in `text`."""
    spans: list[tuple[int, int]] = []
    for rule in _SIMPLE_RULES:
        for match in rule.finditer(text):
            if (span := _group_span(match)) is not None:
                spans.append(span)
    spans += _tool_spans(text, _MYSQL_TOOL, _MYSQL_P)
    spans += _tool_spans(text, _SSHPASS_TOOL, _SSHPASS_P)
    spans += _tool_spans(text, _NET_USE_TOOL, _NET_USE)
    spans += _aws_secret_spans(text)
    spans += _pem_spans(text)
    merged: list[tuple[int, int]] = []
    for start, end in sorted(s for s in spans if s[1] > s[0]):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def mask(text: str | None) -> str:
    """`text` with every secret value masked (deterministic; benign text is unchanged)."""
    if not text:
        return ""
    out: list[str] = []
    pos = 0
    for start, end in secret_spans(text):
        value = text[start:end]
        out.append(text[pos:start])
        # An already masked value stays as it is (masking twice is a no-op).
        out.append(value if MASKED.fullmatch(value) else mask_value(value))
        pos = end
    out.append(text[pos:])
    return "".join(out)


def excerpt(text: str | None, limit: int = 300) -> str:
    """Masked, then shortened (masking first: a cut must never expose half a secret)."""
    masked = mask(text).replace("\r", " ").replace("\n", " ")
    return masked if len(masked) <= limit else masked[: limit - 3] + "..."
