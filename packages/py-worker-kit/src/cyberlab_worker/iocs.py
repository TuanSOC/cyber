"""IOCs from strings (observables, not verdicts; no enrichment).

Shared by the static analyzer (strings) and the memory analyzer (command lines, bash
history): lifted verbatim from `static_worker/detections/iocs.py` in M8 phase 1, which is now a
re-export shim (no behaviour change).

Strings are attacker-controlled and already capped at 512 characters; every pattern is
linear (no nested quantifiers), so matching is bounded per string. Heuristics against the
usual false positives, documented here because they shape what analysts see:
- domains need a known TLD and must be lowercase (`kernel32.dll`, `System.Net` are not);
- IPv4 inside version-like text (`version="6.0.0.0"`, `x.y.0.0`) and special-use ranges
  (loopback, unspecified, multicast, link-local) are skipped;
- IPv6 needs three non-empty groups (`std::` and `d::` are not addresses);
- file paths: drive-letter / %ENV% / \\?\\ Windows paths, and Unix paths under directories
  of interest (/etc, /tmp, /dev/shm, ...), not every library path.
"""

import ipaddress
import re
from dataclasses import dataclass, field

TLDS = frozenset(
    """com net org info biz io co me tv cc us uk de fr ru cn jp kr br in it es nl pl se ch at
    be cz eu ua kz by ir tr vn id th my sg hk tw au ca mx ar cl za ng ke eg sa ae il gr pt ro
    hu dk no fi ie nz online site top xyz club live app dev cloud space tech shop store pw su
    ws to ly gg la nu link click download host website onion bit""".split()
)
# No leading \b: extracted strings often carry a glued byte ("ehttps://..." from UTF-16).
URL_RE = re.compile(r"(?:https?|ftp)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{3,2000}", re.I)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9\-]{1,63}\.){1,8}[A-Za-z]{2,24}\b")
DOMAIN_RE = re.compile(
    r"(?<![\w.@-])(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.){1,8}[A-Za-z]{2,24}(?![\w.-])"
)
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
REGISTRY_RE = re.compile(
    r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKLM|HKCU|HKCR)"
    r"\\[^\x00-\x1f\"<>|]{1,250}"
    r"|\b(?:SOFTWARE|SYSTEM)\\(?:Microsoft|CurrentControlSet|Classes|Policies|Wow6432Node)"
    r"\\[^\x00-\x1f\"<>|]{1,250}",
    re.I,
)
RUN_KEY_RE = re.compile(
    r"\\CurrentVersion\\(?:Run|RunOnce|RunServices|Policies\\Explorer\\Run)\b", re.I
)
WINDOWS_PATH_RE = re.compile(
    r"(?:\b[A-Za-z]:\\|%[A-Za-z_]{2,32}%\\|\\\\\?\\)[^\x00-\x1f\"<>|*?]{1,250}"
)
UNIX_PATH_RE = re.compile(
    r"(?<![\w/.])/(?:etc|tmp|var/tmp|dev/shm|root|home|proc/self|usr/local/bin|var/spool/cron)"
    r"/[^\x00-\x20\"'<>|;]{0,250}"
)
TRAILING = ".,;:)'\"]}>"


def has_run_key(text: str) -> bool:
    return RUN_KEY_RE.search(text) is not None


def _ipv4(candidate: str, context: str) -> str | None:
    if "version" in context.lower():
        return None
    try:
        address = ipaddress.IPv4Address(candidate)
    except ValueError:
        return None
    octets = candidate.split(".")
    if octets[0] == "0" or octets[2:] == ["0", "0"]:
        return None
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        return None
    if address.is_link_local or address.is_reserved:
        return None
    return str(address)


def _ipv6(candidate: str) -> str | None:
    if sum(1 for group in candidate.split(":") if group) < 3:
        return None
    try:
        address = ipaddress.IPv6Address(candidate)
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified or address.is_link_local:
        return None
    if address.is_multicast:
        return None
    return str(address)


def _domain(candidate: str) -> str | None:
    value = candidate.rstrip(".")
    if value != value.lower() or value.rsplit(".", 1)[-1] not in TLDS:
        return None
    if all(part.isdigit() for part in value.split(".")[:-1]):
        return None
    return value


@dataclass
class Seen:
    count: int
    source: str


@dataclass
class IocCollector:
    """Deduplicated (type, value) -> count + first source; capped at `limit` entries."""

    limit: int
    entries: dict[tuple[str, str], Seen] = field(default_factory=dict)
    capped: bool = False

    def add(self, kind: str, value: str | None, source: str) -> None:
        if not value:
            return
        key = (kind, value[:2048])
        seen = self.entries.get(key)
        if seen is not None:
            seen.count += 1
        elif len(self.entries) >= self.limit:
            self.capped = True
        else:
            self.entries[key] = Seen(1, source)

    def observe(self, text: str, source: str) -> None:
        hosts_in_urls: set[str] = set()
        for match in URL_RE.finditer(text):
            url = match.group().rstrip(TRAILING)
            self.add("url", url, source)
            host = url.split("://", 1)[1].split("/", 1)[0].split("?", 1)[0].rsplit("@", 1)[-1]
            host = host.split(":", 1)[0].lower() if not host.startswith("[") else host
            hosts_in_urls.add(host)
            if (ip := _ipv4(host, "")) is not None:
                self.add("ip", ip, source)
            elif (domain := _domain(host)) is not None:
                self.add("domain", domain, source)
        emails = {m.group() for m in EMAIL_RE.finditer(text)}
        for email in emails:
            self.add("email", email.lower(), source)
        email_domains = {e.rsplit("@", 1)[1].lower() for e in emails}
        for match in DOMAIN_RE.finditer(text):
            domain = _domain(match.group())
            if domain and domain not in hosts_in_urls and domain not in email_domains:
                self.add("domain", domain, source)
        for match in IPV4_RE.finditer(text):
            if match.group() not in hosts_in_urls:
                self.add("ip", _ipv4(match.group(), text), source)
        if text.count(":") >= 2:
            for match in IPV6_RE.finditer(text):
                self.add("ip", _ipv6(match.group()), source)
        for match in REGISTRY_RE.finditer(text):
            self.add("registry_key", match.group().rstrip(TRAILING + " "), source)
        for pattern in (WINDOWS_PATH_RE, UNIX_PATH_RE):
            for match in pattern.finditer(text):
                path = match.group().rstrip(TRAILING + " ")
                if not URL_RE.match(path):
                    self.add("file_path", path, source)
