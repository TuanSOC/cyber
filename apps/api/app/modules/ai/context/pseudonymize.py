"""Pseudonymization of internal IPs, hostnames and usernames (M5 phase 4).

Pattern-based (documented residual): what is "internal" is decided by fixed rules plus the
org's `internal_cidrs` / `internal_suffixes`:
- IPs: RFC 1918, 100.64/10 (CGNAT), loopback, link-local, ULA (fc00::/7), the IPv4-mapped
  forms of all of these, and the org CIDRs. Documentation and public ranges stay in clear.
- Hostnames: special-use TLDs (`local`, `lan`, `internal`, `corp`, `home.arpa`,
  `localdomain`, `intranet`, `private`, `home`), PTR names under `arpa`, org suffixes, and
  single-label names inside hostname-typed fields (a single word in free text is not a name).
- Usernames: `C:\\Users\\<x>`, `C:\\Documents and Settings\\<x>`, `/home/<x>`, `/Users/<x>`
  (PDB paths are covered by the same rules), and an email's local part when its domain is
  internal.

Replacements are `INT_IP_n`, `INT_HOST_n`, `USER_n`, numbered per category in first-appearance
order. One `Pseudonymizer` is shared by a whole run tree (an incident's children and root),
so the same value always gets the same pseudonym. `mapping` is `{pseudonym: original}` and
is stored server-side only (`ai_run_inputs.pseudonym_map`).

Raw values that already look like pseudonyms are neutralized first (`neutralize`, RT15), so
planted text never collides with a real pseudonym.
"""

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

INTERNAL_NETWORKS: tuple[IpNetwork, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fe80::/10",
        "fc00::/7",
    )
)
SPECIAL_USE_SUFFIXES = (
    "local",
    "lan",
    "internal",
    "corp",
    "home.arpa",
    "localdomain",
    "intranet",
    "private",
    "home",
    "arpa",  # PTR names (in-addr.arpa, ip6.arpa)
)
# Well-known profile directories that are not people.
NOT_USERS = frozenset({"public", "default", "default user", "all users", "defaultapppool"})

CATEGORY_PREFIX = {"ip": "INT_IP", "host": "INT_HOST", "user": "USER"}
PSEUDONYM = re.compile(r"\b(?:INT_IP|INT_HOST|USER)_\d+\b")
# Anything pseudonym-shaped in raw evidence (any case, any left context): neutralized (RT15).
_PLANTED = re.compile(r"(int)_(ip|host)_(\d+)|(user)_(\d+)", re.IGNORECASE)

_V6 = re.compile(
    r"(?<![\w:.])\[?((?:[0-9A-Fa-f]{0,4}:){2,7}(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{1,4})?)\]?"
    r"(?![\w:]|\.\w)"
)
# Digits and dots only delimit an IPv4 (`x10.0.0.1` is still 10.0.0.1; `110.0.0.1` is not).
_V4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?!\d|\.\d)")
_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
_HOST = re.compile(rf"(?<![\w.@-])({_LABEL}(?:\.{_LABEL})+)\.?(?![\w-])", re.IGNORECASE)
# An email needs a dotted domain whose last label starts with a letter (`x@1`,
# `heuristic:dns_anomaly@1` or `a@1.2` are not addresses).
_EMAIL = re.compile(
    rf"(?<![\w.+-])([\w.+-]{{1,64}})@((?:{_LABEL}\.)+[a-z][a-z0-9-]{{0,62}})(?![\w-]|\.\w)",
    re.IGNORECASE,
)
_WIN_USER = re.compile(
    r"(?i)(\b[a-z]:\\{1,2}(?:users|documents and settings)\\{1,2})([^\\/:*?\"<>|\r\n]{1,64})"
)
_POSIX_USER = re.compile(r"(/(?:home|Users)/)([^/\s:\"'<>|]{1,64})")
_SINGLE_LABEL = re.compile(rf"^{_LABEL}$", re.IGNORECASE)


def neutralize(text: str) -> tuple[str, int]:
    """`INT_IP_7` -> `INT-IP-7`, `user_2` -> `user-2` (RT15); returns the count."""
    count = 0

    def sub(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return match.group(0).replace("_", "-")

    return _PLANTED.sub(sub, text), count


def parse_networks(values: Iterable[object]) -> tuple[IpNetwork, ...]:
    """Org CIDRs (validated on save by phase 7; anything unparseable is ignored here)."""
    out: list[IpNetwork] = []
    for value in values:
        if isinstance(value, str):
            try:
                out.append(ipaddress.ip_network(value.strip(), strict=False))
            except ValueError:
                continue
    return tuple(out)


def parse_suffixes(values: Iterable[object]) -> tuple[str, ...]:
    out: list[str] = []
    for value in values:
        if isinstance(value, str):
            suffix = value.strip().strip(".").lower()
            if suffix:
                out.append(suffix)
    return tuple(out)


def _unmapped(address: IpAddress) -> IpAddress:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


@dataclass
class PseudonymState:
    keys: dict[tuple[str, str], str] = field(default_factory=dict)  # (category, key) -> name
    mapping: dict[str, str] = field(default_factory=dict)  # name -> original
    counters: dict[str, int] = field(default_factory=dict)


class Pseudonymizer:
    """Stable per run tree; `snapshot` / `restore` undo the names of an item that is then
    left out (no numbering gaps)."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        internal_cidrs: Iterable[object] = (),
        internal_suffixes: Iterable[object] = (),
    ) -> None:
        self.enabled = enabled
        self.networks = INTERNAL_NETWORKS + parse_networks(internal_cidrs)
        self.suffixes = SPECIAL_USE_SUFFIXES + parse_suffixes(internal_suffixes)
        self.state = PseudonymState()

    # --- state -----------------------------------------------------------------------------

    @property
    def mapping(self) -> dict[str, str]:
        return dict(self.state.mapping)

    def snapshot(self) -> PseudonymState:
        s = self.state
        return PseudonymState(dict(s.keys), dict(s.mapping), dict(s.counters))

    def restore(self, state: PseudonymState) -> None:
        self.state = state

    def _name(self, category: str, key: str, original: str) -> str:
        existing = self.state.keys.get((category, key))
        if existing is not None:
            return existing
        n = self.state.counters.get(category, 0) + 1
        self.state.counters[category] = n
        name = f"{CATEGORY_PREFIX[category]}_{n}"
        self.state.keys[(category, key)] = name
        self.state.mapping[name] = original
        return name

    # --- predicates ------------------------------------------------------------------------

    def internal_ip(self, address: IpAddress) -> bool:
        address = _unmapped(address)
        return any(address.version == n.version and address in n for n in self.networks)

    def internal_host(self, name: str) -> bool:
        host = name.strip().rstrip(".").lower()
        if not host:
            return False
        return any(host == s or host.endswith("." + s) for s in self.suffixes)

    # --- replacement -----------------------------------------------------------------------

    def _ip_sub(self, match: re.Match[str]) -> str:
        raw = match.group(1)
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            return match.group(0)
        if not self.internal_ip(address):
            return match.group(0)
        canonical = str(_unmapped(address))
        return self._name("ip", canonical, raw)

    def _host(self, raw: str) -> str:
        return self._name("host", raw.rstrip(".").lower(), raw)

    def _host_sub(self, match: re.Match[str]) -> str:
        raw = match.group(1)
        if PSEUDONYM.fullmatch(raw) or not self.internal_host(raw):
            return match.group(0)
        # A PTR name of an internal address already had its IP replaced: map the real name.
        original = PSEUDONYM.sub(lambda m: self.state.mapping.get(m.group(0), m.group(0)), raw)
        return self._host(original)

    def _email_sub(self, match: re.Match[str]) -> str:
        local, domain = match.group(1), match.group(2)
        if not self.internal_host(domain):
            return match.group(0)
        user = self._name("user", local.lower(), local)
        return f"{user}@{self._host(domain)}"

    def _user_sub(self, match: re.Match[str]) -> str:
        prefix, user = match.group(1), match.group(2)
        if user.strip().lower() in NOT_USERS or PSEUDONYM.fullmatch(user):
            return match.group(0)
        return prefix + self._name("user", user.lower(), user)

    def text(self, value: str) -> str:
        """Every internal IP, hostname and username inside a free-text value."""
        if not self.enabled:
            return value
        value = _WIN_USER.sub(self._user_sub, value)
        value = _POSIX_USER.sub(self._user_sub, value)
        value = _EMAIL.sub(self._email_sub, value)
        value = _V6.sub(self._ip_sub, value)
        value = _V4.sub(self._ip_sub, value)
        return _HOST.sub(self._host_sub, value)

    def host_field(self, value: str) -> str:
        """A hostname-typed value (qname, Host, SNI, CN, domain IOC): a single-label name
        (optionally with `:port`) is internal too."""
        if not self.enabled:
            return value
        name, sep, port = value.rpartition(":") if value.count(":") == 1 else (value, "", "")
        if not sep or not port.isdigit():
            name, sep, port = value, "", ""
        bare = name.strip().rstrip(".")
        if bare and _SINGLE_LABEL.fullmatch(bare) and not bare.isdigit():
            if not PSEUDONYM.fullmatch(bare):
                return self._host(bare) + (sep + port if sep else "")
        return self.text(value)


def used_pseudonyms(text: str) -> list[str]:
    """Distinct pseudonyms present in a text, in first-appearance order."""
    return list(dict.fromkeys(PSEUDONYM.findall(text)))


def category_counts(names: Iterable[str]) -> dict[str, int]:
    prefix_to_category = {p: c for c, p in CATEGORY_PREFIX.items()}
    out: dict[str, int] = {}
    for name in names:
        category = prefix_to_category.get(name.rsplit("_", 1)[0])
        if category is not None:
            out[category] = out.get(category, 0) + 1
    return dict(sorted(out.items()))
