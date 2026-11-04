"""IOC normalization and provider eligibility (pure; shared by the API and the enrich worker).

`normalize(type_hint, raw)` turns one observed or typed-in value into a `Normalized`
indicator (`ioc_type`, `value_norm`, `ioc_key`, `notes`) or a `Skip(reason)`. `eligible()`
then decides, per provider, whether that indicator may be sent at all. Nothing here does I/O:
no DNS, no sockets, no clock.

Rules (plan "Normalization and eligibility", RT4 / RT13):
- refang `hxxp`, `[.]`, `(.)`, `[dot]`, `[:]`, `[@]` (note `refanged`);
- IPs must be global after unwrapping IPv4-mapped, IPv4-compatible, 6to4, NAT64 and Teredo
  addresses (no private, loopback, link-local, CGNAT, documentation, multicast or reserved);
- domains: lowercase, IDNA punycode, <= 253 characters, >= 2 labels, never a special-use or
  internal name (the TLDs below, everything under `arpa`, the RFC 2606 `example.*` names);
- URLs: http(s) only, no userinfo, the host passes the IP / domain rule, and the query string
  and fragment are removed before anything is keyed or sent (note `query_removed`);
- hashes: lowercase hex of the right length;
- emails go to MISP and the `mock` provider only; file paths, registry keys, JA3 and
  certificate values are never sent anywhere.

M2/M3 `iocs.type` values map to `IocType` as follows (`IOC_TYPE_MAP`):

| `iocs.type`                                            | `IocType`                        |
|--------------------------------------------------------|----------------------------------|
| `ip`                                                   | `ipv4` or `ipv6` (by parse)      |
| `domain`                                               | `domain`                         |
| `url`                                                  | `url`                            |
| `email`                                                | `email` (MISP / mock only)       |
| `file_md5` / `file_sha1` / `file_sha256`               | `md5` / `sha1` / `sha256`        |
| `ja3`, `ja3s`, `cert_sha256`, `registry_key`, `file_path` | never sent (`unsupported_type`) |

The `mock` provider's behaviour names live under `example.com` (`hit.example.com`, ...). They
are special-use like every `example.*` name, so `normalize` skips them as usual, but the skip
keeps the normalized form and `eligible()` lets only `mock` accept it.
"""

import enum
import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.modules.threat_intel.catalog import CATALOG
from app.modules.threat_intel.providers.base import (
    HASH_TYPES,
    IocType,
    ProviderName,
    compute_ioc_key,
)

MAX_RAW_CHARS = 2048
MAX_DOMAIN_CHARS = 253
MAX_EMAIL_LOCAL = 64


class SkipReason(enum.StrEnum):
    NOT_GLOBAL_IP = "not_global_ip"
    SPECIAL_USE_NAME = "special_use_name"
    EXCLUDED_SUFFIX = "excluded_suffix"
    SINGLE_LABEL = "single_label"
    UNSUPPORTED_TYPE = "unsupported_type"
    INVALID = "invalid"
    HAS_USERINFO = "has_userinfo"
    BAD_SCHEME = "bad_scheme"
    TOO_LONG = "too_long"


class Note(enum.StrEnum):
    QUERY_REMOVED = "query_removed"
    REFANGED = "refanged"


@dataclass(frozen=True)
class Normalized:
    ioc_type: IocType
    value_norm: str
    ioc_key: str
    notes: tuple[Note, ...] = ()

    @classmethod
    def of(cls, ioc_type: IocType, value_norm: str, notes: Iterable[Note] = ()) -> "Normalized":
        return cls(ioc_type, value_norm, compute_ioc_key(ioc_type, value_norm), tuple(notes))

    @property
    def host(self) -> str | None:
        return host_of(self.ioc_type, self.value_norm)


@dataclass(frozen=True)
class Skip:
    """Never sent. A special-use skip keeps the normalized form (for the mock exemption and
    the UI's normalization report); every other skip carries at most the detected type."""

    reason: SkipReason
    ioc_type: IocType | None = None
    value_norm: str | None = None
    notes: tuple[Note, ...] = ()


Outcome = Normalized | Skip

# M2/M3 `iocs.type` (and the manual-lookup type field) -> IocType. `ip` is split by parse.
IOC_TYPE_MAP: dict[str, IocType | None] = {
    "ip": None,
    "ipv4": IocType.IPV4,
    "ipv6": IocType.IPV6,
    "domain": IocType.DOMAIN,
    "url": IocType.URL,
    "email": IocType.EMAIL,
    "file_md5": IocType.MD5,
    "file_sha1": IocType.SHA1,
    "file_sha256": IocType.SHA256,
    "md5": IocType.MD5,
    "sha1": IocType.SHA1,
    "sha256": IocType.SHA256,
}
# Observed types that are never sent to any provider.
NEVER_SENT = frozenset({"ja3", "ja3s", "cert_sha256", "registry_key", "file_path"})

# Special-use and internal top-level names (RFC 6761/6762/7686/8375/9476 plus common internal
# conventions). Everything under `arpa` is refused: PTR names encode (private) addresses.
SPECIAL_TLDS = frozenset(
    {
        "local",
        "localhost",
        "internal",
        "lan",
        "home",
        "corp",
        "private",
        "intranet",
        "localdomain",
        "test",
        "example",
        "invalid",
        "onion",
        "alt",
        "arpa",
    }
)
# RFC 2606 second-level example names (also the mock's behaviour names).
SPECIAL_SUFFIXES = ("example.com", "example.net", "example.org")
MOCK_SUFFIX = "example.com"

_HASH_LENGTHS = {32: IocType.MD5, 40: IocType.SHA1, 64: IocType.SHA256}
_HEX = re.compile(r"[0-9a-f]+")
_LABEL = re.compile(r"(?!-)[a-z0-9_-]{1,63}(?<!-)")
_EMAIL_LOCAL = re.compile(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}")
_PATH_SAFE = re.compile(r"[\x21-\x7e]*")
# A last label that WHATWG's "ends in a number" check (and `inet_aton`) reads as an IPv4 part:
# decimal/octal digits or `0x` hex (`10.0.0.0x1`, `0x7f.0x0.0x0.0x1`, `127.1`).
_NUMERIC_LABEL = re.compile(r"0x[0-9a-f]*|[0-9]+", re.IGNORECASE)
# Not global even if `ipaddress` says so: NAT64 local-use, IPv4-compatible (deprecated).
_EXTRA_NOT_GLOBAL = (
    ipaddress.ip_network("64:ff9b:1::/48"),
    ipaddress.ip_network("::/96"),
)
_NAT64 = ipaddress.ip_network("64:ff9b::/96")

_SCHEME_REFANG = re.compile(r"^(hxxp|fxp)(s?)(?=(?:\[:\]|:)//)", re.IGNORECASE)
_REFANG = (
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[@\]|\(@\)|\[at\]", re.IGNORECASE), "@"),
)


def refang(value: str) -> str:
    value = _SCHEME_REFANG.sub(
        lambda m: ("http" if m.group(1).lower() == "hxxp" else "ftp") + m.group(2).lower(),
        value,
    )
    for pattern, replacement in _REFANG:
        value = pattern.sub(replacement, value)
    return value


# --- IPs -----------------------------------------------------------------------------------


def _embedded_v4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip.teredo is not None:
        return ip.teredo[1]  # the client address
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def _v4_global(ip: ipaddress.IPv4Address) -> bool:
    return (
        ip.is_global
        and not ip.is_multicast
        and not ip.is_reserved
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_unspecified
    )


def ip_is_global(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Public unicast only, with every embedded IPv4 checked too (RT13)."""
    if isinstance(ip, ipaddress.IPv4Address):
        return _v4_global(ip)
    embedded = _embedded_v4(ip)
    if embedded is not None and not _v4_global(embedded):
        return False
    if embedded is not None and ip in _NAT64:
        # 64:ff9b::/96 lies inside ::/8 ("reserved"): it stands for exactly its IPv4 address.
        return True
    if any(ip in net for net in _EXTRA_NOT_GLOBAL):
        return False
    return (
        ip.is_global
        and not ip.is_multicast
        and not ip.is_reserved
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_site_local
        and not ip.is_unspecified
    )


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    text = value.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if "%" in text:  # a zone id is local by definition
        return None
    try:
        # Strict: no decimal/octal/short forms (`2130706433`, `0177.0.0.1`, `127.1`).
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _normalize_ip(value: str) -> Outcome:
    ip = _parse_ip(value)
    if ip is None:
        return Skip(SkipReason.INVALID)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # ::ffff:a.b.c.d is that IPv4 address
    ioc_type = IocType.IPV4 if isinstance(ip, ipaddress.IPv4Address) else IocType.IPV6
    if not ip_is_global(ip):
        return Skip(SkipReason.NOT_GLOBAL_IP, ioc_type)
    return Normalized.of(ioc_type, ip.compressed)


# --- domains -------------------------------------------------------------------------------


def _special_use(name: str) -> bool:
    labels = name.split(".")
    if labels[-1] in SPECIAL_TLDS:
        return True
    return any(name == s or name.endswith(f".{s}") for s in SPECIAL_SUFFIXES)


def normalize_domain(value: str) -> tuple[str | None, SkipReason | None]:
    """The punycode, lowercase form of a host name, or why it is refused."""
    name = value.strip().rstrip(".").lower()
    if not name or ".." in name or name.startswith("."):
        return None, SkipReason.INVALID
    if len(name) > MAX_DOMAIN_CHARS * 2:
        return None, SkipReason.TOO_LONG
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError:
        return None, SkipReason.INVALID
    if len(name) > MAX_DOMAIN_CHARS:
        return None, SkipReason.TOO_LONG
    labels = name.split(".")
    if not all(_LABEL.fullmatch(label) for label in labels):
        return None, SkipReason.INVALID
    if _NUMERIC_LABEL.fullmatch(labels[-1]) or not re.search(r"[a-z]", labels[-1]):
        # A numeric last label (decimal, octal or `0x` hex): an IP in disguise that WHATWG
        # URL parsers and `inet_aton` read as an address (`127.1`, `10.0.0.0x1`,
        # `0x7f000001`), never a name.
        return None, SkipReason.INVALID
    if _special_use(name):
        return name, SkipReason.SPECIAL_USE_NAME
    if len(labels) < 2:
        return name, SkipReason.SINGLE_LABEL
    return name, None


def _normalize_domain(value: str) -> Outcome:
    if _parse_ip(value) is not None:
        return Skip(SkipReason.INVALID)  # an IP typed as a domain: refuse, do not guess
    name, reason = normalize_domain(value)
    if reason is SkipReason.SPECIAL_USE_NAME and name is not None:
        return Skip(reason, IocType.DOMAIN, name)
    if reason is not None or name is None:
        return Skip(reason or SkipReason.INVALID, IocType.DOMAIN)
    return Normalized.of(IocType.DOMAIN, name)


# --- URLs ----------------------------------------------------------------------------------


def _normalize_url(value: str, notes: list[Note]) -> Outcome:
    text = value.strip()
    if any(ord(c) <= 0x20 or ord(c) == 0x7F for c in text):
        return Skip(SkipReason.INVALID, IocType.URL)
    if "://" not in text:
        return Skip(SkipReason.BAD_SCHEME, IocType.URL)
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return Skip(SkipReason.INVALID, IocType.URL)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return Skip(SkipReason.BAD_SCHEME, IocType.URL)
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        return Skip(SkipReason.HAS_USERINFO, IocType.URL)
    host = parts.hostname
    if not host:
        return Skip(SkipReason.INVALID, IocType.URL)
    if parts.query or parts.fragment or text.endswith(("?", "#")):
        notes.append(Note.QUERY_REMOVED)
    path = parts.path or "/"
    if not _PATH_SAFE.fullmatch(path):
        return Skip(SkipReason.INVALID, IocType.URL)

    ip = _parse_ip(host)
    special = False
    if ip is not None:
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if not ip_is_global(ip):
            return Skip(SkipReason.NOT_GLOBAL_IP, IocType.URL)
        host_norm = f"[{ip.compressed}]" if isinstance(ip, ipaddress.IPv6Address) else str(ip)
    else:
        name, reason = normalize_domain(host)
        if reason is SkipReason.SPECIAL_USE_NAME and name is not None:
            special = True
        elif reason is not None or name is None:
            return Skip(reason or SkipReason.INVALID, IocType.URL)
        host_norm = name or ""

    default_port = 443 if scheme == "https" else 80
    netloc = host_norm if port in (None, default_port) else f"{host_norm}:{port}"
    value_norm = f"{scheme}://{netloc}{path}"
    if len(value_norm) > MAX_RAW_CHARS:
        return Skip(SkipReason.TOO_LONG, IocType.URL)
    if special:
        return Skip(SkipReason.SPECIAL_USE_NAME, IocType.URL, value_norm, tuple(notes))
    return Normalized.of(IocType.URL, value_norm, notes)


# --- hashes and emails ---------------------------------------------------------------------


def _normalize_hash(value: str, expected: IocType | None) -> Outcome:
    text = value.strip().lower()
    detected = _HASH_LENGTHS.get(len(text))
    if detected is None or not _HEX.fullmatch(text):
        return Skip(SkipReason.INVALID, expected)
    if expected is not None and expected is not detected:
        return Skip(SkipReason.INVALID, expected)
    return Normalized.of(detected, text)


def _normalize_email(value: str) -> Outcome:
    text = value.strip().lower()
    if text.startswith("mailto:"):
        text = text[len("mailto:") :]
    local, at, domain = text.rpartition("@")
    if not at or not _EMAIL_LOCAL.fullmatch(local) or local.startswith(".") or ".." in local:
        return Skip(SkipReason.INVALID, IocType.EMAIL)
    name, reason = normalize_domain(domain)
    if reason is SkipReason.SPECIAL_USE_NAME and name is not None:
        return Skip(reason, IocType.EMAIL, f"{local}@{name}")
    if reason is not None or name is None:
        return Skip(reason or SkipReason.INVALID, IocType.EMAIL)
    return Normalized.of(IocType.EMAIL, f"{local}@{name}")


# --- entry points --------------------------------------------------------------------------


def _detect(text: str) -> IocType | None:
    """Best guess for an untyped manual lookup value (after refanging)."""
    stripped = text.strip()
    if _parse_ip(stripped) is not None:
        return None  # IP: decided by parse
    if len(stripped) in _HASH_LENGTHS and _HEX.fullmatch(stripped.lower()):
        return _HASH_LENGTHS[len(stripped)]
    if "://" in stripped:
        return IocType.URL
    if "@" in stripped:
        return IocType.EMAIL
    return IocType.DOMAIN


def normalize(type_hint: str | IocType | None, raw: str) -> Outcome:
    """One value -> `Normalized` or `Skip(reason)`. `type_hint` is an `iocs.type` value, an
    `IocType` value, or None to detect (manual lookups)."""
    if not isinstance(raw, str) or not raw.strip():
        return Skip(SkipReason.INVALID)
    if len(raw) > MAX_RAW_CHARS:
        return Skip(SkipReason.TOO_LONG)
    hint = type_hint.value if isinstance(type_hint, IocType) else type_hint
    if hint is not None:
        hint = hint.strip().lower()
        if hint in NEVER_SENT or hint not in IOC_TYPE_MAP:
            return Skip(SkipReason.UNSUPPORTED_TYPE)

    notes: list[Note] = []
    text = refang(raw.strip())
    if text != raw.strip():
        notes.append(Note.REFANGED)

    if hint is None:
        expected = _detect(text)
        is_ip = expected is None
    else:
        expected = IOC_TYPE_MAP[hint]
        is_ip = hint in ("ip", "ipv4", "ipv6")

    outcome: Outcome
    if is_ip:
        outcome = _normalize_ip(text)
    elif expected in HASH_TYPES:
        outcome = _normalize_hash(text, expected if hint is not None else None)
    elif expected is IocType.URL:
        outcome = _normalize_url(text, notes)
    elif expected is IocType.EMAIL:
        outcome = _normalize_email(text)
    else:
        outcome = _normalize_domain(text)

    if Note.REFANGED in notes:
        if isinstance(outcome, Normalized) and Note.REFANGED not in outcome.notes:
            outcome = Normalized(
                outcome.ioc_type, outcome.value_norm, outcome.ioc_key, (*outcome.notes, *notes)
            )
        elif isinstance(outcome, Skip) and Note.REFANGED not in outcome.notes:
            outcome = Skip(outcome.reason, outcome.ioc_type, outcome.value_norm, tuple(notes))
    return outcome


def host_of(ioc_type: IocType, value_norm: str) -> str | None:
    """The DNS name an indicator names (domain, URL host, email domain), if any."""
    if ioc_type is IocType.DOMAIN:
        return value_norm
    if ioc_type is IocType.EMAIL:
        return value_norm.rpartition("@")[2]
    if ioc_type is IocType.URL:
        host = urlsplit(value_norm).hostname
        return host if host and _parse_ip(host) is None else None
    return None


def _under(name: str, suffix: str) -> bool:
    return name == suffix or name.endswith(f".{suffix}")


def normalize_suffix(value: str) -> str | None:
    """An org excluded-suffix entry (`corp.example.org`, `.internal.acme.com`) or None."""
    name, reason = normalize_domain(value.strip().lstrip("."))
    if name is None or reason in (SkipReason.INVALID, SkipReason.TOO_LONG):
        return None
    return name


def is_excluded(host: str | None, excluded_suffixes: Iterable[str]) -> bool:
    return host is not None and any(_under(host, s) for s in excluded_suffixes if s)


def eligible(
    item: Outcome, provider: ProviderName, excluded_suffixes: Iterable[str] = ()
) -> Outcome:
    """Whether `item` may be sent to `provider`: the normalized indicator, or why not.

    - the org's excluded suffixes (domain, URL host, email domain) -> `excluded_suffix`;
    - the provider's supported types (`catalog.py`) -> `unsupported_type`;
    - emails only ever go to MISP and `mock` ("never external");
    - only `mock` accepts a special-use name, and only under `example.com` (its behaviour
      names); every real provider refuses it.
    """
    suffixes = tuple(excluded_suffixes)
    if isinstance(item, Skip):
        if (
            provider is ProviderName.MOCK
            and item.reason is SkipReason.SPECIAL_USE_NAME
            and item.ioc_type is not None
            and item.value_norm is not None
        ):
            host = host_of(item.ioc_type, item.value_norm)
            if host is not None and _under(host, MOCK_SUFFIX):
                if is_excluded(host, suffixes):
                    return Skip(SkipReason.EXCLUDED_SUFFIX, item.ioc_type)
                return Normalized.of(item.ioc_type, item.value_norm, item.notes)
        return item
    if is_excluded(item.host, suffixes):
        return Skip(SkipReason.EXCLUDED_SUFFIX, item.ioc_type)
    if item.ioc_type not in CATALOG[provider].supported_types:
        return Skip(SkipReason.UNSUPPORTED_TYPE, item.ioc_type)
    if item.ioc_type is IocType.EMAIL and provider not in (ProviderName.MISP, ProviderName.MOCK):
        return Skip(SkipReason.UNSUPPORTED_TYPE, item.ioc_type)
    return item


__all__ = [
    "IOC_TYPE_MAP",
    "NEVER_SENT",
    "Normalized",
    "Note",
    "Outcome",
    "Skip",
    "SkipReason",
    "eligible",
    "host_of",
    "ip_is_global",
    "is_excluded",
    "normalize",
    "normalize_domain",
    "normalize_suffix",
    "refang",
]
