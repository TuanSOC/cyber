"""IOC collection item normalization (M6).

Values go through the M4 TI normalizer (`threat_intel.normalize.normalize`, the function
that builds `value_norm` / `ioc_key` for `ti_results`), so collection items join the TI
history by `ioc_key`. A collection is an analyst's list, not a provider request, so values
the normalizer refuses to *send* are still kept, with `ti_eligible=false` (computed on read,
never stored):

- private, loopback, link-local, ... IPs (`not_global_ip`): the compressed address;
- special-use and internal names (`example.com`, `*.local`, single labels): the punycode,
  lowercase name (also as a URL host or an email domain);
- URLs with such a host: `scheme://host[:port]/path`, query and fragment removed, like M4.

The pcap-only types the TI normalizer does not cover (`ja3`, `ja3s`, `cert_sha256`,
`registry_key`, `file_path`) keep their job type as `ioc_type`, the trimmed value as
`value_norm` and `ioc_key = sha256(type || 0x00 || value)`: the same construction as
`compute_ioc_key`, in a type space no TI result ever uses.

Anything that cannot be normalized at all (bad hash, bad scheme, userinfo, too long, an
unknown type) is `Invalid(reason)`.
"""

import hashlib
import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.modules.ioc_collections.models import ITEM_VALUE_MAX_CHARS
from app.modules.threat_intel.normalize import (
    IOC_TYPE_MAP,
    NEVER_SENT,
    Normalized,
    Skip,
    SkipReason,
    normalize,
    normalize_domain,
    refang,
)
from app.modules.threat_intel.providers.base import IocType, compute_ioc_key

# TI-normalizer skips that still have a well-defined normalized form (kept, not eligible).
_KEEPABLE = frozenset(
    {SkipReason.NOT_GLOBAL_IP, SkipReason.SPECIAL_USE_NAME, SkipReason.SINGLE_LABEL}
)


@dataclass(frozen=True)
class Item:
    ioc_type: str
    value_norm: str
    ioc_key: str
    ti_eligible: bool


@dataclass(frozen=True)
class Invalid:
    reason: str


def opaque_key(ioc_type: str, value: str) -> str:
    """`ioc_key` of a type outside the TI normalizer (pcap-only types)."""
    return hashlib.sha256(f"{ioc_type}\0{value}".encode()).hexdigest()


def _ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if "%" in text:
        return None
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _name(text: str) -> str | None:
    name, reason = normalize_domain(text)
    if name is None or reason in (SkipReason.INVALID, SkipReason.TOO_LONG):
        return None
    return name


def _lenient_url(text: str) -> str | None:
    """The M4 URL form for a host the TI normalizer will not send (private IP, internal
    name); None when the URL itself is malformed."""
    try:
        parts = urlsplit(text.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or parts.username is not None or "@" in parts.netloc:
        return None
    host = parts.hostname
    if not host:
        return None
    ip = _ip(host)
    if ip is not None:
        host_norm = f"[{ip.compressed}]" if isinstance(ip, ipaddress.IPv6Address) else str(ip)
    else:
        name = _name(host)
        if name is None:
            return None
        host_norm = name
    path = parts.path or "/"
    if any(ord(c) <= 0x20 or ord(c) >= 0x7F for c in path):
        return None
    default_port = 443 if scheme == "https" else 80
    netloc = host_norm if port in (None, default_port) else f"{host_norm}:{port}"
    return f"{scheme}://{netloc}{path}"


def _keep(skip: Skip, text: str) -> tuple[IocType, str] | None:
    """The normalized form of a value the TI normalizer refuses to send."""
    if skip.ioc_type is not None and skip.value_norm is not None:
        return skip.ioc_type, skip.value_norm  # special-use names keep their form
    if skip.reason not in _KEEPABLE:
        return None
    ip = _ip(text)
    if skip.ioc_type in (None, IocType.IPV4, IocType.IPV6) and ip is not None:
        ioc_type = IocType.IPV4 if isinstance(ip, ipaddress.IPv4Address) else IocType.IPV6
        return ioc_type, ip.compressed
    if skip.ioc_type is IocType.DOMAIN:
        name = _name(text)
        return (IocType.DOMAIN, name) if name else None
    if skip.ioc_type is IocType.EMAIL:
        local, _, domain = text.strip().lower().removeprefix("mailto:").rpartition("@")
        name = _name(domain)
        return (IocType.EMAIL, f"{local}@{name}") if local and name else None
    if skip.ioc_type is IocType.URL:
        url = _lenient_url(text)
        return (IocType.URL, url) if url else None
    return None


def normalize_item(type_name: str, raw: str) -> Item | Invalid:
    """One typed value (an `iocs.type` or TI type name) -> a collection item or why not."""
    hint = type_name.strip().lower()
    if not raw.strip():
        return Invalid(SkipReason.INVALID.value)
    if len(raw) > ITEM_VALUE_MAX_CHARS:
        return Invalid(SkipReason.TOO_LONG.value)
    if hint in NEVER_SENT:
        value = raw.strip()
        return Item(hint, value, opaque_key(hint, value), ti_eligible=False)
    if hint not in IOC_TYPE_MAP:
        return Invalid(SkipReason.UNSUPPORTED_TYPE.value)
    outcome = normalize(hint, raw)
    if isinstance(outcome, Normalized):
        return Item(outcome.ioc_type.value, outcome.value_norm, outcome.ioc_key, True)
    kept = _keep(outcome, refang(raw.strip()))
    if kept is None:
        return Invalid(outcome.reason.value)
    ioc_type, value_norm = kept
    if len(value_norm) > ITEM_VALUE_MAX_CHARS:
        return Invalid(SkipReason.TOO_LONG.value)
    return Item(ioc_type.value, value_norm, compute_ioc_key(ioc_type, value_norm), False)


def ti_eligible(ioc_type: str, value_norm: str) -> bool:
    """Whether the TI normalizer accepts a stored item as is (computed, never stored)."""
    if ioc_type in NEVER_SENT or ioc_type not in IOC_TYPE_MAP:
        return False
    return isinstance(normalize(ioc_type, value_norm), Normalized)


# --- defang (exports) ------------------------------------------------------------------------

_NETWORK_TYPES = frozenset({"ipv4", "ipv6", "domain", "url", "email"})


def defang(ioc_type: str, value: str) -> str:
    """The conventional defanged form (`hxxp[:]//evil[.]example/`, `10.0.0[.]1`,
    `user[@]evil[.]example`), which the M4 TI normalizer refangs. Hashes and host-only
    artefacts (registry keys, paths, JA3) are not clickable and stay as they are."""
    if ioc_type not in _NETWORK_TYPES:
        return value
    out = value.replace(".", "[.]")
    if ioc_type == "url":
        scheme, sep, rest = out.partition("://")
        if sep:
            scheme = scheme.replace("t", "x").replace("T", "X")
            out = f"{scheme}[:]//{rest}"
    if ioc_type == "email":
        out = out.replace("@", "[@]")
    return out
