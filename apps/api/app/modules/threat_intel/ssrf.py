"""MISP base URL checks (SSRF hardening).

Phase 2 provides the syntactic half, `validate_base_url`, used by the API on save: no DNS,
no sockets (the API has no egress, RT5). Phase 4 adds the worker-side resolution and IP
pinning below it, without changing `validate_base_url`.

Rules: https only; no userinfo, query or fragment; port 443 or one of `TI_MISP_ALLOWED_PORTS`;
an IDNA host name that is not special-use (`normalize.py` rules) or a literal IP that is
global (private literals only with the dev-only `TI_MISP_ALLOW_PRIVATE`; loopback, link-local
and unspecified never); a normalized path prefix of at most 256 characters. The result's
`base_url_norm` is what the sealed key is bound to (seal AAD, RT1).
"""

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.modules.threat_intel.normalize import SkipReason, ip_is_global, normalize_domain

MAX_URL_CHARS = 512
MAX_PATH_CHARS = 256
_PATH_SEGMENT = re.compile(r"[A-Za-z0-9._~-]+")


class MispUrlInvalid(ValueError):
    """A refused MISP base URL. `reason` is a fixed code; the URL itself is never echoed
    (it may carry userinfo)."""

    code = "misp_url_invalid"

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ValidatedBase:
    base_url_norm: str  # https://host[:port][/prefix], no trailing slash
    host: str  # punycode name, or the IP literal without brackets
    port: int
    path_prefix: str  # "" or "/a/b"
    is_ip_literal: bool


def _settings_ports() -> tuple[int, ...]:
    from app.core.config import get_settings

    return tuple(get_settings().ti_misp_allowed_ports)


def _settings_allow_private() -> bool:
    from app.core.config import get_settings

    return get_settings().ti_misp_allow_private


def _literal_ok(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_private: bool) -> bool:
    if ip_is_global(ip):
        return True
    if not allow_private:
        return False
    # Dev escape hatch: private ranges only; never loopback, link-local (metadata) or 0.0.0.0.
    target = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip
    return not (
        target.is_loopback
        or target.is_link_local
        or target.is_unspecified
        or target.is_multicast
        or target.is_reserved
    )


def _path_prefix(path: str) -> str:
    segments = [s for s in path.split("/") if s]
    for segment in segments:
        if segment in (".", "..") or not _PATH_SEGMENT.fullmatch(segment):
            raise MispUrlInvalid("path")
    prefix = "".join(f"/{s}" for s in segments)
    if len(prefix) > MAX_PATH_CHARS:
        raise MispUrlInvalid("path")
    return prefix


def validate_base_url(
    url: str,
    *,
    allowed_ports: Iterable[int] | None = None,
    allow_private: bool | None = None,
) -> ValidatedBase:
    """Syntactic check of a MISP base URL (no DNS). Raises `MispUrlInvalid(reason)`."""
    if not isinstance(url, str):
        raise MispUrlInvalid("invalid")
    text = url.strip()
    if not text or len(text) > MAX_URL_CHARS:
        raise MispUrlInvalid("too_long" if text else "invalid")
    if any(ord(c) <= 0x20 or ord(c) >= 0x7F for c in text) and not _idna_only(text):
        raise MispUrlInvalid("invalid")
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        raise MispUrlInvalid("invalid") from None
    if parts.scheme.lower() != "https":
        raise MispUrlInvalid("scheme")
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise MispUrlInvalid("userinfo")
    if parts.query or "?" in text:
        raise MispUrlInvalid("query")
    if parts.fragment or "#" in text:
        raise MispUrlInvalid("fragment")
    ports = tuple(allowed_ports) if allowed_ports is not None else _settings_ports()
    effective_port = 443 if port is None else port
    if effective_port != 443 and effective_port not in ports:
        raise MispUrlInvalid("port")
    private = _settings_allow_private() if allow_private is None else allow_private

    raw_host = parts.hostname or ""
    if not raw_host:
        raise MispUrlInvalid("host")
    try:
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(raw_host)
    except ValueError:
        ip = None
    if ip is not None:
        if not _literal_ok(ip, private):
            raise MispUrlInvalid("ip_not_public")
        host = ip.compressed
        netloc_host = f"[{host}]" if isinstance(ip, ipaddress.IPv6Address) else host
    else:
        name, reason = normalize_domain(raw_host)
        if reason is SkipReason.SPECIAL_USE_NAME:
            raise MispUrlInvalid("special_use_name")
        if name is None or reason is not None:
            raise MispUrlInvalid("host")
        host = netloc_host = name

    prefix = _path_prefix(parts.path)
    netloc = netloc_host if effective_port == 443 else f"{netloc_host}:{effective_port}"
    return ValidatedBase(
        base_url_norm=f"https://{netloc}{prefix}",
        host=host,
        port=effective_port,
        path_prefix=prefix,
        is_ip_literal=ip is not None,
    )


def _idna_only(text: str) -> bool:
    """Non-ASCII is accepted only inside the host (an IDN), never controls or spaces."""
    if any(ord(c) <= 0x20 or ord(c) == 0x7F for c in text):
        return False
    try:
        host = urlsplit(text).hostname or ""
    except ValueError:
        return False
    rest = text.replace(host, "", 1) if host else text
    return all(ord(c) < 0x7F for c in rest)


__all__ = ["MispUrlInvalid", "ValidatedBase", "validate_base_url"]
