"""MISP base URL checks (SSRF hardening).

Phase 2 provides the syntactic half, `validate_base_url`, used by the API on save: no DNS,
no sockets (the API has no egress, RT5). Phase 4 adds the worker-side resolution and IP
pinning below it, without changing `validate_base_url`.

Rules: https only; no userinfo, query or fragment; port 443 or one of `TI_MISP_ALLOWED_PORTS`;
an IDNA host name that is not special-use (`normalize.py` rules) or a literal IP that is
global (private literals only with the dev-only `TI_MISP_ALLOW_PRIVATE`; loopback, link-local
and unspecified never); a normalized path prefix of at most 256 characters. The result's
`base_url_norm` is what the sealed key is bound to (seal AAD, RT1).

Worker half (phase 4): `resolve_pinned` resolves the host (`getaddrinfo` on a small dedicated
pool of `DNS_WORKERS` threads, 2 s timeout; when every thread is busy, e.g. stuck past a
timeout, it fails fast with `DnsBusy` instead of queueing) and requires EVERY answer to be
global (dev `TI_MISP_ALLOW_PRIVATE`: private ranges too, never loopback,
link-local/metadata or unspecified, also when wrapped in IPv6), else
`MispUrlNotPublic`. `PinnedTransport` runs it before every request and sends the request to
the first validated address: the URL names the IP (IPv6 bracketed), `Host` stays the
hostname and the `sni_hostname` extension makes TLS verify the certificate against the
hostname. Hosts are compared in their ASCII (punycode) form: `httpx.URL.host` is Unicode for
an IDN, `raw_host` is not. The API never calls these (it has no egress, RT5); nothing here logs.
"""

import asyncio
import ipaddress
import re
import socket
import threading
from collections.abc import Awaitable, Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from app.modules.threat_intel.normalize import (
    SkipReason,
    _embedded_v4,
    ip_is_global,
    normalize_domain,
)
from app.modules.threat_intel.providers.base import ProviderError, ProviderErrorKind

MAX_URL_CHARS = 512
MAX_PATH_CHARS = 256
_PATH_SEGMENT = re.compile(r"[A-Za-z0-9._~-]+")
# A last label that is a number (`10.0.0.0x1`, `misp.123`): resolvers and `inet_aton` may
# read the name as an IPv4 address in a non-canonical form.
_NUMERIC_LABEL = re.compile(r"0x[0-9a-f]*|[0-9]+", re.IGNORECASE)


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


def _ipv4_like(host: str) -> bool:
    """Hex, octal, partial or decimal IPv4 forms (`0x7f.1`, `127.1`, `10.0.0.0x1`)."""
    if _NUMERIC_LABEL.fullmatch(host.rstrip(".").rsplit(".", 1)[-1]):
        return True
    try:
        socket.inet_aton(host)
    except (OSError, ValueError):
        return False
    return True


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
        if name is None or reason is not None or _ipv4_like(raw_host) or _ipv4_like(name):
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


# --- worker side: resolution and pinning (phase 4, RT5) ------------------------------------

RESOLVE_TIMEOUT_S = 2.0
MAX_ADDRESSES = 32

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
# (host, port) -> the address strings `getaddrinfo` returned (injectable for tests).
Resolver = Callable[[str, int], Awaitable[Sequence[str]]]


class MispUrlNotPublic(ProviderError):
    """The MISP host resolved to at least one non-global address (or a refused literal)."""

    code = "misp_url_not_public"

    def __init__(self) -> None:
        super().__init__(ProviderErrorKind.MISP_URL_NOT_PUBLIC)


class DnsBusy(ProviderError):
    """Every DNS thread is busy (a slow or stuck `getaddrinfo` outlives its timeout): fail
    fast instead of queueing behind it. Mapped like a timeout."""

    code = "dns_busy"

    def __init__(self) -> None:
        super().__init__(ProviderErrorKind.TIMEOUT)


# `getaddrinfo` cannot be cancelled: a timed-out call keeps its thread. A dedicated, bounded
# pool keeps those off the default executor, and the slot count makes callers fail fast once
# every thread is held (a slot is freed only when its `getaddrinfo` really returns).
DNS_WORKERS = 4
_dns_pool = ThreadPoolExecutor(max_workers=DNS_WORKERS, thread_name_prefix="ti-dns")
_dns_slots = threading.BoundedSemaphore(DNS_WORKERS)


def _getaddrinfo_in_slot(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        return [str(info[4][0]) for info in infos]
    finally:
        _dns_slots.release()


async def system_resolver(host: str, port: int) -> list[str]:
    if not _dns_slots.acquire(blocking=False):
        raise DnsBusy()
    try:
        future = asyncio.get_running_loop().run_in_executor(
            _dns_pool, _getaddrinfo_in_slot, host, port
        )
    except BaseException:
        _dns_slots.release()
        raise
    return await future


def _resolved_ok(ip: IPAddress, allow_private: bool) -> bool:
    if not _literal_ok(ip, allow_private):
        return False
    if ip_is_global(ip) or not isinstance(ip, ipaddress.IPv6Address):
        return True
    # allow_private: 6to4 / Teredo / NAT64 must not smuggle loopback or metadata either.
    embedded = _embedded_v4(ip)
    return embedded is None or not (
        embedded.is_loopback
        or embedded.is_link_local
        or embedded.is_unspecified
        or embedded.is_multicast
        or embedded.is_reserved
    )


def _parse_address(text: str) -> IPAddress | None:
    if "%" in text:  # a zone id is link-local by definition
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


async def resolve_pinned(
    validated: ValidatedBase,
    *,
    resolver: Resolver | None = None,
    allow_private: bool | None = None,
    timeout_s: float = RESOLVE_TIMEOUT_S,
) -> list[IPAddress]:
    """The addresses to connect to, in resolver order (the first one is pinned).

    Every answer must pass (a mixed public/private answer is refused as a whole, since the
    OS would be free to pick either): else `MispUrlNotPublic`. A resolver timeout raises
    `ProviderError(timeout)`, a resolver failure or an empty answer `ProviderError(transport)`.
    """
    private = _settings_allow_private() if allow_private is None else allow_private
    if validated.is_ip_literal:
        literal = _parse_address(validated.host)
        if literal is None or not _resolved_ok(literal, private):
            raise MispUrlNotPublic()
        return [literal]
    resolve = resolver or system_resolver
    try:
        async with asyncio.timeout(timeout_s):
            answers = list(await resolve(validated.host, validated.port))
    except TimeoutError:
        raise ProviderError(ProviderErrorKind.TIMEOUT) from None
    except (OSError, UnicodeError, ValueError):
        raise ProviderError(ProviderErrorKind.TRANSPORT) from None
    if not answers:
        raise ProviderError(ProviderErrorKind.TRANSPORT)
    if len(answers) > MAX_ADDRESSES:
        raise MispUrlNotPublic()  # never pin from an answer too large to check
    addresses: list[IPAddress] = []
    for answer in answers:
        ip = _parse_address(answer) if isinstance(answer, str) else None
        if ip is None or not _resolved_ok(ip, private):
            raise MispUrlNotPublic()
        if ip not in addresses:
            addresses.append(ip)
    return addresses


class PinnedTransport(httpx.AsyncBaseTransport):
    """Sends each request for the validated MISP origin to a freshly resolved, validated IP.

    Resolution runs before EVERY request (a rebinding between verify and lookup, or between
    two lookups, is caught). Requests for any other origin are refused before resolution.
    The inner transport carries the TLS settings (CA bundle) and never follows redirects.
    """

    def __init__(
        self,
        inner: httpx.AsyncBaseTransport,
        validated: ValidatedBase,
        *,
        resolver: Resolver | None = None,
        allow_private: bool | None = None,
    ) -> None:
        self._inner = inner
        self._validated = validated
        self._resolver = resolver
        self._allow_private = allow_private
        netloc = f"[{validated.host}]" if ":" in validated.host else validated.host
        self._host_header = netloc if validated.port == 443 else f"{netloc}:{validated.port}"

    @property
    def validated(self) -> ValidatedBase:
        return self._validated

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        if (
            url.scheme != "https"
            or url.raw_host.decode("ascii").lower() != self._validated.host
            or (url.port or 443) != self._validated.port
        ):
            raise ProviderError(ProviderErrorKind.PATH_NOT_ALLOWED)
        addresses = await resolve_pinned(
            self._validated, resolver=self._resolver, allow_private=self._allow_private
        )
        request.url = url.copy_with(host=addresses[0].compressed)
        request.headers["Host"] = self._host_header
        if not self._validated.is_ip_literal:
            request.extensions = {**request.extensions, "sni_hostname": self._validated.host}
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


__all__ = [
    "DNS_WORKERS",
    "DnsBusy",
    "IPAddress",
    "MispUrlInvalid",
    "MispUrlNotPublic",
    "PinnedTransport",
    "Resolver",
    "ValidatedBase",
    "resolve_pinned",
    "system_resolver",
    "validate_base_url",
]
