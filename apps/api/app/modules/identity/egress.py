"""The api's only route to IdPs and DoH: through the egress proxy (M11 phase 1, FROZEN).

`egress_client(timeout_s=...)` builds an `httpx.AsyncClient` that tunnels through
`IDENTITY_EGRESS_PROXY_URL` (HTTP CONNECT; TLS is end to end, the proxy never sees a token or
secret), ignores proxy / CA environment variables (`trust_env=False`), never follows a
redirect and refuses a response body above `IDENTITY_HTTP_MAX_BYTES` (`read_capped`). Without
a proxy URL it refuses to build, except with `ENV=test` (the lanes reach `idp-mock` directly).
`IDENTITY_EXTRA_CA_FILE` (test / e2e only; refused in prod) adds the `idp-mock` CA (RT24).
"""

import ssl

import httpx

from app.core.config import get_settings


class EgressUnavailable(RuntimeError):
    """No proxy configured outside tests (fixed message, no URL)."""


class ResponseTooLarge(ValueError):
    pass


def _verify() -> ssl.SSLContext | bool:
    extra = get_settings().identity_extra_ca_file
    if extra is None:
        return True
    context = ssl.create_default_context()
    context.load_verify_locations(cafile=extra)
    return context


def egress_client(*, timeout_s: float | None = None) -> httpx.AsyncClient:
    settings = get_settings()
    proxy = settings.identity_egress_proxy_url
    if proxy is None and settings.env != "test":
        raise EgressUnavailable("IDENTITY_EGRESS_PROXY_URL is not configured")
    timeout = timeout_s if timeout_s is not None else float(settings.identity_http_timeout_s)
    return httpx.AsyncClient(
        proxy=proxy,
        trust_env=False,
        follow_redirects=False,
        verify=_verify(),
        timeout=httpx.Timeout(timeout),
        headers={"User-Agent": "CyberLab-Identity/1", "Accept": "application/json"},
    )


async def read_capped(response: httpx.Response, *, max_bytes: int | None = None) -> bytes:
    """The body of a streamed response, refused once it exceeds the cap."""
    limit = max_bytes if max_bytes is not None else get_settings().identity_http_max_bytes
    declared = response.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise ResponseTooLarge("response too large")
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body += chunk
        if len(body) > limit:
            raise ResponseTooLarge("response too large")
    return bytes(body)
