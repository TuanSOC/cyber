"""`GET /internal/metrics` (M7): Prometheus text for an operator's scraper.

Mounted on the root app, outside `/api`, so the gateway never forwards it (Caddy sends only
`/api/*` to the api). The checks, in order:
1. no token configured (`METRICS_TOKEN_FILE` unset, unreadable or empty): 404, the route is
   off;
2. a request carrying `X-Forwarded-For` or `Forwarded`: 403, before the rate limit so a
   proxied request never takes a slot. Defence in depth only: uvicorn trusts that header from
   any peer, so a backend-network caller can simply omit it (RT27);
3. 60 requests per minute in ONE global bucket `metrics:` (`rate_limit.hit`, before the token
   check so the token cannot be guessed quickly). Not per peer: the peer address is what
   uvicorn derives from the forwarded headers, so a per-peer key could be rotated at will.
   The only legitimate caller is one scraper, so a shared window costs nothing;
4. the bearer `METRICS_TOKEN` (a compose secret file, constant-time compare): 401 without it.
   This is the control.
Every answer is `Cache-Control: no-store`. The body holds no tenant data (`ops/metrics.py`).
"""

import hmac
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Header
from fastapi.responses import PlainTextResponse

from app.core import rate_limit
from app.core.config import get_settings
from app.core.errors import Forbidden, NotFound, Unauthorized
from app.core.tenancy import tenant_session
from app.modules.ops.metrics import platform_metrics, render_prometheus

router = APIRouter(tags=["internal"])

PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
NO_STORE = {"Cache-Control": "no-store"}
RATE_LIMIT_PER_MIN = 60
# One global window (see the module docstring): never keyed by the spoofable peer address.
RATE_LIMIT_KEY = "metrics:"


@lru_cache
def metrics_token() -> str | None:
    """The configured token (stripped), or None when unset or empty (the route is off)."""
    path = get_settings().metrics_token_file
    if path is None:
        return None
    try:
        token = Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return token or None


def bearer_matches(authorization: str | None, token: str) -> bool:
    scheme, _, supplied = (authorization or "").partition(" ")
    return scheme.lower() == "bearer" and hmac.compare_digest(
        supplied.strip().encode(), token.encode()
    )


async def check_access(authorization: str | None, forwarded: str | None) -> None:
    token = metrics_token()
    if token is None:
        raise NotFound(headers=NO_STORE)
    if forwarded:
        raise Forbidden(code="proxied_request", headers=NO_STORE)
    await rate_limit.hit(RATE_LIMIT_KEY, RATE_LIMIT_PER_MIN, 60)
    if not bearer_matches(authorization, token):
        raise Unauthorized(code="invalid_token", headers={**NO_STORE, "WWW-Authenticate": "Bearer"})


@router.get(
    "/internal/metrics",
    response_class=PlainTextResponse,
    responses={200: {"content": {PROMETHEUS_CONTENT_TYPE: {}}}},
)
async def internal_metrics(
    authorization: Annotated[str | None, Header()] = None,
    x_forwarded_for: Annotated[str | None, Header()] = None,
    forwarded: Annotated[str | None, Header()] = None,
) -> PlainTextResponse:
    """Platform job metrics (`job_outcomes` and the queue gauges): no tenant data."""
    await check_access(authorization, x_forwarded_for or forwarded)
    async with tenant_session(None, None) as session:
        metrics = await platform_metrics(session, now=datetime.now(UTC))
    return PlainTextResponse(
        render_prometheus(metrics), media_type=PROMETHEUS_CONTENT_TYPE, headers=NO_STORE
    )
