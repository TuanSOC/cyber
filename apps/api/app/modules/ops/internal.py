"""`GET /internal/metrics` (M7): Prometheus text for an operator's scraper.

Mounted on the root app, outside `/api`, so the gateway never forwards it (Caddy sends only
`/api/*` to the api). The control is the bearer `METRICS_TOKEN` (a compose secret file,
constant-time compare): with no token configured the route answers 404. The refusal of a
request carrying `X-Forwarded-For` is defence in depth only: uvicorn trusts that header from
any peer, so a backend-network caller can simply omit it (RT27). Phase 1 checks access and
answers `501 not_implemented`; phase 5 renders the metrics (`ops/metrics.py`).
"""

import hmac
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Header
from fastapi.responses import PlainTextResponse

from app.core.config import get_settings
from app.core.errors import NotFound, Unauthorized
from app.core.stubs import not_implemented

router = APIRouter(tags=["internal"])

PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


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


def check_access(authorization: str | None, forwarded_for: str | None) -> None:
    token = metrics_token()
    if token is None or forwarded_for:
        raise NotFound()
    scheme, _, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(
        supplied.strip().encode(), token.encode()
    ):
        raise Unauthorized(code="invalid_token")


@router.get(
    "/internal/metrics",
    response_class=PlainTextResponse,
    responses={200: {"content": {PROMETHEUS_CONTENT_TYPE: {}}}},
)
async def internal_metrics(
    authorization: Annotated[str | None, Header()] = None,
    x_forwarded_for: Annotated[str | None, Header()] = None,
) -> PlainTextResponse:
    """Platform job metrics (`job_outcomes` and the queue gauges): no tenant data."""
    check_access(authorization, x_forwarded_for)
    raise not_implemented()
