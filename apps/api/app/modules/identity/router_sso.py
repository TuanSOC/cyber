"""OIDC sign-in (M11 phase 8; phase 1 stubs answering 501).

`POST /auth/sso/start` (public, CSRF-exempt, RT4): home realm discovery by the email's domain
(`sso_domain_index`), a 10-minute Redis state bound to this browser by `cl_sso` (Lax) ->
`{redirect_url}`. `GET /auth/sso/callback` always redirects: `303 /sso/complete#next=…` with a
session, or `/login#sso_error=<code>` (`identity.errors.SSO_REDIRECT_CODES`); its query string
is redacted in the access log (`core.logging`), and it answers `Cache-Control: no-store` and
`Referrer-Policy: no-referrer`.
"""

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from app.core.stubs import not_implemented
from app.modules.identity.schemas import SsoStartIn, SsoStartOut

router = APIRouter(prefix="/auth/sso", tags=["identity"])


@router.post("/start", response_model=SsoStartOut)
async def start_sso(body: SsoStartIn, request: Request) -> SsoStartOut:
    raise not_implemented()


@router.get("/callback", response_class=RedirectResponse, status_code=303)
async def sso_callback(request: Request) -> RedirectResponse:
    raise not_implemented()
