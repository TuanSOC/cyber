import hmac
import json

from starlette.requests import cookie_parser
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.cookies import CSRF_COOKIE
from app.core.errors import error_body

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# No session exists yet on these, so there is nothing to forge. M11 (RT4): the four public
# POSTs a signed-out browser makes (it holds no `cl_csrf`): JSON bodies only, and none sets a
# session cookie. `mfa/verify`, `step-up`, `invitations/accept` and `email/verify` stay checked.
EXEMPT_PATHS = frozenset(
    {
        "/api/v1/auth/login",
        "/api/v1/auth/register",
        "/api/v1/auth/sso/start",
        "/api/v1/auth/password/forgot",
        "/api/v1/auth/password/reset",
        "/api/v1/invitations/inspect",
    }
)
HEADER = b"x-csrf-token"


class CSRFMiddleware:
    """Double-submit check: mutating API requests must echo the cl_csrf cookie in a header."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and self._needs_check(scope) and not self._valid(scope):
            body = json.dumps(error_body("csrf_failed", "Missing or invalid CSRF token")).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode()),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)

    @staticmethod
    def _needs_check(scope: Scope) -> bool:
        path: str = scope["path"]
        return (
            scope["method"] not in SAFE_METHODS
            and path.startswith("/api/v1/")
            and path not in EXEMPT_PATHS
        )

    @staticmethod
    def _valid(scope: Scope) -> bool:
        header_tokens: list[bytes] = []
        cookie_headers: list[str] = []
        for name, value in scope["headers"]:
            if name == HEADER:
                header_tokens.append(value)
            elif name == b"cookie":
                cookie_headers.append(value.decode("latin-1"))
        # Exactly one token header; ambiguity is rejected.
        if len(header_tokens) != 1 or not header_tokens[0] or not cookie_headers:
            return False
        # Same lenient parser Starlette uses for request.cookies: a malformed cookie set by
        # some other script must not hide cl_csrf (http.cookies.SimpleCookie would).
        cookie = cookie_parser("; ".join(cookie_headers)).get(CSRF_COOKIE, "")
        return bool(cookie) and hmac.compare_digest(cookie.encode(), header_tokens[0])
