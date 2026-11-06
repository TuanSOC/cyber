import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Annotated, Literal

from fastapi import Depends, Request

from app.core import rate_limit
from app.core.client_ip import ip_key
from app.core.clients import get_redis
from app.core.config import get_settings
from app.core.cookies import ACCESS_COOKIE
from app.core.errors import Unauthorized
from app.core.security import decode_access_token
from app.core.tenancy import tenant_session
from app.modules.api_keys.auth import ParsedKey, is_bearer_attempt, parse_bearer
from app.modules.identity.errors import AmbiguousCredentials, InvalidApiKey
from app.modules.users import repository as users
from app.modules.users.models import UserKind

DENYLIST_PREFIX = "denylist:"
FAMILY_DENYLIST_PREFIX = "denylist:fam:"

# M7 (phase 6): the global per-user API limit. Exempt: `GET /auth/me` (the shell polls it to
# keep the session). The health routes and `GET /report-signing-keys` never call
# `current_user` (the keys route has its own per-IP limit), so they are exempt by
# construction. The unauthenticated surface (login, register, refresh) keeps its own limits;
# there is no anonymous per-IP limiter (RT14, cut).
USER_LIMIT_PREFIX = "u:"
USER_LIMIT_WINDOW_S = 60
USER_LIMIT_EXEMPT: frozenset[tuple[str, str]] = frozenset({("GET", "/api/v1/auth/me")})
_COUNTED = "cyberlab_user_limit_counted"
# M11: format-invalid bearer keys per client IP (before any database read).
API_KEY_FAILURE_PREFIX = "apikey:fail:ip:"
API_KEY_FAILURE_WINDOW_S = 60

PrincipalKind = Literal["session", "api_key"]


@dataclass(frozen=True)
class CurrentUser:
    """The authenticated principal of a request.

    M11: `session_id` (= `family_id`, the `user_sessions` row), `amr`, `sso_org_id` (the org of
    an SSO session), `kind` (`session`, or `api_key` for the service account a key resolved
    to inside `org_session`), `has_password` (a usable local password: the SSO scope rule,
    RT2) and `api_key_id` (keys only). The defaults keep pre-M11 constructions valid."""

    id: uuid.UUID
    email: str
    display_name: str
    jti: str
    family_id: uuid.UUID
    token_expires_at: datetime
    amr: frozenset[str] = field(default_factory=lambda: frozenset({"pwd"}))
    sso_org_id: uuid.UUID | None = None
    kind: PrincipalKind = "session"
    has_password: bool = True
    api_key_id: uuid.UUID | None = None

    @property
    def session_id(self) -> uuid.UUID:
        return self.family_id


@dataclass(frozen=True)
class ApiKeyPrincipal:
    """An `Authorization: Bearer clk_…` request before its key is resolved: only org routes
    (`core.rbac.require` / `org_session`) accept it; they resolve the key inside the org's
    tenant session (phase 9) and continue with the service account as a `CurrentUser`."""

    parsed: ParsedKey
    ip: str
    kind: Literal["api_key"] = "api_key"


Principal = CurrentUser | ApiKeyPrincipal


async def _count_request(request: Request, key: str) -> None:
    """One hit per request (an upload or download body counts once), whatever the number of
    dependencies resolving the user. 429 with `Retry-After`; a Redis failure fails closed.
    `key` is the user id, or `key:<public id>` for an API key (M11)."""
    if (request.method, request.url.path) in USER_LIMIT_EXEMPT:
        return
    if getattr(request.state, _COUNTED, False):
        return
    setattr(request.state, _COUNTED, True)
    await rate_limit.hit(
        f"{USER_LIMIT_PREFIX}{key}",
        get_settings().rate_limit_user_per_min,
        USER_LIMIT_WINDOW_S,
    )


def _refuse_bearer(request: Request) -> None:
    """A bearer key together with a session cookie is ambiguous (M11): 400."""
    if is_bearer_attempt(request.headers.get("authorization")):
        if request.cookies.get(ACCESS_COOKIE):
            raise AmbiguousCredentials()
        raise Unauthorized(code="invalid_token")


async def current_user(request: Request) -> CurrentUser:
    """The session principal (cookie). Session-only by construction: an API-key request is
    refused (`401 invalid_token`), so every non-org route refuses keys (M11)."""
    _refuse_bearer(request)
    return await _session_user(request)


async def _session_user(request: Request) -> CurrentUser:
    token = request.cookies.get(ACCESS_COOKIE)
    if not token:
        raise Unauthorized()
    claims = decode_access_token(token)
    # Denied individually (logout) or with its whole refresh family (logout/reuse/deactivation).
    if await get_redis().exists(
        DENYLIST_PREFIX + claims.jti, FAMILY_DENYLIST_PREFIX + str(claims.family_id)
    ):
        raise Unauthorized(code="invalid_token")
    # After the token is validated, before the database lookup (a flood costs Redis only).
    await _count_request(request, str(claims.user_id))
    async with tenant_session(None, None) as session:
        user = await users.get_active(session, claims.user_id)
    # Service and system accounts never hold a session (M11).
    if user is None or user.kind != UserKind.HUMAN.value:
        raise Unauthorized(code="invalid_token")
    return CurrentUser(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        jti=claims.jti,
        family_id=claims.family_id,
        token_expires_at=claims.expires_at,
        amr=frozenset(claims.amr),
        sso_org_id=claims.sso_org_id,
        kind="session",
        has_password=user.has_password,
    )


async def current_principal(request: Request) -> Principal:
    """A session (cookie) or an API key (`Authorization: Bearer clk_…`, M11).

    Both at once -> `400 ambiguous_credentials`. A malformed bearer value -> `401
    invalid_api_key` after one hit on the per-IP failure limit (429 once exceeded), before
    any database read. A well-formed key is resolved later, inside the org's tenant session."""
    header = request.headers.get("authorization")
    if not is_bearer_attempt(header):
        return await _session_user(request)
    if request.cookies.get(ACCESS_COOKIE):
        raise AmbiguousCredentials()
    ip = ip_key(request)
    parsed = parse_bearer(header or "")
    if parsed is None:
        await rate_limit.hit(
            f"{API_KEY_FAILURE_PREFIX}{ip}",
            get_settings().rate_limit_api_key_failures_per_ip_per_min,
            API_KEY_FAILURE_WINDOW_S,
        )
        raise InvalidApiKey()
    await _count_request(request, f"key:{parsed.public_id}")
    return ApiKeyPrincipal(parsed=parsed, ip=ip)


CurrentUserDep = Annotated[CurrentUser, Depends(current_user)]
PrincipalDep = Annotated[Principal, Depends(current_principal)]
