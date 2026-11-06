import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import anyio
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.core.config import get_settings
from app.core.errors import Unauthorized

ACCESS_TOKEN_TTL = timedelta(minutes=15)
REFRESH_TOKEN_TTL = timedelta(days=7)
# A session (refresh family) cannot outlive this, however often it is rotated.
SESSION_MAX_AGE = timedelta(days=30)
JWT_ALGORITHM = "HS256"
# A stored hash with this prefix never verifies (the M7 system user, M11 SSO-only users and
# service accounts).
UNUSABLE_PREFIX = "!"
# Session authentication methods an access token may carry (`user_sessions.amr`, M11).
AMR_VALUES = frozenset({"pwd", "otp", "recovery", "sso"})

_hasher = PasswordHasher()  # argon2id with library defaults
# Verified against when the email is unknown, so both paths cost the same.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def _dummy_verify(password: str) -> None:
    try:
        _hasher.verify(_DUMMY_HASH, password)
    except (VerificationError, InvalidHashError):
        pass


def verify_password(password_hash: str | None, password: str) -> bool:
    """argon2 verify. An unknown user (None), an unusable (`!…`) or an unparsable stored hash
    all pay the dummy-hash cost before answering False, so login answers every account state
    in one timing class (M11 RT5: argon2 used to reject a `!…` hash at once)."""
    if password_hash is None or password_hash.startswith(UNUSABLE_PREFIX):
        _dummy_verify(password)
        return False
    try:
        _hasher.verify(password_hash, password)
    except InvalidHashError:
        _dummy_verify(password)
        return False
    except VerificationError:
        return False
    return True


# argon2 is CPU-bound (~50-100 ms); keep it off the event loop (cffi releases the GIL).
async def hash_password_async(password: str) -> str:
    return await anyio.to_thread.run_sync(hash_password, password)


async def verify_password_async(password_hash: str | None, password: str) -> bool:
    return await anyio.to_thread.run_sync(verify_password, password_hash, password)


def password_needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


@dataclass(frozen=True)
class AccessClaims:
    user_id: uuid.UUID
    family_id: uuid.UUID  # = `sid`: the `user_sessions` row (M11)
    jti: str
    expires_at: datetime
    amr: tuple[str, ...] = ("pwd",)
    sso_org_id: uuid.UUID | None = None


def create_access_token(
    user_id: uuid.UUID,
    family_id: uuid.UUID,
    *,
    amr: tuple[str, ...] | list[str] = ("pwd",),
    sso_org_id: uuid.UUID | None = None,
) -> tuple[str, AccessClaims]:
    """`fid` ties the access token to its refresh family so revoking the family kills it.

    M11: `sid` (= the family id, the `user_sessions` row), `amr` (the session's methods) and
    `sso` (the org of an SSO session; absent otherwise)."""
    amr_t = tuple(amr)
    if not amr_t or not set(amr_t) <= AMR_VALUES:
        raise ValueError("invalid amr")
    now = datetime.now(UTC)
    claims = AccessClaims(
        user_id=user_id,
        family_id=family_id,
        jti=secrets.token_hex(16),
        expires_at=now + ACCESS_TOKEN_TTL,
        amr=amr_t,
        sso_org_id=sso_org_id,
    )
    payload: dict[str, object] = {
        "sub": str(user_id),
        "fid": str(family_id),
        "sid": str(family_id),
        "amr": list(amr_t),
        "jti": claims.jti,
        "iat": now,
        "exp": claims.expires_at,
        "typ": "access",
    }
    if sso_org_id is not None:
        payload["sso"] = str(sso_org_id)
    token = jwt.encode(payload, get_settings().need("jwt_secret"), algorithm=JWT_ALGORITHM)
    return token, claims


def decode_access_token(token: str) -> AccessClaims:
    """M11: `sid` and `amr` are required. A pre-M11 token is refused once; the web's refresh
    re-issues it (migration 0019 backfilled a session row for every live family, RT7)."""
    try:
        payload = jwt.decode(
            token,
            get_settings().need("jwt_secret"),
            algorithms=[JWT_ALGORITHM],
            options={"require": ["sub", "fid", "sid", "amr", "jti", "iat", "exp", "typ"]},
            leeway=0,
        )
        if payload["typ"] != "access":
            raise jwt.InvalidTokenError("wrong token type")
        if payload["sid"] != payload["fid"]:
            raise jwt.InvalidTokenError("sid mismatch")
        amr = payload["amr"]
        if (
            not isinstance(amr, list)
            or not amr
            or not all(isinstance(v, str) and v in AMR_VALUES for v in amr)
        ):
            raise jwt.InvalidTokenError("bad amr")
        sso = payload.get("sso")
        return AccessClaims(
            user_id=uuid.UUID(payload["sub"]),
            family_id=uuid.UUID(payload["fid"]),
            jti=str(payload["jti"]),
            expires_at=datetime.fromtimestamp(payload["exp"], UTC),
            amr=tuple(amr),
            sso_org_id=uuid.UUID(sso) if sso is not None else None,
        )
    except (jwt.PyJWTError, ValueError, TypeError, AttributeError) as exc:
        raise Unauthorized(code="invalid_token") from exc


def new_opaque_token() -> tuple[str, str]:
    """Returns (token, sha256 hex). Only the hash is stored."""
    token = secrets.token_urlsafe(32)
    return token, hash_token(token)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)
