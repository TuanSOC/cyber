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

_hasher = PasswordHasher()  # argon2id with library defaults
# Verified against when the email is unknown, so both paths cost the same.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        _hasher.verify(password_hash or _DUMMY_HASH, password)
    except (VerificationError, InvalidHashError):
        return False
    return password_hash is not None


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
    family_id: uuid.UUID
    jti: str
    expires_at: datetime


def create_access_token(user_id: uuid.UUID, family_id: uuid.UUID) -> tuple[str, AccessClaims]:
    """`fid` ties the access token to its refresh family so revoking the family kills it."""
    now = datetime.now(UTC)
    claims = AccessClaims(
        user_id=user_id,
        family_id=family_id,
        jti=secrets.token_hex(16),
        expires_at=now + ACCESS_TOKEN_TTL,
    )
    token = jwt.encode(
        {
            "sub": str(user_id),
            "fid": str(family_id),
            "jti": claims.jti,
            "iat": now,
            "exp": claims.expires_at,
            "typ": "access",
        },
        get_settings().jwt_secret,
        algorithm=JWT_ALGORITHM,
    )
    return token, claims


def decode_access_token(token: str) -> AccessClaims:
    try:
        payload = jwt.decode(
            token,
            get_settings().jwt_secret,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["sub", "fid", "jti", "iat", "exp", "typ"]},
            leeway=0,
        )
        if payload["typ"] != "access":
            raise jwt.InvalidTokenError("wrong token type")
        return AccessClaims(
            user_id=uuid.UUID(payload["sub"]),
            family_id=uuid.UUID(payload["fid"]),
            jti=str(payload["jti"]),
            expires_at=datetime.fromtimestamp(payload["exp"], UTC),
        )
    except (jwt.PyJWTError, ValueError) as exc:
        raise Unauthorized(code="invalid_token") from exc


def new_opaque_token() -> tuple[str, str]:
    """Returns (token, sha256 hex). Only the hash is stored."""
    token = secrets.token_urlsafe(32)
    return token, hash_token(token)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)
