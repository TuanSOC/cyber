"""Platform API key authentication (M11 phase 1, FROZEN signatures).

A key is `clk_<public id>_<secret>`: 12 lowercase base32-ish characters, then the 43
characters of `secrets.token_urlsafe(32)`. Only sha256 of the secret is stored.

- `parse_bearer(value)` (implemented): the format check of an `Authorization` header value,
  no database access; `None` for anything that is not exactly `Bearer clk_…`.
- `resolve(session, org_id, parsed)` (phase 9): looked up inside the org's tenant session by
  `public_id`, constant-time hash compare, not revoked, not expired (DB `now()`); answers
  `401 invalid_api_key` otherwise. Until phase 9 every key is refused.
"""

import hashlib
import hmac
import re
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.identity.errors import InvalidApiKey

KEY_PREFIX = "clk_"
PUBLIC_ID_LENGTH = 12
_PUBLIC_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
_KEY = re.compile(r"clk_([a-z0-9]{12})_([A-Za-z0-9_-]{43})")
_BEARER = re.compile(r"Bearer ([^\s]+)", re.IGNORECASE)


@dataclass(frozen=True)
class ParsedKey:
    public_id: str
    secret: str = field(repr=False)

    def __str__(self) -> str:  # never the secret
        return f"clk_{self.public_id}_***"


@dataclass(frozen=True)
class ResolvedKey:
    """A live key of the org. `scopes` are permission values (`core.rbac.Permission`)."""

    key_id: uuid.UUID
    public_id: str
    service_user_id: uuid.UUID
    name: str
    role: str
    scopes: frozenset[str]
    expires_at: datetime


def parse_bearer(value: str) -> ParsedKey | None:
    """`Bearer clk_<12>_<43>` exactly (one space, nothing else), or None."""
    match = _BEARER.fullmatch(value.strip())
    if match is None:
        return None
    key = _KEY.fullmatch(match.group(1))
    if key is None:
        return None
    return ParsedKey(public_id=key.group(1), secret=key.group(2))


def is_bearer_attempt(value: str | None) -> bool:
    """An `Authorization: Bearer …` header (any token): the request means to use a key."""
    return value is not None and value.strip()[:7].lower() == "bearer "


def secret_hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def secret_matches(secret: str, stored_hash: str) -> bool:
    return hmac.compare_digest(secret_hash(secret), stored_hash)


def new_key() -> tuple[str, ParsedKey]:
    """A fresh key (shown once) and its parts."""
    public_id = "".join(secrets.choice(_PUBLIC_ALPHABET) for _ in range(PUBLIC_ID_LENGTH))
    parsed = ParsedKey(public_id=public_id, secret=secrets.token_urlsafe(32))
    return format_key(parsed), parsed


def format_key(parsed: ParsedKey) -> str:
    return f"{KEY_PREFIX}{parsed.public_id}_{parsed.secret}"


async def resolve(session: AsyncSession, org_id: uuid.UUID, parsed: ParsedKey) -> ResolvedKey:
    """Phase 9 implements the lookup; until then no key authenticates."""
    raise InvalidApiKey()
