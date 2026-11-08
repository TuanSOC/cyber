"""MFA login challenges stored in Redis (M11 phase 5).

When a user with an active or locked MFA factor signs in with a valid password,
a challenge is created in Redis with a 5-minute TTL. No session is issued yet.
The response returns 202 Accepted with `cl_mfa` (the challenge ID) and `cl_csrf`.
"""

from __future__ import annotations

import json
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from app.core.clients import get_redis
from app.core.security import new_csrf_token

CHALLENGE_PREFIX = "auth:mfa:challenge:"
CHALLENGE_TTL_S = 300
MAX_CHALLENGE_ATTEMPTS = 5


@dataclass(frozen=True)
class MfaChallenge:
    """M11 phase 5: the password was right and the account has an active factor. The router
    answers `202 MfaChallengeOut`, sets `cl_mfa` (= `challenge_id`) and `cl_csrf`; no session
    exists yet. Phase 1 never returns one (no factor can be enrolled before phase 5)."""

    challenge_id: str = field(repr=False)
    csrf_token: str = field(repr=False)
    methods: tuple[str, ...]


async def create_challenge(
    user_id: uuid.UUID,
    *,
    password_changed_at: str | None,
    methods: tuple[str, ...],
) -> MfaChallenge:
    """Store challenge in Redis and return MfaChallenge dataclass."""
    challenge_id = secrets.token_hex(32)
    csrf_token = new_csrf_token()
    data = {
        "user_id": str(user_id),
        "created_at": time.time(),
        "attempts": 0,
        "password_changed_at": password_changed_at,
        "methods": list(methods),
    }
    redis = get_redis()
    await redis.set(
        f"{CHALLENGE_PREFIX}{challenge_id}",
        json.dumps(data),
        ex=CHALLENGE_TTL_S,
    )
    return MfaChallenge(
        challenge_id=challenge_id,
        csrf_token=csrf_token,
        methods=methods,
    )


async def get_challenge(challenge_id: str) -> dict[str, Any] | None:
    """Retrieve challenge data from Redis, or None if expired/missing."""
    redis = get_redis()
    raw = await redis.get(f"{CHALLENGE_PREFIX}{challenge_id}")
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


async def increment_attempts(challenge_id: str) -> int:
    """Increment attempt count in challenge and refresh remaining TTL."""
    redis = get_redis()
    key = f"{CHALLENGE_PREFIX}{challenge_id}"
    raw = await redis.get(key)
    if raw is None:
        return MAX_CHALLENGE_ATTEMPTS + 1
    try:
        data = json.loads(raw)
    except Exception:
        return MAX_CHALLENGE_ATTEMPTS + 1

    data["attempts"] = data.get("attempts", 0) + 1
    ttl = await redis.ttl(key)
    if ttl > 0:
        await redis.set(key, json.dumps(data), ex=ttl)
    return data["attempts"]


async def delete_challenge(challenge_id: str) -> None:
    """Delete challenge from Redis immediately upon completion or cap breach."""
    redis = get_redis()
    await redis.delete(f"{CHALLENGE_PREFIX}{challenge_id}")
