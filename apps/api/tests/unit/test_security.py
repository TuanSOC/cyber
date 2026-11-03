import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.config import get_settings
from app.core.errors import Unauthorized
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    hash_token,
    new_opaque_token,
    verify_password,
)


def test_password_hash_is_argon2id_and_verifies() -> None:
    hashed = hash_password("correct horse battery staple")
    assert hashed.startswith("$argon2id$")
    assert verify_password(hashed, "correct horse battery staple")
    assert not verify_password(hashed, "wrong password!!")


def test_verify_without_hash_is_false() -> None:
    assert not verify_password(None, "anything at all")


def test_opaque_token_stores_only_hash() -> None:
    token, digest = new_opaque_token()
    assert digest == hash_token(token)
    assert token not in digest
    assert len(digest) == 64


def test_access_token_round_trip() -> None:
    user_id, family_id = uuid.uuid4(), uuid.uuid4()
    token, claims = create_access_token(user_id, family_id)
    decoded = decode_access_token(token)
    assert decoded.user_id == user_id
    assert decoded.family_id == family_id
    assert decoded.jti == claims.jti


def _forge(payload: dict[str, object], secret: str | None = None, alg: str = "HS256") -> str:
    return jwt.encode(payload, secret or get_settings().jwt_secret, algorithm=alg)


def _claims(**overrides: object) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "sub": str(uuid.uuid4()),
        "fid": str(uuid.uuid4()),
        "jti": "abc",
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "typ": "access",
        **overrides,
    }


@pytest.mark.parametrize(
    "token_factory",
    [
        lambda: _forge(_claims(exp=datetime.now(UTC) - timedelta(seconds=1))),  # expired
        lambda: _forge(_claims(), secret="x" * 48),  # wrong key
        lambda: _forge(_claims(typ="refresh")),  # wrong type
        lambda: _forge({k: v for k, v in _claims().items() if k != "jti"}),  # missing claim
        lambda: jwt.encode(_claims(), key="", algorithm="none"),  # alg=none
        lambda: _forge(_claims(), alg="HS512"),  # unexpected algorithm
        lambda: "not-a-jwt",
    ],
)
def test_invalid_access_tokens_are_rejected(token_factory: object) -> None:
    with pytest.raises(Unauthorized):
        decode_access_token(token_factory())  # type: ignore[operator]
