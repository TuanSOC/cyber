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
        "fid": (fid := str(uuid.uuid4())),
        "sid": fid,
        "amr": ["pwd"],
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
        # M11: pre-M11 tokens (no sid / amr) and malformed session claims are refused.
        lambda: _forge({k: v for k, v in _claims().items() if k != "sid"}),
        lambda: _forge({k: v for k, v in _claims().items() if k != "amr"}),
        lambda: _forge(_claims(sid=str(uuid.uuid4()))),  # sid != fid
        lambda: _forge(_claims(amr=[])),
        lambda: _forge(_claims(amr=["pwd", "magic"])),
        lambda: _forge(_claims(amr="pwd")),
        lambda: _forge(_claims(sso="not-a-uuid")),
        lambda: jwt.encode(_claims(), key="", algorithm="none"),  # alg=none
        lambda: _forge(_claims(), alg="HS512"),  # unexpected algorithm
        lambda: "not-a-jwt",
    ],
)
def test_invalid_access_tokens_are_rejected(token_factory: object) -> None:
    with pytest.raises(Unauthorized):
        decode_access_token(token_factory())  # type: ignore[operator]


def test_access_token_carries_the_session_claims() -> None:
    user_id, family_id, org_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    token, _ = create_access_token(user_id, family_id, amr=["sso"], sso_org_id=org_id)
    decoded = decode_access_token(token)
    assert decoded.amr == ("sso",)
    assert decoded.sso_org_id == org_id
    payload = jwt.decode(token, options={"verify_signature": False})
    assert payload["sid"] == payload["fid"] == str(family_id)
    plain, _ = create_access_token(user_id, family_id)
    assert "sso" not in jwt.decode(plain, options={"verify_signature": False})
    assert decode_access_token(plain).amr == ("pwd",)


@pytest.mark.parametrize("amr", [[], ["bogus"]])
def test_access_token_refuses_unknown_amr(amr: list[str]) -> None:
    with pytest.raises(ValueError):
        create_access_token(uuid.uuid4(), uuid.uuid4(), amr=amr)


class _CountingHasher:
    """Counts argon2 verifications (RT5 is a timing-class property: every path verifies once)."""

    def __init__(self, real: object) -> None:
        self.real = real
        self.calls = 0

    def verify(self, hashed: str, password: str) -> bool:
        self.calls += 1
        return self.real.verify(hashed, password)  # type: ignore[attr-defined, no-any-return]


@pytest.mark.parametrize(
    "stored",
    [None, "!sso", "!service", "!unusable:retention-system-user", "not-an-argon2-hash"],
)
def test_unusable_hashes_pay_one_full_verification(
    stored: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """M11 RT5: SSO, service, system and unknown accounts answer login in one timing class.
    An unparsable hash fails fast inside argon2, so the dummy hash runs after it."""
    from app.core import security

    counter = _CountingHasher(security._hasher)
    monkeypatch.setattr(security, "_hasher", counter)
    assert verify_password(stored, "correct horse battery staple") is False
    expected = 2 if stored == "not-an-argon2-hash" else 1
    assert counter.calls == expected


def test_a_usable_hash_verifies_once(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core import security

    hashed = hash_password("correct horse battery staple")
    counter = _CountingHasher(security._hasher)
    monkeypatch.setattr(security, "_hasher", counter)
    assert verify_password(hashed, "correct horse battery staple") is True
    assert verify_password(hashed, "wrong password!!") is False
    assert counter.calls == 2
