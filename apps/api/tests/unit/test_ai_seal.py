"""Sealed AI provider keys (M5 phase 1): the generic sealbox in the `cyberlab.ai.v1` domain.
The API seals with the public key, only the analyst worker opens; a TI ciphertext never opens
as AI (and vice versa) even under the same key pair."""

import base64
import dataclasses
import json
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from pydantic import SecretStr

from app.core import sealbox
from app.core.config import Settings
from app.core.sealbox import SealError, raw_public
from app.modules.ai.seal import AI_DOMAIN, AI_SCHEME, seal
from app.modules.ai.unseal import UnsealError, open_sealed
from app.modules.threat_intel import seal as ti_seal
from app.modules.threat_intel import unseal as ti_unseal
from app.workers import analyst

SENTINEL = "SENTINEL-ai-provider-key-0123456789abcdef"
ORG = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_ORG = uuid.UUID("22222222-2222-2222-2222-222222222222")
PRIVATE = X25519PrivateKey.generate()
KEYS = {"k1": PRIVATE}


def _seal(provider: str = "anthropic", version: int = 1, kid: str = "k1") -> sealbox.SealedKey:
    return seal(SecretStr(SENTINEL), ORG, provider, kid, version, PRIVATE.public_key())


@pytest.mark.parametrize("provider", ["anthropic", "gemini", "mock"])
def test_round_trip(provider: str) -> None:
    sealed = _seal(provider)
    assert sealed.last4 == SENTINEL[-4:]
    assert open_sealed(sealed, ORG, provider, KEYS).get_secret_value() == SENTINEL


def test_the_domain_is_its_own() -> None:
    assert AI_SCHEME == "cyberlab.ai.v1" != ti_seal.SCHEME
    assert AI_DOMAIN.providers == frozenset({"anthropic", "gemini", "mock"})
    assert not any(AI_DOMAIN.url_bound(p) for p in AI_DOMAIN.providers)
    aad = sealbox.aad(AI_DOMAIN, ORG, "anthropic", "k1", 2, "")
    assert aad == f"cyberlab.ai.v1|{ORG}|anthropic|k1|2|".encode()


@pytest.mark.parametrize(
    ("org", "provider"), [(OTHER_ORG, "anthropic"), (ORG, "gemini"), (ORG, "mock")]
)
def test_wrong_org_or_provider_fails(org: uuid.UUID, provider: str) -> None:
    with pytest.raises(UnsealError, match="unseal_failed"):
        open_sealed(_seal(), org, provider, KEYS)


def test_wrong_version_or_kid_fails() -> None:
    for version in (2, 4):
        with pytest.raises(UnsealError, match="unseal_failed"):
            open_sealed(
                dataclasses.replace(_seal(version=3), key_version=version), ORG, "anthropic", KEYS
            )
    with pytest.raises(UnsealError, match="unseal_failed"):
        open_sealed(dataclasses.replace(_seal(), kid="k2"), ORG, "anthropic", {"k2": PRIVATE})
    with pytest.raises(UnsealError, match="unknown_kid"):
        open_sealed(_seal(), ORG, "anthropic", {"other": PRIVATE})


@pytest.mark.parametrize("field", ["ct", "nonce", "epk"])
def test_a_flipped_byte_fails(field: str) -> None:
    sealed = _seal()
    raw = bytearray(getattr(sealed, field))
    raw[len(raw) // 2] ^= 0x01
    with pytest.raises(UnsealError, match="unseal_failed"):
        open_sealed(dataclasses.replace(sealed, **{field: bytes(raw)}), ORG, "anthropic", KEYS)


def test_an_ai_ciphertext_never_opens_as_ti_and_vice_versa() -> None:
    """Same key pair, same org, kid, version and provider name `mock` (valid in both
    domains): the scheme in the HKDF info and the AAD keeps the domains apart."""
    ai = seal(SENTINEL, ORG, "mock", "k1", 1, PRIVATE.public_key())
    with pytest.raises(UnsealError, match="unseal_failed"):
        ti_unseal.open_sealed(ai, ORG, "mock", "", KEYS)
    ti = ti_seal.seal(SENTINEL, ORG, "mock", "k1", 1, "", PRIVATE.public_key())
    with pytest.raises(UnsealError, match="unseal_failed"):
        open_sealed(ti, ORG, "mock", KEYS)
    # Sanity: each opens in its own domain.
    assert open_sealed(ai, ORG, "mock", KEYS).get_secret_value() == SENTINEL
    assert ti_unseal.open_sealed(ti, ORG, "mock", "", KEYS).get_secret_value() == SENTINEL


def test_each_domain_refuses_the_others_providers() -> None:
    with pytest.raises(SealError, match="unknown_provider"):
        seal(SENTINEL, ORG, "virustotal", "k1", 1, PRIVATE.public_key())
    with pytest.raises(SealError, match="unknown_provider"):
        ti_seal.seal(SENTINEL, ORG, "anthropic", "k1", 1, "", PRIVATE.public_key())
    with pytest.raises(UnsealError, match="unknown_provider"):
        open_sealed(_seal(), ORG, "otx", KEYS)


@pytest.mark.parametrize(
    ("kid", "version", "code"), [("k|1", 1, "bad_kid"), ("k1", 0, "bad_key_version")]
)
def test_seal_context_is_validated(kid: str, version: int, code: str) -> None:
    with pytest.raises(SealError, match=code):
        seal(SENTINEL, ORG, "anthropic", kid, version, PRIVATE.public_key())


@pytest.mark.parametrize("bad", [f" {SENTINEL}", f"{SENTINEL}\n", "1234567", "x" * 257, "é" * 9])
def test_key_rules_are_the_m4_rules(bad: str) -> None:
    with pytest.raises(SealError) as caught:
        seal(bad, ORG, "anthropic", "k1", 1, PRIVATE.public_key())
    assert caught.value.code == "bad_api_key"
    assert bad not in str(caught.value) + repr(caught.value)


def test_plaintext_never_in_reprs_or_errors() -> None:
    sealed = _seal()
    assert SENTINEL not in repr(sealed) and SENTINEL[-4:] not in repr(sealed)
    opened = open_sealed(sealed, ORG, "anthropic", KEYS)
    assert SENTINEL not in repr(opened) and SENTINEL not in str(opened)
    try:
        open_sealed(sealed, OTHER_ORG, "anthropic", KEYS)
    except UnsealError as exc:
        assert SENTINEL not in repr(exc) and SENTINEL not in str(exc)


# --- analyst worker startup check -----------------------------------------------------------


def _key_file(tmp_path: Path, content: object) -> Path:
    path = tmp_path / "keys.json"
    path.write_text(content if isinstance(content, str) else json.dumps(content))
    return path


def _b64(key: X25519PrivateKey) -> str:
    return base64.b64encode(
        key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    ).decode()


def _analyst_settings(path: Path | None, kid: str = "k1", public: str | None = None) -> Settings:
    return Settings(
        process_role="analyst",
        database_url="postgresql+asyncpg://cyberlab_app:x@postgres/cyberlab_test",
        broker_url="redis://analyst:x@redis-broker:6379/1",
        jwt_secret=None,
        redis_url=None,
        minio_endpoint=None,
        minio_access_key=None,
        minio_secret_key=None,
        ti_seal_private_keys_file=None,
        ai_seal_private_keys_file=str(path) if path else None,
        ai_seal_active_kid=kid,
        ai_seal_public_keys={
            kid: public or base64.b64encode(raw_public(PRIVATE.public_key())).decode()
        },
    )


def test_analyst_startup_check(tmp_path: Path) -> None:
    path = _key_file(tmp_path, {"k1": _b64(PRIVATE)})
    analyst.check_startup(_analyst_settings(path))  # usable: no error
    with pytest.raises(RuntimeError, match="AI_SEAL_PRIVATE_KEYS_FILE is not set"):
        analyst.check_startup(_analyst_settings(None))
    with pytest.raises(RuntimeError, match="unusable"):
        analyst.check_startup(_analyst_settings(tmp_path / "missing.json"))
    garbled = tmp_path / "garbled.json"
    garbled.write_text("not json")
    with pytest.raises(RuntimeError, match="unusable"):
        analyst.check_startup(_analyst_settings(garbled))
    with pytest.raises(RuntimeError, match="lacks the active kid"):
        analyst.check_startup(_analyst_settings(path, kid="k2"))
    other = base64.b64encode(raw_public(X25519PrivateKey.generate().public_key())).decode()
    with pytest.raises(RuntimeError, match="does not match"):
        analyst.check_startup(_analyst_settings(path, public=other))
