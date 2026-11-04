"""Sealed provider keys: the API seals with a public key, only the enrich worker opens."""

import base64
import dataclasses
import json
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from pydantic import SecretStr

from app.core.config import Settings
from app.modules.threat_intel.seal import SealedKey, SealError, raw_public, seal
from app.modules.threat_intel.unseal import UnsealError, load_private_keys, open_sealed
from app.workers import enrich

SENTINEL = "SENTINEL-provider-key-0123456789abcdef"
ORG = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_ORG = uuid.UUID("22222222-2222-2222-2222-222222222222")
MISP_URL = "https://misp.example.org"
PRIVATE = X25519PrivateKey.generate()
KEYS = {"k1": PRIVATE}


def _seal(
    provider: str = "virustotal", base_url: str = "", version: int = 1, kid: str = "k1"
) -> SealedKey:
    return seal(SecretStr(SENTINEL), ORG, provider, kid, version, base_url, PRIVATE.public_key())


def test_round_trip() -> None:
    sealed = _seal()
    assert sealed.last4 == SENTINEL[-4:]
    assert len(sealed.epk) == 32 and len(sealed.nonce) == 12
    opened = open_sealed(sealed, ORG, "virustotal", "", KEYS)
    assert opened.get_secret_value() == SENTINEL


def test_misp_round_trip_is_bound_to_its_url() -> None:
    sealed = _seal("misp", MISP_URL)
    assert open_sealed(sealed, ORG, "misp", MISP_URL, KEYS).get_secret_value() == SENTINEL
    for other in (
        "https://evil.example",
        "https://misp.example.org/",
        "https://misp.example.org:8443",
    ):
        with pytest.raises(UnsealError, match="unseal_failed"):
            open_sealed(sealed, ORG, "misp", other, KEYS)


def test_each_seal_is_unique() -> None:
    first, second = _seal(), _seal()
    assert first.epk != second.epk and first.nonce != second.nonce and first.ct != second.ct


@pytest.mark.parametrize(
    ("org", "provider"),
    [(OTHER_ORG, "virustotal"), (ORG, "otx"), (ORG, "abuseipdb")],
)
def test_wrong_org_or_provider_fails(org: uuid.UUID, provider: str) -> None:
    with pytest.raises(UnsealError, match="unseal_failed"):
        open_sealed(_seal(), org, provider, "", KEYS)


def test_wrong_key_version_fails() -> None:
    sealed = dataclasses.replace(_seal(version=3), key_version=4)
    with pytest.raises(UnsealError, match="unseal_failed"):
        open_sealed(sealed, ORG, "virustotal", "", KEYS)
    rolled_back = dataclasses.replace(_seal(version=3), key_version=2)
    with pytest.raises(UnsealError, match="unseal_failed"):
        open_sealed(rolled_back, ORG, "virustotal", "", KEYS)


def test_wrong_kid_fails() -> None:
    # The same private key under another kid: the kid is in the AAD.
    sealed = dataclasses.replace(_seal(), kid="k2")
    with pytest.raises(UnsealError, match="unseal_failed"):
        open_sealed(sealed, ORG, "virustotal", "", {"k2": PRIVATE})


def test_unknown_kid_fails() -> None:
    with pytest.raises(UnsealError, match="unknown_kid"):
        open_sealed(_seal(), ORG, "virustotal", "", {"other": PRIVATE})


def test_another_private_key_fails() -> None:
    with pytest.raises(UnsealError, match="unseal_failed"):
        open_sealed(_seal(), ORG, "virustotal", "", {"k1": X25519PrivateKey.generate()})


@pytest.mark.parametrize("field", ["ct", "nonce", "epk"])
def test_a_flipped_byte_fails(field: str) -> None:
    sealed = _seal()
    raw = bytearray(getattr(sealed, field))
    raw[len(raw) // 2] ^= 0x01
    with pytest.raises(UnsealError, match="unseal_failed"):
        open_sealed(dataclasses.replace(sealed, **{field: bytes(raw)}), ORG, "virustotal", "", KEYS)


def test_truncated_parts_fail() -> None:
    sealed = _seal()
    for broken in (
        dataclasses.replace(sealed, nonce=sealed.nonce[:-1]),
        dataclasses.replace(sealed, epk=sealed.epk[:-1]),
        dataclasses.replace(sealed, ct=sealed.ct[:-1]),
        dataclasses.replace(sealed, epk=bytes(32)),  # low-order point
    ):
        with pytest.raises(UnsealError):
            open_sealed(broken, ORG, "virustotal", "", KEYS)


def test_plaintext_never_in_reprs_or_errors() -> None:
    sealed = _seal()
    assert SENTINEL not in repr(sealed) and SENTINEL[-4:] not in repr(sealed)
    assert SENTINEL not in str(sealed)
    try:
        open_sealed(sealed, OTHER_ORG, "virustotal", "", KEYS)
    except UnsealError as exc:
        assert SENTINEL not in repr(exc) and SENTINEL not in str(exc)
    opened = open_sealed(sealed, ORG, "virustotal", "", KEYS)
    assert SENTINEL not in repr(opened) and SENTINEL not in str(opened)
    for bad in ("x" * 300, "short", "tab\tinside-the-key"):
        try:
            seal(bad, ORG, "otx", "k1", 1, "", PRIVATE.public_key())
        except SealError as exc:
            assert bad not in str(exc) and bad not in repr(exc)
        else:
            pytest.fail("bad key accepted")


@pytest.mark.parametrize(
    ("provider", "base_url", "kid", "version", "code"),
    [
        ("misp", "", "k1", 1, "base_url_mismatch"),
        ("otx", MISP_URL, "k1", 1, "base_url_mismatch"),
        ("nope", "", "k1", 1, "unknown_provider"),
        ("otx", "", "k|1", 1, "bad_kid"),
        ("otx", "", "k1", 0, "bad_key_version"),
    ],
)
def test_seal_context_is_validated(
    provider: str, base_url: str, kid: str, version: int, code: str
) -> None:
    with pytest.raises(SealError, match=code):
        seal(SENTINEL, ORG, provider, kid, version, base_url, PRIVATE.public_key())


def _key_file(tmp_path: Path, content: object) -> Path:
    path = tmp_path / "keys.json"
    path.write_text(content if isinstance(content, str) else json.dumps(content))
    return path


def _b64(key: X25519PrivateKey) -> str:
    return base64.b64encode(
        key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    ).decode()


def test_private_key_file_loading(tmp_path: Path) -> None:
    keys = load_private_keys(_key_file(tmp_path, {"k1": _b64(PRIVATE)}))
    assert raw_public(keys["k1"].public_key()) == raw_public(PRIVATE.public_key())
    for bad in ("not json", {}, {"k 1": _b64(PRIVATE)}, {"k1": "c2hvcnQ="}, ["k1"]):
        with pytest.raises(UnsealError, match="private_keys_invalid|private_keys_unreadable"):
            load_private_keys(_key_file(tmp_path, bad))
    with pytest.raises(UnsealError, match="private_keys_unreadable"):
        load_private_keys(tmp_path / "missing.json")


def _enrich_settings(path: Path | None, kid: str = "k1", public: str | None = None) -> Settings:
    return Settings(
        process_role="enrich",
        database_url="postgresql+asyncpg://cyberlab_app:x@postgres/cyberlab_test",
        broker_url="redis://enrich:x@redis-broker:6379/1",
        jwt_secret=None,
        redis_url=None,
        minio_endpoint=None,
        minio_access_key=None,
        minio_secret_key=None,
        ti_seal_private_keys_file=str(path) if path else None,
        ti_seal_active_kid=kid,
        ti_seal_public_keys={
            kid: public or base64.b64encode(raw_public(PRIVATE.public_key())).decode()
        },
    )


def test_worker_startup_check(tmp_path: Path) -> None:
    path = _key_file(tmp_path, {"k1": _b64(PRIVATE)})
    enrich.check_startup(_enrich_settings(path))  # usable: no error
    with pytest.raises(RuntimeError, match="TI_SEAL_PRIVATE_KEYS_FILE is not set"):
        enrich.check_startup(_enrich_settings(None))
    with pytest.raises(RuntimeError, match="unusable"):
        enrich.check_startup(_enrich_settings(tmp_path / "missing.json"))
    with pytest.raises(RuntimeError, match="lacks the active kid"):
        enrich.check_startup(_enrich_settings(path, kid="k2"))
    other = base64.b64encode(raw_public(X25519PrivateKey.generate().public_key())).decode()
    with pytest.raises(RuntimeError, match="does not match"):
        enrich.check_startup(_enrich_settings(path, public=other))
