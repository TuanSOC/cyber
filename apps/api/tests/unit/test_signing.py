"""`app/core/signing.py` (M6 phase 1): Ed25519 sign / verify over canonical manifests, key
files, reprs without key material, and the committed dev pair."""

import base64
import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cyberlab_jobs.report import TLP, Manifest, Profile, manifest_bytes

from app.core.config import DEV_REPORT_SIGNING_PUBLIC_KEYS, Settings, get_settings
from app.core.signing import (
    SigningError,
    load_public_keys,
    load_signing_keys,
    public_key_b64,
    sign,
    verify,
)
from app.modules.reports import signing as report_signing

REPO = Path(__file__).resolve().parents[4]


def _raw(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    ).decode()


def _manifest(**over: object) -> bytes:
    values: dict[str, object] = {
        "report_id": uuid.UUID(int=1),
        "version": 1,
        "org_id": uuid.UUID(int=2),
        "snapshot_sha256": "a" * 64,
        "snapshot_bytes": 1234,
        "tlp": TLP.AMBER,
        "profile": Profile.INTERNAL,
        "finalized_at": datetime(2026, 11, 6, 9, 0, tzinfo=UTC),
        "finalized_by": uuid.UUID(int=3),
        "kid": "k1",
    }
    values.update(over)
    return manifest_bytes(Manifest.model_validate(values))


@pytest.fixture
def keys(tmp_path: Path) -> tuple[Path, Ed25519PrivateKey]:
    private = Ed25519PrivateKey.generate()
    path = tmp_path / "signing.json"
    path.write_text(json.dumps({"k1": _raw(private)}))
    return path, private


def test_sign_verify_round_trip(keys: tuple[Path, Ed25519PrivateKey]) -> None:
    path, private = keys
    loaded = load_signing_keys(path)
    public = load_public_keys({"k1": public_key_b64(private)})
    data = _manifest()
    signature = sign(data, "k1", loaded)
    assert len(base64.b64decode(signature)) == 64
    assert verify(data, signature, "k1", public)
    # The same manifest from a dict with another key order gives the same bytes.
    assert _manifest() == data


def test_wrong_kid_or_flipped_byte_fails(keys: tuple[Path, Ed25519PrivateKey]) -> None:
    path, private = keys
    public = load_public_keys(json.dumps({"k1": public_key_b64(private)}))
    data = _manifest()
    signature = sign(data, "k1", load_signing_keys(path))
    assert not verify(data, signature, "k2", public)
    flipped = bytearray(data)
    flipped[10] ^= 0x01
    assert not verify(bytes(flipped), signature, "k1", public)
    raw = bytearray(base64.b64decode(signature))
    raw[0] ^= 0x01
    assert not verify(data, base64.b64encode(bytes(raw)).decode(), "k1", public)
    assert not verify(data, "not base64!", "k1", public)
    assert not verify(data, base64.b64encode(b"short").decode(), "k1", public)
    other = load_public_keys({"k1": public_key_b64(Ed25519PrivateKey.generate())})
    assert not verify(data, signature, "k1", other)
    assert not verify(_manifest(version=2), signature, "k1", public)


def test_unknown_kid_cannot_sign(keys: tuple[Path, Ed25519PrivateKey]) -> None:
    path, _ = keys
    with pytest.raises(SigningError, match="unknown_kid"):
        sign(b"x", "nope", load_signing_keys(path))


@pytest.mark.parametrize(
    "content",
    ["not json", "{}", "[]", '{"bad kid": "AAAA"}', '{"k1": "c2hvcnQ="}', '{"k1": 5}'],
)
def test_bad_key_files_are_refused(tmp_path: Path, content: str) -> None:
    path = tmp_path / "bad.json"
    path.write_text(content)
    with pytest.raises(SigningError, match="signing_keys_invalid|signing_keys_unreadable"):
        load_signing_keys(path)
    with pytest.raises(SigningError, match="signing_keys_unreadable"):
        load_signing_keys(tmp_path / "missing.json")


@pytest.mark.parametrize(
    "data",
    [
        "not json",
        "[]",
        {"k1": "c2hvcnQ="},
        {"bad kid": base64.b64encode(bytes(32)).decode()},
    ],
)
def test_bad_public_keys_are_refused(data: object) -> None:
    with pytest.raises(SigningError, match="public_keys_invalid"):
        load_public_keys(data)  # type: ignore[arg-type]


def test_errors_and_reprs_carry_no_key_material(keys: tuple[Path, Ed25519PrivateKey]) -> None:
    path, private = keys
    secret = _raw(private)
    loaded = load_signing_keys(path)
    assert secret not in repr(loaded) and secret not in str(loaded)
    bad = path.with_name("bad.json")
    bad.write_text(json.dumps({"k1": secret[:-4] + "!!!!"}))
    with pytest.raises(SigningError) as raised:
        load_signing_keys(bad)
    assert secret[:20] not in str(raised.value) and secret[:20] not in repr(raised.value)


def test_the_committed_dev_pair_matches_its_public_key() -> None:
    dev = REPO / "infra/reports/dev-signing-private.json"
    if not dev.exists():
        pytest.skip("infra/ is not mounted in this container")
    loaded = load_signing_keys(dev)
    assert set(loaded) == {"dev-report-1"}
    assert {public_key_b64(loaded["dev-report-1"])} == set(DEV_REPORT_SIGNING_PUBLIC_KEYS)


# --- prod api startup check (review L3) ---------------------------------------------------


@pytest.fixture
def prod_api(
    monkeypatch: pytest.MonkeyPatch, keys: tuple[Path, Ed25519PrivateKey]
) -> Iterator[tuple[Settings, Ed25519PrivateKey]]:
    path, private = keys
    settings = get_settings()
    monkeypatch.setattr(settings, "env", "prod")
    monkeypatch.setattr(settings, "process_role", "api")
    monkeypatch.setattr(settings, "report_signing_keys_file", str(path))
    monkeypatch.setattr(settings, "report_signing_active_kid", "k1")
    monkeypatch.setattr(settings, "report_signing_public_keys", {"k1": public_key_b64(private)})
    report_signing.reset_cache()
    yield settings, private
    report_signing.reset_cache()


def test_startup_check_accepts_a_matching_pair(
    prod_api: tuple[Settings, Ed25519PrivateKey],
) -> None:
    report_signing.check_startup_keys()


def test_startup_check_refuses_a_published_key_of_another_pair(
    monkeypatch: pytest.MonkeyPatch, prod_api: tuple[Settings, Ed25519PrivateKey]
) -> None:
    settings, _ = prod_api
    other = public_key_b64(Ed25519PrivateKey.generate())
    monkeypatch.setattr(settings, "report_signing_public_keys", {"k1": other})
    with pytest.raises(SigningError, match="active_key_mismatch"):
        report_signing.check_startup_keys()


def test_startup_check_refuses_an_active_kid_missing_from_the_file(
    monkeypatch: pytest.MonkeyPatch, prod_api: tuple[Settings, Ed25519PrivateKey]
) -> None:
    settings, private = prod_api
    monkeypatch.setattr(settings, "report_signing_active_kid", "k2")
    monkeypatch.setattr(settings, "report_signing_public_keys", {"k2": public_key_b64(private)})
    with pytest.raises(SigningError, match="active_kid_not_in_key_file"):
        report_signing.check_startup_keys()


def test_startup_check_refuses_an_unreadable_key_file(
    monkeypatch: pytest.MonkeyPatch, prod_api: tuple[Settings, Ed25519PrivateKey], tmp_path: Path
) -> None:
    settings, _ = prod_api
    monkeypatch.setattr(settings, "report_signing_keys_file", str(tmp_path / "missing.json"))
    with pytest.raises(SigningError, match="signing_keys_unreadable"):
        report_signing.check_startup_keys()


def test_startup_check_refuses_the_committed_dev_private_key(
    monkeypatch: pytest.MonkeyPatch, prod_api: tuple[Settings, Ed25519PrivateKey]
) -> None:
    """A key whose public half is a committed dev public key is the dev private key."""
    _, private = prod_api
    monkeypatch.setattr(
        report_signing, "DEV_REPORT_SIGNING_PUBLIC_KEYS", frozenset({public_key_b64(private)})
    )
    with pytest.raises(SigningError, match="dev_signing_key"):
        report_signing.check_startup_keys()


def test_the_real_dev_private_key_is_refused(
    monkeypatch: pytest.MonkeyPatch, prod_api: tuple[Settings, Ed25519PrivateKey]
) -> None:
    dev = REPO / "infra/reports/dev-signing-private.json"
    if not dev.exists():
        pytest.skip("infra/ is not mounted in this container")
    settings, _ = prod_api
    monkeypatch.setattr(settings, "report_signing_keys_file", str(dev))
    monkeypatch.setattr(settings, "report_signing_active_kid", "dev-report-1")
    monkeypatch.setattr(
        settings,
        "report_signing_public_keys",
        {"dev-report-1": next(iter(DEV_REPORT_SIGNING_PUBLIC_KEYS))},
    )
    with pytest.raises(SigningError, match="dev_signing_key"):
        report_signing.check_startup_keys()


def test_startup_check_is_prod_api_only(
    monkeypatch: pytest.MonkeyPatch, prod_api: tuple[Settings, Ed25519PrivateKey], tmp_path: Path
) -> None:
    settings, _ = prod_api
    monkeypatch.setattr(settings, "report_signing_keys_file", str(tmp_path / "missing.json"))
    monkeypatch.setattr(settings, "env", "test")
    report_signing.check_startup_keys()
    monkeypatch.setattr(settings, "env", "prod")
    monkeypatch.setattr(settings, "process_role", "analyst")
    report_signing.check_startup_keys()
