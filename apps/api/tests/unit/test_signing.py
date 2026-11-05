"""`app/core/signing.py` (M6 phase 1): Ed25519 sign / verify over canonical manifests, key
files, reprs without key material, and the committed dev pair."""

import base64
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cyberlab_jobs.report import TLP, Manifest, Profile, manifest_bytes

from app.core.config import DEV_REPORT_SIGNING_PUBLIC_KEYS
from app.core.signing import (
    SigningError,
    load_public_keys,
    load_signing_keys,
    public_key_b64,
    sign,
    verify,
)

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
