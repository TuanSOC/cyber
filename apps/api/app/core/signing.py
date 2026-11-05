"""Ed25519 report signing (M6, FROZEN).

The API signs the canonical `Manifest` of each finalized report version
(`cyberlab_jobs.report.manifest_bytes`) with the active kid; the detached signature is
stored in `report_versions` and embedded in the PDF. Anyone can verify it with the public
keys (`GET /api/v1/report-signing-keys`, `scripts/verify_report.py`).

- `load_signing_keys(path)` reads the private keys `{kid: base64 raw 32-byte key}` from the
  api's compose secret (REPORT_SIGNING_KEYS_FILE, refused for every other process role). Only
  `app/modules/reports/signing.py` may import it (`tests/unit/test_report_import_guard.py`).
- `load_public_keys`, `sign` and `verify` are free to use.

Errors carry fixed codes, never key material; the key objects never appear in a repr.
"""

import base64
import binascii
import json
from collections.abc import Mapping
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.core.sealbox import KID_PATTERN

KEY_BYTES = 32
SIGNATURE_BYTES = 64
ALGORITHM = "Ed25519"


class SigningError(Exception):
    """A fixed code (`signing_keys_unreadable`, `signing_keys_invalid`, `unknown_kid`,
    `public_keys_invalid`), never key material."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _decode_key(encoded: object, code: str) -> bytes:
    try:
        raw = base64.b64decode(str(encoded), validate=True)
    except (binascii.Error, ValueError):
        raise SigningError(code) from None
    if len(raw) != KEY_BYTES:
        raise SigningError(code)
    return raw


def load_signing_keys(path: str | Path) -> dict[str, Ed25519PrivateKey]:
    """`{kid: Ed25519PrivateKey}` from the api's secret file (import-guarded)."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise SigningError("signing_keys_unreadable") from None
    if not isinstance(data, dict) or not data:
        raise SigningError("signing_keys_invalid")
    keys: dict[str, Ed25519PrivateKey] = {}
    for kid, encoded in data.items():
        if not isinstance(kid, str) or not KID_PATTERN.fullmatch(kid):
            raise SigningError("signing_keys_invalid")
        keys[kid] = Ed25519PrivateKey.from_private_bytes(
            _decode_key(encoded, "signing_keys_invalid")
        )
    return keys


def load_public_keys(data: Mapping[str, str] | str) -> dict[str, Ed25519PublicKey]:
    """`{kid: Ed25519PublicKey}` from REPORT_SIGNING_PUBLIC_KEYS (a mapping or its JSON)."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            raise SigningError("public_keys_invalid") from None
    if not isinstance(data, Mapping):
        raise SigningError("public_keys_invalid")
    keys: dict[str, Ed25519PublicKey] = {}
    for kid, encoded in data.items():
        if not isinstance(kid, str) or not KID_PATTERN.fullmatch(kid):
            raise SigningError("public_keys_invalid")
        raw = _decode_key(encoded, "public_keys_invalid")
        try:
            keys[kid] = Ed25519PublicKey.from_public_bytes(raw)
        except ValueError:
            raise SigningError("public_keys_invalid") from None
    return keys


def public_key_b64(key: Ed25519PublicKey | Ed25519PrivateKey) -> str:
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return base64.b64encode(public.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def sign(manifest_bytes: bytes, kid: str, keys: Mapping[str, Ed25519PrivateKey]) -> str:
    """The base64 detached Ed25519 signature of the canonical manifest bytes."""
    private = keys.get(kid)
    if private is None:
        raise SigningError("unknown_kid")
    return base64.b64encode(private.sign(manifest_bytes)).decode()


def verify(
    manifest_bytes: bytes,
    signature_b64: str,
    kid: str,
    public_keys: Mapping[str, Ed25519PublicKey],
) -> bool:
    """True only for a valid signature by `kid` over exactly these bytes."""
    public = public_keys.get(kid)
    if public is None:
        return False
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        return False
    if len(signature) != SIGNATURE_BYTES:
        return False
    try:
        public.verify(signature, manifest_bytes)
    except InvalidSignature:
        return False
    return True
