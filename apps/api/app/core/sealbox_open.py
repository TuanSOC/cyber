"""Open sealed boxes (generic; see `sealbox.py` for the format).

Only the per-domain unseal wrappers may import this module: `threat_intel/unseal.py` (the
enrich worker) and `ai/unseal.py` (the analyst worker). `tests/unit/test_ai_import_guard.py`
enforces it, and each worker's settings refuse the other domain's private key file.
"""

import base64
import binascii
import json
import uuid
from collections.abc import Mapping
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import SecretStr

from app.core.sealbox import (
    KEY_BYTES,
    KID_PATTERN,
    NONCE_BYTES,
    SealDomain,
    SealedKey,
    SealError,
    aad,
    check_context,
    derive_key,
    raw_public,
)


class UnsealError(Exception):
    """Opening failed. The message is a fixed code, never key material."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def load_private_keys(path: str | Path) -> dict[str, X25519PrivateKey]:
    """`{kid: base64 raw 32-byte X25519 private key}` from the worker's secret file."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise UnsealError("private_keys_unreadable") from exc
    if not isinstance(data, dict) or not data:
        raise UnsealError("private_keys_invalid")
    keys: dict[str, X25519PrivateKey] = {}
    for kid, encoded in data.items():
        if not isinstance(kid, str) or not KID_PATTERN.fullmatch(kid):
            raise UnsealError("private_keys_invalid")
        try:
            raw = base64.b64decode(str(encoded), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise UnsealError("private_keys_invalid") from exc
        if len(raw) != KEY_BYTES:
            raise UnsealError("private_keys_invalid")
        keys[kid] = X25519PrivateKey.from_private_bytes(raw)
    return keys


def open_in(
    domain: SealDomain,
    sealed: SealedKey,
    org_id: uuid.UUID,
    provider: str,
    base_url_norm: str,
    private_keys: Mapping[str, X25519PrivateKey],
) -> SecretStr:
    """Open a key sealed in `domain` for exactly this org, provider, kid, version and URL."""
    try:
        check_context(domain, provider, sealed.kid, sealed.key_version, base_url_norm)
    except SealError as exc:
        raise UnsealError(exc.code) from None
    private = private_keys.get(sealed.kid)
    if private is None:
        raise UnsealError("unknown_kid")
    if len(sealed.epk) != KEY_BYTES or len(sealed.nonce) != NONCE_BYTES:
        raise UnsealError("unseal_failed")
    try:
        epk = X25519PublicKey.from_public_bytes(sealed.epk)
        key = derive_key(
            domain, private.exchange(epk), sealed.epk, raw_public(private.public_key())
        )
        plaintext = AESGCM(key).decrypt(
            sealed.nonce,
            sealed.ct,
            aad(domain, org_id, provider, sealed.kid, sealed.key_version, base_url_norm),
        )
    except (InvalidTag, ValueError):
        raise UnsealError("unseal_failed") from None
    return SecretStr(plaintext.decode("ascii", errors="replace"))
