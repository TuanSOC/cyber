"""Open sealed provider keys: the enrich worker only (RT21).

`tests/unit/test_ti_import_guard.py` refuses any import of this module outside
`app/workers/enrich*.py` (and tests). The API process cannot even load a private key file:
`Settings` refuses `TI_SEAL_PRIVATE_KEYS_FILE` unless `PROCESS_ROLE=enrich`.
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

from app.modules.threat_intel.seal import (
    KEY_BYTES,
    KID_PATTERN,
    NONCE_BYTES,
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


def open_sealed(
    sealed: SealedKey,
    org_id: uuid.UUID,
    provider: str,
    base_url_norm: str,
    private_keys: Mapping[str, X25519PrivateKey],
) -> SecretStr:
    """Open a key sealed for exactly this org, provider, kid, version and (MISP) URL."""
    try:
        check_context(provider, sealed.kid, sealed.key_version, base_url_norm)
    except SealError as exc:
        raise UnsealError(exc.code) from None
    private = private_keys.get(sealed.kid)
    if private is None:
        raise UnsealError("unknown_kid")
    if len(sealed.epk) != KEY_BYTES or len(sealed.nonce) != NONCE_BYTES:
        raise UnsealError("unseal_failed")
    try:
        epk = X25519PublicKey.from_public_bytes(sealed.epk)
        key = derive_key(private.exchange(epk), sealed.epk, raw_public(private.public_key()))
        plaintext = AESGCM(key).decrypt(
            sealed.nonce,
            sealed.ct,
            aad(org_id, provider, sealed.kid, sealed.key_version, base_url_norm),
        )
    except (InvalidTag, ValueError):
        raise UnsealError("unseal_failed") from None
    return SecretStr(plaintext.decode("ascii", errors="replace"))
