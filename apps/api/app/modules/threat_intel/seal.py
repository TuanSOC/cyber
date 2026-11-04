"""Seal provider API keys for the enrich worker (frozen format, M4 phase 1).

The API holds only the public keys (`TI_SEAL_PUBLIC_KEYS`), so it can seal but never open;
opening lives in `unseal.py`, which only the enrich worker may import (RT21).

Format (one sealed box per key):
  ephemeral X25519 key pair -> shared secret with the recipient (kid) public key
  -> HKDF-SHA256(salt = epk || recipient_pk, info = "cyberlab.ti.v1") -> 32-byte key
  -> AES-256-GCM with a random 96-bit nonce (the derived key is unique per seal)
  AAD = "cyberlab.ti.v1|{org_id}|{provider}|{kid}|{key_version}|{base_url_norm}"
`base_url_norm` is empty except for MISP, so a MISP key only opens for the URL it was saved
with (RT1). Stored columns: key_kid, key_version, key_epk, key_nonce, key_ct, key_last4.
"""

import base64
import binascii
import os
import re
import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import SecretStr

from app.modules.threat_intel.providers.base import ProviderName

SCHEME = "cyberlab.ti.v1"
KEY_BYTES = 32
NONCE_BYTES = 12
MIN_KEY_CHARS = 8
MAX_KEY_CHARS = 256
KID_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,64}")


class SealError(ValueError):
    """Refused input. The message is a fixed code, never the key."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class SealedKey:
    kid: str
    key_version: int
    epk: bytes
    nonce: bytes
    ct: bytes
    last4: str

    def __repr__(self) -> str:
        return f"SealedKey(kid={self.kid!r}, key_version={self.key_version}, last4=***)"


def aad(org_id: uuid.UUID, provider: str, kid: str, key_version: int, base_url_norm: str) -> bytes:
    return f"{SCHEME}|{org_id}|{provider}|{kid}|{key_version}|{base_url_norm}".encode()


def derive_key(shared: bytes, epk: bytes, recipient_pk: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=KEY_BYTES, salt=epk + recipient_pk, info=SCHEME.encode()
    ).derive(shared)


def raw_public(key: X25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def load_public_key(encoded: str) -> X25519PublicKey:
    """A base64 raw 32-byte X25519 public key (the `TI_SEAL_PUBLIC_KEYS` values)."""
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SealError("bad_public_key") from exc
    if len(raw) != KEY_BYTES:
        raise SealError("bad_public_key")
    return X25519PublicKey.from_public_bytes(raw)


def check_context(provider: str, kid: str, key_version: int, base_url_norm: str) -> None:
    if provider not in {p.value for p in ProviderName}:
        raise SealError("unknown_provider")
    if not KID_PATTERN.fullmatch(kid):
        raise SealError("bad_kid")
    if key_version < 1:
        raise SealError("bad_key_version")
    if (provider == ProviderName.MISP) != bool(base_url_norm):
        raise SealError("base_url_mismatch")


def _plaintext(value: SecretStr | str) -> str:
    text = value.get_secret_value() if isinstance(value, SecretStr) else value
    if not MIN_KEY_CHARS <= len(text) <= MAX_KEY_CHARS or not all(
        0x20 <= ord(c) <= 0x7E for c in text
    ):
        raise SealError("bad_api_key")
    return text


def last4(value: SecretStr | str) -> str:
    return _plaintext(value)[-4:]


def seal(
    plaintext: SecretStr | str,
    org_id: uuid.UUID,
    provider: str,
    kid: str,
    key_version: int,
    base_url_norm: str,
    public_key: X25519PublicKey,
) -> SealedKey:
    check_context(provider, kid, key_version, base_url_norm)
    text = _plaintext(plaintext)
    ephemeral = X25519PrivateKey.generate()
    epk = raw_public(ephemeral.public_key())
    key = derive_key(ephemeral.exchange(public_key), epk, raw_public(public_key))
    nonce = os.urandom(NONCE_BYTES)
    ct = AESGCM(key).encrypt(
        nonce, text.encode(), aad(org_id, provider, kid, key_version, base_url_norm)
    )
    return SealedKey(kid=kid, key_version=key_version, epk=epk, nonce=nonce, ct=ct, last4=text[-4:])
