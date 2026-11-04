"""Generic sealed-box format for write-only provider keys (M4 format, generalized in M5).

One sealed box per key, parametrized by a `SealDomain`:
  ephemeral X25519 key pair -> shared secret with the recipient (kid) public key
  -> HKDF-SHA256(salt = epk || recipient_pk, info = domain.scheme) -> 32-byte key
  -> AES-256-GCM with a random 96-bit nonce (the derived key is unique per seal)
  AAD = "{scheme}|{org_id}|{provider}|{kid}|{key_version}|{base_url_norm}"

The scheme sits in both the HKDF info and the AAD, so a ciphertext of one domain never opens
in another, even under the same key pair. `base_url_norm` is non-empty exactly for the
providers the domain marks as URL-bound (TI: MISP; AI: none).

This module only seals (public keys). Opening lives in `sealbox_open.py`, which only the two
per-domain unseal wrappers may import (`tests/unit/test_ai_import_guard.py`).

Domains: `threat_intel.seal.TI_DOMAIN` (`cyberlab.ti.v1`) and `ai.seal.AI_DOMAIN`
(`cyberlab.ai.v1`). The TI bytes are unchanged from M4 (committed pre-refactor fixture).
"""

import base64
import binascii
import os
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import SecretStr

KEY_BYTES = 32
NONCE_BYTES = 12
MIN_KEY_CHARS = 8
MAX_KEY_CHARS = 256
KID_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,64}")


@dataclass(frozen=True)
class SealDomain:
    """One key domain: its scheme string (HKDF info + AAD prefix), the provider names it
    accepts and which of them are bound to a base URL."""

    scheme: str
    providers: frozenset[str]
    url_bound: Callable[[str], bool]


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


def aad(
    domain: SealDomain,
    org_id: uuid.UUID,
    provider: str,
    kid: str,
    key_version: int,
    base_url_norm: str,
) -> bytes:
    return f"{domain.scheme}|{org_id}|{provider}|{kid}|{key_version}|{base_url_norm}".encode()


def derive_key(domain: SealDomain, shared: bytes, epk: bytes, recipient_pk: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=epk + recipient_pk,
        info=domain.scheme.encode(),
    ).derive(shared)


def raw_public(key: X25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def load_public_key(encoded: str) -> X25519PublicKey:
    """A base64 raw 32-byte X25519 public key (the `*_SEAL_PUBLIC_KEYS` values)."""
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SealError("bad_public_key") from exc
    if len(raw) != KEY_BYTES:
        raise SealError("bad_public_key")
    return X25519PublicKey.from_public_bytes(raw)


def check_context(
    domain: SealDomain, provider: str, kid: str, key_version: int, base_url_norm: str
) -> None:
    if provider not in domain.providers:
        raise SealError("unknown_provider")
    if not KID_PATTERN.fullmatch(kid):
        raise SealError("bad_kid")
    if key_version < 1:
        raise SealError("bad_key_version")
    if domain.url_bound(provider) != bool(base_url_norm):
        raise SealError("base_url_mismatch")


def key_text(value: SecretStr | str) -> str:
    """8-256 printable ASCII characters without surrounding whitespace (a header value that
    httpx/h11 accept verbatim: a refused one would end up in their exception messages).
    The error is the fixed code `bad_api_key`, never the key."""
    text = value.get_secret_value() if isinstance(value, SecretStr) else value
    if (
        not isinstance(text, str)
        or not MIN_KEY_CHARS <= len(text) <= MAX_KEY_CHARS
        or not all(0x20 <= ord(c) <= 0x7E for c in text)
        or text != text.strip()
    ):
        raise SealError("bad_api_key")
    return text


def last4(value: SecretStr | str) -> str:
    return key_text(value)[-4:]


def seal_in(
    domain: SealDomain,
    plaintext: SecretStr | str,
    org_id: uuid.UUID,
    provider: str,
    kid: str,
    key_version: int,
    base_url_norm: str,
    public_key: X25519PublicKey,
) -> SealedKey:
    check_context(domain, provider, kid, key_version, base_url_norm)
    text = key_text(plaintext)
    ephemeral = X25519PrivateKey.generate()
    epk = raw_public(ephemeral.public_key())
    key = derive_key(domain, ephemeral.exchange(public_key), epk, raw_public(public_key))
    nonce = os.urandom(NONCE_BYTES)
    ct = AESGCM(key).encrypt(
        nonce, text.encode(), aad(domain, org_id, provider, kid, key_version, base_url_norm)
    )
    return SealedKey(kid=kid, key_version=key_version, epk=epk, nonce=nonce, ct=ct, last4=text[-4:])
