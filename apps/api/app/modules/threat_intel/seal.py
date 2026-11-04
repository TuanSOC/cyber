"""Seal provider API keys for the enrich worker (frozen format, M4 phase 1).

The API holds only the public keys (`TI_SEAL_PUBLIC_KEYS`), so it can seal but never open;
opening lives in `unseal.py`, which only the enrich worker may import (RT21).

Format (one sealed box per key; generic code in `app/core/sealbox.py` since M5):
  ephemeral X25519 key pair -> shared secret with the recipient (kid) public key
  -> HKDF-SHA256(salt = epk || recipient_pk, info = "cyberlab.ti.v1") -> 32-byte key
  -> AES-256-GCM with a random 96-bit nonce (the derived key is unique per seal)
  AAD = "cyberlab.ti.v1|{org_id}|{provider}|{kid}|{key_version}|{base_url_norm}"
`base_url_norm` is empty except for MISP, so a MISP key only opens for the URL it was saved
with (RT1). Stored columns: key_kid, key_version, key_epk, key_nonce, key_ct, key_last4.

Every public name and signature of M4 is kept; the bytes are unchanged (the committed
`tests/fixtures/seal/ti_prerefactor.json` still opens).
"""

import uuid

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from pydantic import SecretStr

from app.core import sealbox
from app.core.sealbox import (
    KEY_BYTES,
    KID_PATTERN,
    MAX_KEY_CHARS,
    MIN_KEY_CHARS,
    NONCE_BYTES,
    SealDomain,
    SealedKey,
    SealError,
    last4,
    load_public_key,
    raw_public,
)
from app.modules.threat_intel.providers.base import ProviderName

__all__ = [
    "KEY_BYTES",
    "KID_PATTERN",
    "MAX_KEY_CHARS",
    "MIN_KEY_CHARS",
    "NONCE_BYTES",
    "SCHEME",
    "TI_DOMAIN",
    "SealError",
    "SealedKey",
    "aad",
    "check_context",
    "derive_key",
    "last4",
    "load_public_key",
    "raw_public",
    "seal",
]

SCHEME = "cyberlab.ti.v1"
TI_DOMAIN = SealDomain(
    SCHEME,
    frozenset(p.value for p in ProviderName),
    url_bound=lambda provider: provider == ProviderName.MISP,
)


def aad(org_id: uuid.UUID, provider: str, kid: str, key_version: int, base_url_norm: str) -> bytes:
    return sealbox.aad(TI_DOMAIN, org_id, provider, kid, key_version, base_url_norm)


def derive_key(shared: bytes, epk: bytes, recipient_pk: bytes) -> bytes:
    return sealbox.derive_key(TI_DOMAIN, shared, epk, recipient_pk)


def check_context(provider: str, kid: str, key_version: int, base_url_norm: str) -> None:
    sealbox.check_context(TI_DOMAIN, provider, kid, key_version, base_url_norm)


def seal(
    plaintext: SecretStr | str,
    org_id: uuid.UUID,
    provider: str,
    kid: str,
    key_version: int,
    base_url_norm: str,
    public_key: X25519PublicKey,
) -> SealedKey:
    return sealbox.seal_in(
        TI_DOMAIN, plaintext, org_id, provider, kid, key_version, base_url_norm, public_key
    )
