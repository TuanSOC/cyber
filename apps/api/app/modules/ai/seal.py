"""Seal AI provider keys (M5 phase 1, FROZEN): the API (and the analyst's lazy re-seal, RT18).

Same sealed-box format as threat intel (`app/core/sealbox.py`) in its own domain
`cyberlab.ai.v1`, with its own key pair (`AI_SEAL_PUBLIC_KEYS` / `AI_SEAL_ACTIVE_KID`; the
private half only in the analyst's `AI_SEAL_PRIVATE_KEYS_FILE`). No AI provider is bound to a
URL, so `base_url_norm` is always "". A TI ciphertext never opens here, and vice versa.
"""

import uuid

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from pydantic import SecretStr

from app.core import sealbox
from app.core.sealbox import SealDomain, SealedKey, SealError, last4, load_public_key
from app.modules.ai.contracts import AiProviderName

__all__ = ["AI_DOMAIN", "AI_SCHEME", "SealError", "SealedKey", "last4", "load_public_key", "seal"]

AI_SCHEME = "cyberlab.ai.v1"
AI_DOMAIN = SealDomain(
    AI_SCHEME, frozenset(p.value for p in AiProviderName), url_bound=lambda _provider: False
)


def seal(
    plaintext: SecretStr | str,
    org_id: uuid.UUID,
    provider: str,
    kid: str,
    key_version: int,
    public_key: X25519PublicKey,
) -> SealedKey:
    return sealbox.seal_in(AI_DOMAIN, plaintext, org_id, provider, kid, key_version, "", public_key)
