"""Seal identity secrets (M11 phase 1, FROZEN): TOTP secrets and IdP client secrets.

The `core/sealbox` format in its own domain `cyberlab.identity.v1` (decision 1), with its own
key pair (`IDENTITY_SEAL_PUBLIC_KEYS` / `IDENTITY_SEAL_ACTIVE_KID`; the private half only in the
api's `IDENTITY_SEAL_PRIVATE_KEYS_FILE`). Providers:
- `totp`: the base32 TOTP secret; the AAD uuid is the USER id; not URL-bound;
- `oidc`: the IdP client secret; the AAD uuid is the ORG id; URL-bound to the normalized
  issuer, so a secret never opens for another issuer.
Opened only by `identity/unseal.py` (`open_identity_secret`).
"""

import uuid

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from pydantic import SecretStr

from app.core import sealbox
from app.core.config import get_settings
from app.core.sealbox import SealDomain, SealedKey, SealError, load_public_key

__all__ = [
    "IDENTITY_DOMAIN",
    "IDENTITY_SCHEME",
    "PROVIDER_OIDC",
    "PROVIDER_TOTP",
    "SealError",
    "SealedKey",
    "active_key",
    "seal_client_secret",
    "seal_totp_secret",
    "sealed_from_columns",
]

IDENTITY_SCHEME = "cyberlab.identity.v1"
PROVIDER_TOTP = "totp"
PROVIDER_OIDC = "oidc"
IDENTITY_DOMAIN = SealDomain(
    IDENTITY_SCHEME,
    frozenset({PROVIDER_TOTP, PROVIDER_OIDC}),
    url_bound=lambda provider: provider == PROVIDER_OIDC,
)


def active_key() -> tuple[str, X25519PublicKey]:
    """The active kid and its public key; `SealError("identity_seal_unconfigured")` if unset."""
    settings = get_settings()
    kid = settings.identity_seal_active_kid
    if not kid or kid not in settings.identity_seal_public_keys:
        raise SealError("identity_seal_unconfigured")
    return kid, load_public_key(settings.identity_seal_public_keys[kid])


def seal_totp_secret(
    secret: SecretStr | str, user_id: uuid.UUID, *, key_version: int = 1
) -> SealedKey:
    kid, public_key = active_key()
    return sealbox.seal_in(
        IDENTITY_DOMAIN, secret, user_id, PROVIDER_TOTP, kid, key_version, "", public_key
    )


def seal_client_secret(
    secret: SecretStr | str, org_id: uuid.UUID, issuer_norm: str, *, key_version: int = 1
) -> SealedKey:
    kid, public_key = active_key()
    return sealbox.seal_in(
        IDENTITY_DOMAIN, secret, org_id, PROVIDER_OIDC, kid, key_version, issuer_norm, public_key
    )


def sealed_from_columns(
    kid: str, key_version: int, epk: bytes, nonce: bytes, ct: bytes
) -> SealedKey:
    """A `SealedKey` read back from the sealed columns (`last4` is not stored there)."""
    return SealedKey(kid=kid, key_version=key_version, epk=epk, nonce=nonce, ct=ct, last4="")
