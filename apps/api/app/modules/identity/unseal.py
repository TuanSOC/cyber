"""Open identity secrets: the api process only (M11 phase 1, FROZEN).

The third allowed importer of `core/sealbox_open.py` (`tests/unit/test_ai_import_guard.py`).
Only `identity/{mfa,discovery,idp_config}.py` and `identity/sso/*.py` may import this module
(`tests/unit/test_identity_import_guard.py`). `Settings` refuses
`IDENTITY_SEAL_PRIVATE_KEYS_FILE` unless `PROCESS_ROLE=api`, and the mail worker (whose role
refuses it) never imports it.
"""

import uuid
from functools import lru_cache

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pydantic import SecretStr

from app.core.config import get_settings
from app.core.sealbox import SealedKey
from app.core.sealbox_open import UnsealError, load_private_keys, open_in
from app.modules.identity.seal import IDENTITY_DOMAIN

__all__ = ["UnsealError", "open_identity_secret"]


@lru_cache(maxsize=1)
def _private_keys(path: str) -> dict[str, X25519PrivateKey]:
    return load_private_keys(path)


def open_identity_secret(
    sealed: SealedKey, owner_id: uuid.UUID, provider: str, base_url_norm: str = ""
) -> SecretStr:
    """Open a `totp` (owner = user id) or `oidc` (owner = org id, URL = the issuer) secret.
    Fixed `UnsealError` codes only, never key material."""
    path = get_settings().identity_seal_private_keys_file
    if path is None:
        raise UnsealError("private_keys_unconfigured")
    return open_in(IDENTITY_DOMAIN, sealed, owner_id, provider, base_url_norm, _private_keys(path))
