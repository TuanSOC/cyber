"""Open sealed AI provider keys: the analyst worker only (M5 phase 1, FROZEN).

`tests/unit/test_ai_import_guard.py` refuses any import of this module outside
`app/workers/analyst*.py`. `Settings` refuses `AI_SEAL_PRIVATE_KEYS_FILE` unless
`PROCESS_ROLE=analyst`, and refuses the TI private key file for the analyst.
"""

import uuid
from collections.abc import Mapping

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pydantic import SecretStr

from app.core.sealbox import SealedKey
from app.core.sealbox_open import UnsealError, load_private_keys, open_in
from app.modules.ai.seal import AI_DOMAIN

__all__ = ["UnsealError", "load_private_keys", "open_sealed"]


def open_sealed(
    sealed: SealedKey,
    org_id: uuid.UUID,
    provider: str,
    private_keys: Mapping[str, X25519PrivateKey],
) -> SecretStr:
    """Open a key sealed for exactly this org, provider, kid and version."""
    return open_in(AI_DOMAIN, sealed, org_id, provider, "", private_keys)
