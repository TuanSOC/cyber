"""Open sealed provider keys: the enrich worker only (RT21).

`tests/unit/test_ti_import_guard.py` refuses any import of this module outside
`app/workers/enrich*.py` (and tests). The API process cannot even load a private key file:
`Settings` refuses `TI_SEAL_PRIVATE_KEYS_FILE` unless `PROCESS_ROLE=enrich`.

Since M5 a thin wrapper over the generic `app/core/sealbox_open.py` with the TI domain; the
names and signatures are unchanged.
"""

import uuid
from collections.abc import Mapping

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pydantic import SecretStr

from app.core.sealbox import SealedKey
from app.core.sealbox_open import UnsealError, load_private_keys, open_in
from app.modules.threat_intel.seal import TI_DOMAIN

__all__ = ["UnsealError", "load_private_keys", "open_sealed"]


def open_sealed(
    sealed: SealedKey,
    org_id: uuid.UUID,
    provider: str,
    base_url_norm: str,
    private_keys: Mapping[str, X25519PrivateKey],
) -> SecretStr:
    """Open a key sealed for exactly this org, provider, kid, version and (MISP) URL."""
    return open_in(TI_DOMAIN, sealed, org_id, provider, base_url_norm, private_keys)
