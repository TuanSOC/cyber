"""Open mail link tokens: the mail worker only (M11 phase 1, FROZEN).

The fourth unseal wrapper allowed to import `core/sealbox_open.py`. Only `mail/worker.py` and
`app/workers/mail_*.py` (phase 2) may import it (`tests/unit/test_identity_import_guard.py`);
`Settings` refuses `MAIL_SEAL_PRIVATE_KEYS_FILE` unless `PROCESS_ROLE=mail`, and the mail role
refuses every other private key.
"""

import uuid
from collections.abc import Mapping

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pydantic import SecretStr

from app.core.sealbox import SealedKey
from app.core.sealbox_open import UnsealError, load_private_keys, open_in
from app.modules.mail.seal import MAIL_DOMAIN, PROVIDER_LINK

__all__ = ["UnsealError", "load_private_keys", "open_link_token"]


def open_link_token(
    sealed: SealedKey, outbox_id: uuid.UUID, private_keys: Mapping[str, X25519PrivateKey]
) -> SecretStr:
    return open_in(MAIL_DOMAIN, sealed, outbox_id, PROVIDER_LINK, "", private_keys)
