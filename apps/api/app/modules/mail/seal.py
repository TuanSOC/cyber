"""Seal mail link tokens for the mail worker (M11 phase 1, FROZEN).

Domain `cyberlab.mail.v1`, provider `link`, the AAD uuid is the outbox row id (a token sealed
for one row never opens for another). The API only seals (`MAIL_SEAL_PUBLIC_KEYS` /
`MAIL_SEAL_ACTIVE_KID`); the mail worker opens through `mail/unseal.py`, which only
`mail/worker.py` and `app/workers/mail_*.py` may import
(`tests/unit/test_identity_import_guard.py`).
"""

import uuid

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from pydantic import SecretStr

from app.core import sealbox
from app.core.config import get_settings
from app.core.sealbox import SealDomain, SealedKey, SealError, load_public_key

__all__ = ["MAIL_DOMAIN", "MAIL_SCHEME", "PROVIDER_LINK", "SealError", "seal_link_token"]

MAIL_SCHEME = "cyberlab.mail.v1"
PROVIDER_LINK = "link"
MAIL_DOMAIN = SealDomain(MAIL_SCHEME, frozenset({PROVIDER_LINK}), url_bound=lambda _p: False)


def active_key() -> tuple[str, X25519PublicKey]:
    settings = get_settings()
    kid = settings.mail_seal_active_kid
    if not kid or kid not in settings.mail_seal_public_keys:
        raise SealError("mail_seal_unconfigured")
    return kid, load_public_key(settings.mail_seal_public_keys[kid])


def seal_link_token(token: SecretStr | str, outbox_id: uuid.UUID) -> SealedKey:
    kid, public_key = active_key()
    return sealbox.seal_in(MAIL_DOMAIN, token, outbox_id, PROVIDER_LINK, kid, 1, "", public_key)
