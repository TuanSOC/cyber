"""The API side of report signing (M6; phase 1 wrapper, owned by phase 3 afterwards).

The only module allowed to import `app.core.signing.load_signing_keys`
(`tests/unit/test_report_import_guard.py`): it loads the api's private keys once from
REPORT_SIGNING_KEYS_FILE and signs canonical manifests with the active kid. Verification
uses the public keys from the settings.
"""

from functools import lru_cache

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.core import signing as core
from app.core.config import get_settings
from app.core.signing import SigningError, load_signing_keys


@lru_cache(maxsize=1)
def _private_keys() -> dict[str, Ed25519PrivateKey]:
    path = get_settings().report_signing_keys_file
    if path is None:
        raise SigningError("signing_keys_unavailable")
    return load_signing_keys(path)


def public_keys() -> dict[str, Ed25519PublicKey]:
    return core.load_public_keys(get_settings().report_signing_public_keys)


def active_kid() -> str:
    kid = get_settings().report_signing_active_kid
    if not kid:
        raise SigningError("no_active_kid")
    return kid


def sign_manifest(manifest_bytes: bytes) -> tuple[str, str]:
    """`(signature_b64, kid)` with the active kid."""
    kid = active_kid()
    return core.sign(manifest_bytes, kid, _private_keys()), kid


def verify_manifest(manifest_bytes: bytes, signature_b64: str, kid: str) -> bool:
    return core.verify(manifest_bytes, signature_b64, kid, public_keys())


def reset_cache() -> None:
    """Tests: forget the loaded keys (after changing the settings)."""
    _private_keys.cache_clear()
