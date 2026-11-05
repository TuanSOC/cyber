"""The API side of report signing (M6; phase 1 wrapper, owned by phase 3 afterwards).

The only module allowed to import `app.core.signing.load_signing_keys`
(`tests/unit/test_report_import_guard.py`): it loads the api's private keys once from
REPORT_SIGNING_KEYS_FILE and signs canonical manifests with the active kid. Verification
uses the public keys from the settings. `check_startup_keys()` runs when the prod api starts:
the active private key must match its published public key and no key may be the committed
dev pair.
"""

from collections.abc import Mapping
from functools import lru_cache
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cyberlab_jobs.report import Manifest, manifest_bytes
from pydantic import ValidationError

from app.core import signing as core
from app.core.config import DEV_REPORT_SIGNING_PUBLIC_KEYS, get_settings
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
    try:
        keys = public_keys()
    except SigningError:
        return False
    return core.verify(manifest_bytes, signature_b64, kid, keys)


def verify_stored(manifest: Mapping[str, Any], signature_b64: str, kid: str) -> bool:
    """A stored manifest (`report_versions.manifest`) and its detached signature: the
    manifest must validate, name the same kid, and its canonical bytes must verify with the
    public key of that kid. Never raises."""
    try:
        parsed = Manifest.model_validate(dict(manifest))
    except ValidationError:
        return False
    if parsed.kid != kid:
        return False
    return verify_manifest(manifest_bytes(parsed), signature_b64, kid)


def check_startup_keys() -> None:
    """Prod api startup (M6 review L3): load the private keys now (a missing or unreadable
    file fails the start, not the first finalize), require the active kid's public half to
    equal its published key (REPORT_SIGNING_PUBLIC_KEYS), and refuse the committed dev
    pair: a private key whose public half is a dev public key is the dev private key.
    Raises `SigningError` with a fixed code; other envs and roles are not checked."""
    settings = get_settings()
    if settings.env != "prod" or settings.process_role != "api":
        return
    keys = _private_keys()
    kid = active_kid()
    private = keys.get(kid)
    if private is None:
        raise SigningError("active_kid_not_in_key_file")
    published = public_keys().get(kid)
    if published is None or core.public_key_b64(published) != core.public_key_b64(private):
        raise SigningError("active_key_mismatch")
    if any(core.public_key_b64(key) in DEV_REPORT_SIGNING_PUBLIC_KEYS for key in keys.values()):
        raise SigningError("dev_signing_key")


def reset_cache() -> None:
    """Tests: forget the loaded keys (after changing the settings)."""
    _private_keys.cache_clear()
