import re
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import HTTPConnection

from app.core.client_ip import client_ip, user_agent
from app.modules.audit.models import AuditLog

# Matched against the normalized key (camelCase -> snake_case, `-`/spaces -> `_`, lowercase),
# so `privateKey`, `X-Mock-Key`, `mock-key` and `X-OTX-API-KEY` are caught like `api_key`.
_SENSITIVE_KEY = re.compile(
    r"password|passphrase|token|secret|credentials?|cookie|api_?key|authorization|auth_?key"
    r"|x_apikey|(^|_)keys?$"
)
# Key metadata that is safe (and useful) to audit: never key material.
_ALLOWED_KEYS = frozenset({"key_last4", "key_kid", "key_version", "ioc_key"})
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SEPARATORS = re.compile(r"[\s\-.]+")


def normalize_key(key: str) -> str:
    return _SEPARATORS.sub("_", _CAMEL.sub("_", key.strip())).lower()


def _is_sensitive(key: str) -> bool:
    name = normalize_key(key)
    return name not in _ALLOWED_KEYS and _SENSITIVE_KEY.search(name) is not None


def _clean(value: Any) -> Any:
    if isinstance(value, dict):
        return sanitize(value)
    if isinstance(value, list | tuple):
        return [_clean(item) for item in value]
    return value


def sanitize(details: dict[str, Any] | None) -> dict[str, Any]:
    """Drop secret-looking keys at any depth (nested dicts and lists of dicts)."""
    if not details:
        return {}
    return {key: _clean(value) for key, value in details.items() if not _is_sensitive(str(key))}


def record(
    session: AsyncSession,
    *,
    action: str,
    org_id: uuid.UUID,
    actor_id: uuid.UUID | None,
    target_type: str | None = None,
    target_id: uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
    request: HTTPConnection | None = None,
) -> AuditLog:
    """Add an audit row to the caller's transaction (atomic with the audited action)."""
    log = AuditLog(
        organization_id=org_id,
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=sanitize(details),
        ip=client_ip(request) if request else None,
        user_agent=user_agent(request) if request else None,
    )
    session.add(log)
    return log
