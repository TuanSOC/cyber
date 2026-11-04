"""Integrations (provider configs, sealed keys, terms) and per-org TI settings (M4 phase 5).

The API seals with the active kid's public key only (`seal.py`); it never opens a key, never
calls a provider and never resolves a name. MISP base URLs are checked syntactically here
(`ssrf.validate_base_url`) and resolved by the enrich worker, before every request, and
through the `ti.verify` task (RT5). A save queues `ti.verify` only when a new key (or a new
MISP URL) was stored, and only within the per-(org, provider) verify limit that POST
.../verify uses (`verify_allowed`). A MISP key is bound to its URL (seal AAD, RT1), so a new
URL needs a new key.

Writes lock the org row `FOR NO KEY UPDATE`, so concurrent PUTs of one org serialize (and
the first-configuration INSERT cannot race into the unique constraint).
"""

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import anyio
from cyberlab_jobs import TI_VERIFY, Queues
from redis.exceptions import RedisError
from sqlalchemy import select
from starlette.requests import HTTPConnection

from app.core import rate_limit
from app.core.config import Settings, get_settings
from app.core.errors import AppError, Conflict, TooManyRequests
from app.core.rbac import OrgContext
from app.core.threads import broker_limiter
from app.modules.audit import service as audit
from app.modules.organizations.models import Organization
from app.modules.threat_intel.availability import provider_available
from app.modules.threat_intel.catalog import CATALOG, ProviderLimits
from app.modules.threat_intel.messages import TiVerifyMessage
from app.modules.threat_intel.models import TiOrgSettings, TiProviderConfig
from app.modules.threat_intel.providers.base import IocType, ProviderName, VerifyStatus
from app.modules.threat_intel.schemas import (
    IntegrationOut,
    IntegrationPage,
    IntegrationUpdate,
    LimitsIn,
    LimitsOut,
    TiSettingsOut,
    TiSettingsUpdate,
)
from app.modules.threat_intel.seal import SealError, load_public_key, seal
from app.modules.threat_intel.ssrf import MispUrlInvalid, validate_base_url

log = logging.getLogger(__name__)

SEND_TIMEOUT_S = 15
VERIFY_PER_10MIN = 10


class ProviderUnavailable(AppError):
    status_code = 422
    code = "provider_unavailable"
    message = "This provider is not available in this deployment"


class TermsNotAcknowledged(AppError):
    status_code = 422
    code = "terms_not_acknowledged"
    message = "Enabling a provider for the first time requires acknowledge_terms: true"


class ApiKeyRequired(AppError):
    status_code = 422
    code = "api_key_required"
    message = "The first configuration of a provider requires an api_key"


class KeyRequiredForUrlChange(AppError):
    status_code = 422
    code = "key_required_for_url_change"
    message = "The stored key is bound to the current MISP URL: re-enter the key to change it"


class MispUrlRejected(AppError):
    status_code = 422
    code = "misp_url_invalid"
    message = "The MISP base URL is not acceptable"


class MispUrlRequired(AppError):
    status_code = 422
    code = "misp_url_required"
    message = "MISP needs a base_url"


class BaseUrlNotSupported(AppError):
    status_code = 422
    code = "base_url_not_supported"
    message = "Only MISP takes a base_url"


class LimitAboveCeiling(AppError):
    status_code = 422
    code = "limit_above_ceiling"
    message = "Limits may only be lowered, never raised above the provider's ceiling"


class InvalidApiKey(AppError):
    status_code = 422
    code = "invalid_api_key"
    message = "The api_key is not acceptable"


class IntegrationNotConfigured(Conflict):
    code = "integration_not_configured"
    message = "No key is stored for this provider"


class SealUnavailable(AppError):
    status_code = 503
    code = "seal_key_unavailable"
    message = "Provider keys cannot be stored right now"


class BrokerUnavailable(AppError):
    status_code = 503
    code = "broker_unavailable"
    message = "The verification could not be queued, try again later"


# --- read model ----------------------------------------------------------------------


def _limits(limits: ProviderLimits) -> LimitsOut:
    return LimitsOut(per_minute=limits.per_minute, per_day=limits.per_day)


def _org_limits(raw: dict[str, Any] | None) -> LimitsOut | None:
    if not raw:
        return None
    minute, day = raw.get("per_minute"), raw.get("per_day")
    return LimitsOut(
        per_minute=minute if isinstance(minute, int) else None,
        per_day=day if isinstance(day, int) else None,
    )


def to_out(
    provider: ProviderName, config: TiProviderConfig | None, settings: Settings
) -> IntegrationOut:
    entry = CATALOG[provider]
    configured = config is not None and config.key_ct is not None
    return IntegrationOut(
        name=provider,
        label=entry.label,
        supported_types=[t for t in IocType if t in entry.supported_types],
        tos_note=entry.tos_note,
        privacy_note=entry.privacy_note,
        needs_base_url=entry.needs_base_url,
        default_limits=_limits(entry.default_limits),
        ceilings=_limits(settings.ti_ceiling(provider)),
        available=provider_available(provider, settings),
        configured=configured,
        enabled=bool(config and config.enabled),
        key_last4=config.key_last4 if config is not None and configured else None,
        verify_status=VerifyStatus(config.verify_status) if config is not None else None,
        verified_at=config.verified_at if config is not None else None,
        last_error_code=config.last_error_code if config is not None else None,
        terms_ack_at=config.terms_ack_at if config is not None else None,
        base_url=config.base_url if config is not None else None,
        limits=_org_limits(config.limits) if config is not None else None,
    )


async def _configs(ctx: OrgContext) -> dict[str, TiProviderConfig]:
    rows = await ctx.session.scalars(
        select(TiProviderConfig).where(TiProviderConfig.organization_id == ctx.org_id)
    )
    return {row.provider: row for row in rows}


async def list_integrations(ctx: OrgContext) -> IntegrationPage:
    settings = get_settings()
    configs = await _configs(ctx)
    items = [to_out(name, configs.get(name.value), settings) for name in CATALOG]
    return IntegrationPage(items=items, total=len(items), ti_enabled=settings.ti_enabled)


# --- writes --------------------------------------------------------------------------


async def _lock_org(ctx: OrgContext) -> None:
    await ctx.session.execute(
        select(Organization.id).where(Organization.id == ctx.org_id).with_for_update(key_share=True)
    )


async def _config_for_update(ctx: OrgContext, provider: ProviderName) -> TiProviderConfig | None:
    return await ctx.session.scalar(
        select(TiProviderConfig)
        .where(
            TiProviderConfig.organization_id == ctx.org_id,
            TiProviderConfig.provider == provider.value,
        )
        .with_for_update()
    )


def _checked_limits(provider: ProviderName, limits: LimitsIn, settings: Settings) -> dict[str, int]:
    ceiling = settings.ti_ceiling(provider)
    if limits.per_minute is not None and limits.per_minute > ceiling.per_minute:
        raise LimitAboveCeiling()
    if (
        limits.per_day is not None
        and ceiling.per_day is not None
        and limits.per_day > ceiling.per_day
    ):
        raise LimitAboveCeiling()
    return {k: v for k, v in limits.model_dump().items() if v is not None}


def _base_url(provider: ProviderName, raw: str | None) -> str | None:
    if raw is None:
        return None
    if not CATALOG[provider].needs_base_url:
        raise BaseUrlNotSupported()
    try:
        return validate_base_url(raw).base_url_norm
    except MispUrlInvalid as exc:
        # A fixed reason code only: the URL may carry userinfo and is never echoed.
        raise MispUrlRejected(f"The MISP base URL is not acceptable ({exc.reason})") from None


def _public_key(settings: Settings) -> tuple[str, Any]:
    kid = settings.ti_seal_active_kid
    encoded = settings.ti_seal_public_keys.get(kid) if kid else None
    if not kid or not encoded:
        raise SealUnavailable()
    try:
        return kid, load_public_key(encoded)
    except SealError:
        raise SealUnavailable() from None


async def update_integration(
    ctx: OrgContext,
    provider: ProviderName,
    body: IntegrationUpdate,
    request: HTTPConnection,
) -> tuple[IntegrationOut, bool]:
    """Apply one PUT. Returns the read model and whether `ti.verify` should be queued
    (after the caller's commit)."""
    settings = get_settings()
    if not provider_available(provider, settings):
        raise ProviderUnavailable()
    entry = CATALOG[provider]
    new_limits = _checked_limits(provider, body.limits, settings) if body.limits else None
    new_url = _base_url(provider, body.base_url)

    await _lock_org(ctx)
    config = await _config_for_update(ctx, provider)
    had_key = config is not None and config.key_ct is not None
    current_url = config.base_url if config is not None else None
    url_changed = new_url is not None and new_url != current_url

    if body.api_key is None:
        if url_changed and had_key:
            raise KeyRequiredForUrlChange()
        if not had_key and (config is None or body.enabled or body.base_url is not None):
            raise ApiKeyRequired()
    if entry.needs_base_url and new_url is None and current_url is None:
        raise MispUrlRequired()

    now = datetime.now(UTC)
    if config is None:
        config = TiProviderConfig(
            organization_id=ctx.org_id,
            provider=provider.value,
            base_url=new_url,
            key_version=0,
            limits={},
        )
        ctx.session.add(config)
    changed: list[str] = []

    if body.acknowledge_terms and config.terms_ack_at is None:
        config.terms_ack_at = now
        config.terms_ack_by = ctx.user.id
        audit.record(
            ctx.session,
            action="integration.terms_acknowledged",
            org_id=ctx.org_id,
            actor_id=ctx.user.id,
            target_type="ti_provider",
            details={"provider": provider.value},
            request=request,
        )
    if body.enabled and config.terms_ack_at is None:
        raise TermsNotAcknowledged()

    if url_changed:
        config.base_url = new_url
        changed.append("base_url")

    key_audit: dict[str, Any] | None = None
    if body.api_key is not None:
        kid, public_key = _public_key(settings)
        version = (config.key_version or 0) + 1
        try:
            sealed = seal(
                body.api_key,
                ctx.org_id,
                provider.value,
                kid,
                version,
                (config.base_url or "") if entry.needs_base_url else "",
                public_key,
            )
        except SealError:
            raise InvalidApiKey() from None
        config.key_kid = sealed.kid
        config.key_version = sealed.key_version
        config.key_epk = sealed.epk
        config.key_nonce = sealed.nonce
        config.key_ct = sealed.ct
        config.key_last4 = sealed.last4
        config.verify_status = VerifyStatus.UNVERIFIED.value
        config.verified_at = None
        config.last_error_code = None
        key_audit = {
            "provider": provider.value,
            "key_last4": sealed.last4,
            "key_kid": sealed.kid,
            "key_version": sealed.key_version,
        }

    if body.enabled is not None and body.enabled != bool(config.enabled):
        config.enabled = body.enabled
        changed.append("enabled")
    if new_limits is not None and new_limits != (config.limits or {}):
        config.limits = new_limits
        changed.append("limits")
    await ctx.session.flush()

    if key_audit is not None:
        audit.record(
            ctx.session,
            action="integration.key_replaced" if had_key else "integration.key_set",
            org_id=ctx.org_id,
            actor_id=ctx.user.id,
            target_type="ti_provider",
            target_id=config.id,
            details=key_audit,
            request=request,
        )
    if changed:
        details: dict[str, Any] = {"provider": provider.value, "changed": changed}
        if "enabled" in changed:
            details["enabled"] = config.enabled
        if "limits" in changed:
            details["limits"] = config.limits
        if "base_url" in changed:
            details["base_url"] = config.base_url  # normalized: never userinfo
        audit.record(
            ctx.session,
            action="integration.updated",
            org_id=ctx.org_id,
            actor_id=ctx.user.id,
            target_type="ti_provider",
            target_id=config.id,
            details=details,
            request=request,
        )
    has_key = config.key_ct is not None
    # Only a new key (a new MISP URL always comes with one) is worth a check: an unchanged
    # save never queues one (no flood of the shared enrich queue). The worker resolves the
    # MISP host before every request anyway; the API never does.
    queue_verify = has_key and (key_audit is not None or "base_url" in changed)
    return to_out(provider, config, settings), queue_verify


async def remove_key(ctx: OrgContext, provider: ProviderName, request: HTTPConnection) -> None:
    """Clear the sealed columns and disable the provider. `key_version` stays, so the next
    key needs a higher one (RT18); the row itself is never deleted (0010)."""
    await _lock_org(ctx)
    config = await _config_for_update(ctx, provider)
    if config is None or config.key_ct is None:
        raise IntegrationNotConfigured()
    last4 = config.key_last4
    config.key_kid = None
    config.key_epk = None
    config.key_nonce = None
    config.key_ct = None
    config.key_last4 = None
    config.enabled = False
    config.verify_status = VerifyStatus.UNVERIFIED.value
    config.verified_at = None
    config.last_error_code = None
    await ctx.session.flush()
    audit.record(
        ctx.session,
        action="integration.key_removed",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="ti_provider",
        target_id=config.id,
        details={
            "provider": provider.value,
            "key_last4": last4,
            "key_version": config.key_version,
        },
        request=request,
    )


async def check_verifiable(ctx: OrgContext, provider: ProviderName) -> None:
    if not provider_available(provider, get_settings()):
        raise ProviderUnavailable()
    config = await ctx.session.scalar(
        select(TiProviderConfig.id).where(
            TiProviderConfig.organization_id == ctx.org_id,
            TiProviderConfig.provider == provider.value,
            TiProviderConfig.key_ct.is_not(None),
        )
    )
    if config is None:
        raise IntegrationNotConfigured()


def verify_rate_key(org_id: uuid.UUID, provider: ProviderName) -> str:
    return f"ti:verify:{org_id}:{provider.value}"


async def check_verify_rate(org_id: uuid.UUID, provider: ProviderName) -> None:
    """POST .../verify: count one check, 429 past `VERIFY_PER_10MIN` per 10 minutes."""
    await rate_limit.hit(verify_rate_key(org_id, provider), VERIFY_PER_10MIN, 600)


async def verify_allowed(org_id: uuid.UUID, provider: ProviderName) -> bool:
    """A save's check counts against the same limit, but a spent limit (or an unreachable
    rate-limit store) only skips the check: the save stands."""
    try:
        await check_verify_rate(org_id, provider)
    except TooManyRequests:
        return False
    except (RedisError, OSError, TimeoutError) as exc:
        log.warning("verify rate limit unavailable for %s (%s)", provider.value, type(exc).__name__)
        return False
    return True


def _send_verify_sync(message: TiVerifyMessage) -> None:
    from app.workers.celery_app import celery_app  # broker client only, no worker

    celery_app.send_task(
        TI_VERIFY,
        kwargs={"message": message.model_dump(mode="json")},
        queue=Queues(get_settings().queue_prefix).enrich,
        retry=True,
        retry_policy={"max_retries": 1, "interval_start": 0, "interval_step": 0.5},
    )


async def send_verify(org_id: uuid.UUID, provider: ProviderName) -> bool:
    """Publish `ti.verify {org_id, provider}` (ids only, never a key). False on failure."""
    message = TiVerifyMessage(org_id=org_id, provider=provider.value)
    try:
        with anyio.fail_after(SEND_TIMEOUT_S):
            await anyio.to_thread.run_sync(
                _send_verify_sync, message, limiter=broker_limiter(), abandon_on_cancel=True
            )
    except Exception as exc:  # noqa: BLE001 - any broker failure is reported as a bool
        log.warning("ti.verify publish failed for %s (%s)", provider.value, type(exc).__name__)
        return False
    return True


# --- TI settings ---------------------------------------------------------------------


def _settings_out(row: TiOrgSettings | None) -> TiSettingsOut:
    if row is None:
        return TiSettingsOut(excluded_suffixes=[], updated_at=None)
    suffixes = [s for s in row.excluded_suffixes if isinstance(s, str)]
    return TiSettingsOut(excluded_suffixes=suffixes, updated_at=row.updated_at)


async def get_ti_settings(ctx: OrgContext) -> TiSettingsOut:
    return _settings_out(await ctx.session.get(TiOrgSettings, ctx.org_id))


async def update_ti_settings(
    ctx: OrgContext, body: TiSettingsUpdate, request: HTTPConnection
) -> TiSettingsOut:
    await _lock_org(ctx)
    row = await ctx.session.get(TiOrgSettings, ctx.org_id, with_for_update=True)
    before = list(row.excluded_suffixes) if row is not None else []
    if row is None:
        row = TiOrgSettings(
            organization_id=ctx.org_id,
            excluded_suffixes=body.excluded_suffixes,
            updated_by=ctx.user.id,
        )
        ctx.session.add(row)
    else:
        row.excluded_suffixes = body.excluded_suffixes
        row.updated_by = ctx.user.id
        row.updated_at = datetime.now(UTC)
    await ctx.session.flush()
    await ctx.session.refresh(row)
    if before != body.excluded_suffixes:
        audit.record(
            ctx.session,
            action="ti.settings_updated",
            org_id=ctx.org_id,
            actor_id=ctx.user.id,
            target_type="ti_settings",
            details={
                "excluded_suffixes": body.excluded_suffixes,
                "added": [s for s in body.excluded_suffixes if s not in before],
                "removed": [s for s in before if s not in body.excluded_suffixes],
            },
            request=request,
        )
    return _settings_out(row)
