"""AI provider configs: catalog, write-only sealed keys, terms and paid-tier
acknowledgements, verify queueing (M5 phase 7).

The API seals with the active kid's public key only (`ai/seal.py`); it never opens a key and
never calls a provider (the analyst worker verifies through `ai.verify`). Writes lock the org
row `FOR NO KEY UPDATE`, so concurrent PUTs of one org serialize (and the first-configuration
INSERT cannot race into the unique constraint).

Consent (plan Keys): the first `enabled=true` needs `acknowledge_terms`; for Gemini also
`acknowledge_paid_tier`, the admin's attestation that the key is a paid-tier key (RT5). A
provider can be enabled without an own key only when the dev platform key covers it.
"""

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import anyio
from cyberlab_jobs import AI_VERIFY, Queues
from redis.exceptions import RedisError
from starlette.requests import HTTPConnection

from app.core import rate_limit
from app.core.config import Settings, get_settings
from app.core.errors import AppError, Conflict, TooManyRequests
from app.core.rbac import OrgContext
from app.core.stepup import StepUpAction, require_recent_auth
from app.core.threads import broker_limiter
from app.modules.ai import repository
from app.modules.ai.availability import provider_available
from app.modules.ai.catalog import AI_CATALOG, PRICE_VERSION
from app.modules.ai.contracts import AiProviderName, VerifyStatus
from app.modules.ai.messages import AiVerifyMessage
from app.modules.ai.models import AiProviderConfig
from app.modules.ai.schemas import (
    AiLimitsIn,
    AiLimitsOut,
    AiModelOut,
    AiModelPrice,
    AiProviderOut,
    AiProviderPage,
    AiProviderUpdate,
)
from app.modules.ai.seal import SealError, load_public_key, seal
from app.modules.audit import service as audit

log = logging.getLogger(__name__)

SEND_TIMEOUT_S = 15
VERIFY_PER_10MIN = 10
TARGET_TYPE = "ai_provider"


class ProviderUnavailable(AppError):
    status_code = 422
    code = "provider_unavailable"
    message = "This AI provider is not available in this deployment"


class TermsNotAcknowledged(AppError):
    status_code = 422
    code = "terms_not_acknowledged"
    message = "Enabling a provider for the first time requires acknowledge_terms: true"


class PaidTierNotAcknowledged(AppError):
    status_code = 422
    code = "paid_tier_not_acknowledged"
    message = "Enabling Gemini requires acknowledge_paid_tier: true (a paid-tier key)"


class ModelNotAllowed(AppError):
    status_code = 422
    code = "model_not_allowed"
    message = "The model is not in this provider's allowlist"


class ApiKeyRequired(AppError):
    status_code = 422
    code = "api_key_required"
    message = "The first configuration of a provider requires an api_key"


class InvalidApiKey(AppError):
    status_code = 422
    code = "invalid_api_key"
    message = "The api_key is not acceptable"


class LimitAboveCeiling(AppError):
    status_code = 422
    code = "limit_above_ceiling"
    message = "Limits may not be set above the provider's ceiling"


class ProviderNotConfigured(Conflict):
    code = "provider_not_configured"
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


def platform_key(settings: Settings, provider: AiProviderName) -> bool:
    """The dev/test platform key covers `provider` (the API only reads the non-secret
    `AI_PLATFORM_PROVIDER`; it never sees the key file). Never in prod."""
    return settings.env != "prod" and settings.ai_platform_provider == provider


def keyed(config: AiProviderConfig | None, settings: Settings, provider: AiProviderName) -> bool:
    return (config is not None and config.key_ct is not None) or platform_key(settings, provider)


def per_minute_ceiling(settings: Settings, provider: AiProviderName) -> int:
    entry = AI_CATALOG[provider]
    return settings.ai_ceilings.per_minute.get(entry.name, entry.ceilings.per_minute)


def _org_limits(raw: dict[str, Any] | None, ceiling: int) -> AiLimitsOut | None:
    """The org's own limit as the worker applies it: a value stored under a higher ceiling
    shows the current (lowered) ceiling, never more."""
    minute = (raw or {}).get("per_minute")
    if isinstance(minute, bool) or not isinstance(minute, int) or minute < 1:
        return None
    return AiLimitsOut(per_minute=min(minute, ceiling))


def _checked_limits(
    provider: AiProviderName, limits: AiLimitsIn, settings: Settings
) -> dict[str, int]:
    if limits.per_minute is not None and limits.per_minute > per_minute_ceiling(settings, provider):
        raise LimitAboveCeiling()
    return {k: v for k, v in limits.model_dump().items() if v is not None}


def to_out(
    provider: AiProviderName, config: AiProviderConfig | None, settings: Settings
) -> AiProviderOut:
    entry = AI_CATALOG[provider]
    available, reason = provider_available(settings, provider)
    configured = config is not None and config.key_ct is not None
    ceiling = per_minute_ceiling(settings, provider)
    return AiProviderOut(
        name=provider,
        label=entry.label,
        models=[
            AiModelOut(
                id=m.id,
                label=m.label,
                price=AiModelPrice(
                    input=m.price.input,
                    output=m.price.output,
                    cache_read=m.price.cache_read,
                    cache_write=m.price.cache_write,
                ),
                verified=m.verified,
            )
            for m in entry.models
        ],
        default_model=entry.default_model,
        price_version=PRICE_VERSION,
        tos_note=entry.tos_note,
        privacy_note=entry.privacy_note,
        available=available,
        unavailable_reason=reason,
        platform_key=platform_key(settings, provider),
        requires_paid_tier_ack=entry.requires_billing_flag,
        configured=configured,
        enabled=bool(config and config.enabled),
        model=config.model if config is not None else None,
        key_last4=config.key_last4 if config is not None and configured else None,
        verify_status=VerifyStatus(config.verify_status) if config is not None else None,
        verified_at=config.verified_at if config is not None else None,
        last_error_code=config.last_error_code if config is not None else None,
        terms_ack_at=config.terms_ack_at if config is not None else None,
        paid_tier_ack_at=config.paid_tier_ack_at if config is not None else None,
        default_limits=AiLimitsOut(per_minute=entry.default_limits.per_minute),
        ceilings=AiLimitsOut(per_minute=ceiling),
        limits=_org_limits(config.limits, ceiling) if config is not None else None,
    )


async def list_providers(ctx: OrgContext) -> AiProviderPage:
    settings = get_settings()
    configs = await repository.provider_configs(ctx.session, ctx.org_id)
    items = [to_out(name, configs.get(name.value), settings) for name in AI_CATALOG]
    return AiProviderPage(items=items, total=len(items), platform_ai_enabled=settings.ai_enabled)


# --- writes --------------------------------------------------------------------------


def _public_key(settings: Settings) -> tuple[str, Any]:
    kid = settings.ai_seal_active_kid
    encoded = settings.ai_seal_public_keys.get(kid) if kid else None
    if not kid or not encoded:
        raise SealUnavailable()
    try:
        return kid, load_public_key(encoded)
    except SealError:
        raise SealUnavailable() from None


def _record(
    ctx: OrgContext,
    request: HTTPConnection,
    action: str,
    config: AiProviderConfig | None,
    details: dict[str, Any],
) -> None:
    audit.record(
        ctx.session,
        action=action,
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type=TARGET_TYPE,
        target_id=config.id if config is not None else None,
        details=details,
        request=request,
    )


async def update_provider(
    ctx: OrgContext,
    provider: AiProviderName,
    body: AiProviderUpdate,
    request: HTTPConnection,
) -> tuple[AiProviderOut, int | None]:
    """Apply one PUT. Returns the read model and, when a new key was stored, its
    `key_version` (the caller queues `ai.verify` for it after the commit)."""
    settings = get_settings()
    available, _ = provider_available(settings, provider)
    if not available:
        raise ProviderUnavailable()
    entry = AI_CATALOG[provider]
    model_set = "model" in body.model_fields_set
    if model_set and body.model is not None and body.model not in entry.model_ids:
        raise ModelNotAllowed()
    platform = platform_key(settings, provider)
    # `{}` resets the org's limits to the catalog defaults.
    new_limits = (
        _checked_limits(provider, body.limits, settings) if body.limits is not None else None
    )

    await repository.lock_org(ctx.session, ctx.org_id)
    config = await repository.provider_config(
        ctx.session, ctx.org_id, provider.value, for_update=True
    )
    had_key = config is not None and config.key_ct is not None
    if body.api_key is None and not had_key and not platform and (config is None or body.enabled):
        raise ApiKeyRequired()

    if config is None:
        config = AiProviderConfig(
            organization_id=ctx.org_id, provider=provider.value, key_version=0, limits={}
        )
        ctx.session.add(config)
    now = datetime.now(UTC)
    acknowledged: list[str] = []
    # The paid-tier attestation is about one key (RT5): a new key clears it, so it must be
    # given again (in this request or before the next enable).
    attestation_cleared = (
        body.api_key is not None
        and entry.requires_billing_flag
        and config.paid_tier_ack_at is not None
    )
    if attestation_cleared:
        config.paid_tier_ack_at = None
        config.paid_tier_ack_by = None
    if body.acknowledge_terms and config.terms_ack_at is None:
        config.terms_ack_at = now
        config.terms_ack_by = ctx.user.id
        acknowledged.append("terms")
    if (
        body.acknowledge_paid_tier
        and entry.requires_billing_flag
        and config.paid_tier_ack_at is None
    ):
        config.paid_tier_ack_at = now
        config.paid_tier_ack_by = ctx.user.id
        acknowledged.append("paid_tier")
    # Enabled after this request (an enabled Gemini config whose key is replaced needs the
    # new attestation in the same request).
    if body.enabled if body.enabled is not None else bool(config.enabled):
        if config.terms_ack_at is None:
            raise TermsNotAcknowledged()
        if entry.requires_billing_flag and config.paid_tier_ack_at is None:
            raise PaidTierNotAcknowledged()

    key_audit: dict[str, Any] | None = None
    if body.api_key is not None:
        with ctx.session.no_autoflush:
            await require_recent_auth(ctx.session, ctx.user, action=StepUpAction.PROVIDER_KEY_CHANGE)
        kid, public_key = _public_key(settings)
        version = (config.key_version or 0) + 1
        try:
            sealed = seal(body.api_key, ctx.org_id, provider.value, kid, version, public_key)
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
        if entry.requires_billing_flag:
            key_audit["paid_tier_ack_cleared"] = attestation_cleared

    changed: list[str] = []
    if body.enabled is not None and body.enabled != bool(config.enabled):
        config.enabled = body.enabled
        changed.append("enabled")
    if model_set and body.model != config.model:
        config.model = body.model
        changed.append("model")
    if new_limits is not None and new_limits != (config.limits or {}):
        config.limits = new_limits
        changed.append("limits")
    await ctx.session.flush()

    if acknowledged:
        _record(
            ctx,
            request,
            "integration.ai_terms_acknowledged",
            config,
            {"provider": provider.value, "acknowledged": acknowledged},
        )
    if key_audit is not None:
        action = "integration.ai_key_replaced" if had_key else "integration.ai_key_set"
        _record(ctx, request, action, config, key_audit)
    if changed:
        _record(
            ctx,
            request,
            "integration.ai_updated",
            config,
            {
                "provider": provider.value,
                "changed": changed,
                "enabled": config.enabled,
                "model": config.model,
                **({"limits": config.limits} if "limits" in changed else {}),
            },
        )
    new_version = config.key_version if key_audit is not None else None
    return to_out(provider, config, settings), new_version


async def remove_key(ctx: OrgContext, provider: AiProviderName, request: HTTPConnection) -> None:
    """Clear the sealed columns and disable the provider (an UPDATE: the row is never
    deleted). `key_version` stays, so the next key needs a higher one (RT18)."""
    await repository.lock_org(ctx.session, ctx.org_id)
    config = await repository.provider_config(
        ctx.session, ctx.org_id, provider.value, for_update=True
    )
    if config is None or config.key_ct is None:
        raise ProviderNotConfigured()
    await require_recent_auth(ctx.session, ctx.user, action=StepUpAction.PROVIDER_KEY_CHANGE)
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
    _record(
        ctx,
        request,
        "integration.ai_key_removed",
        config,
        {"provider": provider.value, "key_last4": last4, "key_version": config.key_version},
    )


async def check_verifiable(ctx: OrgContext, provider: AiProviderName) -> int:
    """The stored `key_version` to verify (409 without a key, 422 when unavailable)."""
    available, _ = provider_available(get_settings(), provider)
    if not available:
        raise ProviderUnavailable()
    config = await repository.provider_config(ctx.session, ctx.org_id, provider.value)
    if config is None or config.key_ct is None:
        raise ProviderNotConfigured()
    return config.key_version


def verify_rate_key(org_id: uuid.UUID, provider: AiProviderName) -> str:
    return f"ai:verify:{org_id}:{provider.value}"


async def check_verify_rate(org_id: uuid.UUID, provider: AiProviderName) -> None:
    """POST .../verify: count one check, 429 past `VERIFY_PER_10MIN` per 10 minutes."""
    await rate_limit.hit(verify_rate_key(org_id, provider), VERIFY_PER_10MIN, 600)


async def verify_allowed(org_id: uuid.UUID, provider: AiProviderName) -> bool:
    """A save's check counts against the same limit; a spent limit (or an unreachable
    rate-limit store) only skips the check: the save stands."""
    try:
        await check_verify_rate(org_id, provider)
    except TooManyRequests:
        return False
    except (RedisError, OSError, TimeoutError) as exc:
        log.warning("ai verify rate limit unavailable (%s)", type(exc).__name__)
        return False
    return True


def _send_verify_sync(message: AiVerifyMessage) -> None:
    from app.workers.celery_app import celery_app  # broker client only, no worker

    celery_app.send_task(
        AI_VERIFY,
        kwargs={"message": message.model_dump(mode="json")},
        queue=Queues(get_settings().queue_prefix).analyst,
        retry=True,
        retry_policy={"max_retries": 1, "interval_start": 0, "interval_step": 0.5},
    )


async def send_verify(org_id: uuid.UUID, provider: AiProviderName, key_version: int) -> bool:
    """Publish `ai.verify {org_id, provider, key_version}` (ids only, never a key)."""
    message = AiVerifyMessage(org_id=org_id, provider=provider, key_version=key_version)
    try:
        with anyio.fail_after(SEND_TIMEOUT_S):
            await anyio.to_thread.run_sync(
                _send_verify_sync, message, limiter=broker_limiter(), abandon_on_cancel=True
            )
    except Exception as exc:  # noqa: BLE001 - any broker failure is reported as a bool
        log.warning("ai.verify publish failed for %s (%s)", provider.value, type(exc).__name__)
        return False
    return True
