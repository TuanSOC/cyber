"""Per-org AI settings: opt-in with privacy acknowledgement, pseudonymization, inclusions and
budgets (M5 phase 7).

AI is off by default. Turning it on needs `acknowledge_privacy`, and so does widening the
disclosure later: strings or case text turned on, or pseudonymization turned off (RT22).
Budgets may not exceed the operator ceilings (`AI_CEILINGS`). There is no refusal-fallback
setting (RT10). The audit rows carry changed field names, booleans and list counts, never
the CIDR or suffix values.
"""

from datetime import UTC, datetime
from typing import Any

from starlette.requests import HTTPConnection

from app.core.config import (
    AI_DEFAULT_DAILY_TOKEN_BUDGET,
    AI_DEFAULT_INCIDENT_TOKEN_CAP,
    AI_DEFAULT_RUN_TOKEN_CAP,
    Settings,
    get_settings,
)
from app.core.errors import AppError
from app.core.rbac import OrgContext
from app.modules.ai import repository
from app.modules.ai.contracts import AiProviderName
from app.modules.ai.models import AiOrgSettings
from app.modules.ai.schemas import AiCeilingsOut, AiSettingsOut, AiSettingsUpdate
from app.modules.audit import service as audit

PRIVACY_NOTICE = (
    "When AI analysis is on, running an analysis sends evidence excerpts from the selected job "
    "or investigation to the chosen AI provider: finding and alert text, IP addresses, "
    "domains and hostnames, URLs (query values replaced), file facts (hashes, names, sizes, "
    "structure), indicators and, when enabled, threat intel summaries, decoded strings and "
    "the case title and description. Internal IP addresses, hostnames and usernames are "
    "replaced with pseudonyms while pseudonymization is on (add your internal CIDRs and "
    "domain suffixes so they are recognized); public indicators are sent as is. The "
    "provider's own terms and retention apply. You can preview exactly what will be sent "
    "before every run."
)

_BOOLS = ("pseudonymize_internal", "include_strings", "include_ti", "include_case_text")
_LISTS = ("internal_cidrs", "internal_suffixes")
_BUDGETS = ("daily_token_budget", "run_token_cap", "incident_token_cap")


class PrivacyNotAcknowledged(AppError):
    status_code = 422
    code = "privacy_not_acknowledged"
    message = (
        "Turning AI on, or widening what is sent (an include toggle on, pseudonymization "
        "off, an internal CIDR or suffix removed), requires acknowledge_privacy: true"
    )


class BudgetAboveCeiling(AppError):
    status_code = 422
    code = "budget_above_ceiling"
    message = "A budget is above the operator ceiling"


def ceilings(settings: Settings) -> AiCeilingsOut:
    c = settings.ai_ceilings
    return AiCeilingsOut(
        daily_token_budget=c.daily_token_budget,
        run_token_cap=c.run_token_cap,
        incident_token_cap=c.incident_token_cap,
    )


def defaults(org_id: Any) -> AiOrgSettings:
    """The effective settings of an org that never saved any (not added to a session)."""
    return AiOrgSettings(
        organization_id=org_id,
        ai_enabled=False,
        default_provider=None,
        pseudonymize_internal=True,
        internal_cidrs=[],
        internal_suffixes=[],
        include_strings=False,
        include_ti=True,
        include_case_text=False,
        daily_token_budget=AI_DEFAULT_DAILY_TOKEN_BUDGET,
        run_token_cap=AI_DEFAULT_RUN_TOKEN_CAP,
        incident_token_cap=AI_DEFAULT_INCIDENT_TOKEN_CAP,
    )


def to_out(row: AiOrgSettings, settings: Settings, *, saved: bool) -> AiSettingsOut:
    return AiSettingsOut(
        ai_enabled=row.ai_enabled,
        platform_ai_enabled=settings.ai_enabled,
        privacy_ack_at=row.privacy_ack_at,
        privacy_ack_by=row.privacy_ack_by,
        default_provider=AiProviderName(row.default_provider) if row.default_provider else None,
        pseudonymize_internal=row.pseudonymize_internal,
        internal_cidrs=[c for c in row.internal_cidrs if isinstance(c, str)],
        internal_suffixes=[s for s in row.internal_suffixes if isinstance(s, str)],
        include_strings=row.include_strings,
        include_ti=row.include_ti,
        include_case_text=row.include_case_text,
        daily_token_budget=row.daily_token_budget,
        run_token_cap=row.run_token_cap,
        incident_token_cap=row.incident_token_cap,
        ceilings=ceilings(settings),
        privacy_notice=PRIVACY_NOTICE,
        updated_at=row.updated_at if saved else None,
    )


async def effective(ctx: OrgContext) -> tuple[AiOrgSettings, bool]:
    """(settings row or the defaults, whether a row exists)."""
    row = await repository.org_settings(ctx.session, ctx.org_id)
    return (row, True) if row is not None else (defaults(ctx.org_id), False)


async def get_ai_settings(ctx: OrgContext) -> AiSettingsOut:
    row, saved = await effective(ctx)
    return to_out(row, get_settings(), saved=saved)


def _removes(current: list[Any], new: list[str] | None) -> bool:
    return new is not None and any(entry not in new for entry in current)


def _widens(row: AiOrgSettings, body: AiSettingsUpdate) -> bool:
    """Anything that sends more (RT22): an `include_*` toggle turned on, pseudonymization
    turned off, or an internal CIDR / suffix removed (less is pseudonymized)."""
    return (
        any(
            getattr(body, name) is True and not getattr(row, name)
            for name in ("include_strings", "include_ti", "include_case_text")
        )
        or (body.pseudonymize_internal is False and row.pseudonymize_internal)
        or _removes(list(row.internal_cidrs), body.internal_cidrs)
        or _removes(list(row.internal_suffixes), body.internal_suffixes)
    )


def _check_budgets(body: AiSettingsUpdate, settings: Settings) -> None:
    c = settings.ai_ceilings
    limits = {
        "daily_token_budget": c.daily_token_budget,
        "run_token_cap": c.run_token_cap,
        "incident_token_cap": c.incident_token_cap,
    }
    for name, ceiling in limits.items():
        value = getattr(body, name)
        if value is not None and value > ceiling:
            raise BudgetAboveCeiling()


async def update_ai_settings(
    ctx: OrgContext, body: AiSettingsUpdate, request: HTTPConnection
) -> AiSettingsOut:
    settings = get_settings()
    _check_budgets(body, settings)
    await repository.lock_org(ctx.session, ctx.org_id)
    row = await repository.org_settings(ctx.session, ctx.org_id, for_update=True)
    if row is None:
        row = defaults(ctx.org_id)
        ctx.session.add(row)
    was_enabled = bool(row.ai_enabled)
    turning_on = body.ai_enabled is True and not was_enabled
    if (turning_on or _widens(row, body)) and not body.acknowledge_privacy:
        raise PrivacyNotAcknowledged()

    changed: list[str] = []
    booleans: dict[str, bool] = {}
    for name in ("ai_enabled", *_BOOLS):
        value = getattr(body, name)
        if value is not None and value != getattr(row, name):
            setattr(row, name, value)
            changed.append(name)
            booleans[name] = value
    for name in (*_LISTS, *_BUDGETS):
        value = getattr(body, name)
        if value is not None and value != getattr(row, name):
            setattr(row, name, value)
            changed.append(name)
    if "default_provider" in body.model_fields_set:
        provider = body.default_provider.value if body.default_provider else None
        if provider != row.default_provider:
            row.default_provider = provider
            changed.append("default_provider")
    acknowledged = body.acknowledge_privacy and (
        turning_on or bool(changed) or row.privacy_ack_at is None
    )
    if acknowledged:
        row.privacy_ack_at = datetime.now(UTC)
        row.privacy_ack_by = ctx.user.id
    if changed or acknowledged:
        row.updated_by = ctx.user.id
        row.updated_at = datetime.now(UTC)
    await ctx.session.flush()
    await ctx.session.refresh(row)

    if changed or acknowledged:
        details: dict[str, Any] = {
            "changed": changed,
            "booleans": booleans,
            "privacy_acknowledged": bool(acknowledged),
            "internal_cidrs_count": len(row.internal_cidrs),
            "internal_suffixes_count": len(row.internal_suffixes),
        }
        if "default_provider" in changed:
            details["default_provider"] = row.default_provider
        audit.record(
            ctx.session,
            action="ai.settings_updated",
            org_id=ctx.org_id,
            actor_id=ctx.user.id,
            target_type="ai_settings",
            details=details,
            request=request,
        )
    if row.ai_enabled != was_enabled:
        audit.record(
            ctx.session,
            action="ai.enabled" if row.ai_enabled else "ai.disabled",
            org_id=ctx.org_id,
            actor_id=ctx.user.id,
            target_type="ai_settings",
            details={"privacy_acknowledged": bool(acknowledged)},
            request=request,
        )
    return to_out(row, settings, saved=True)
