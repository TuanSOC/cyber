"""AI analyst queries shared by the services (M5 phase 7).

Everything runs in the caller's tenant session (RLS) and filters by org explicitly as
well; the only system-session reads are the global active-run count and the dispatch
lookup in `runs.py`.
"""

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import ColumnElement, Numeric, Select, case, cast, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.ai.contracts import RUN_ACTIVE
from app.modules.ai.models import (
    AiCitation,
    AiOrgSettings,
    AiOutput,
    AiProviderConfig,
    AiRun,
    AiRunIndex,
    AiRunInput,
)
from app.modules.organizations.models import Organization
from app.modules.users.models import User

USAGE_KEYS = ("input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens")


async def lock_org(session: AsyncSession, org_id: uuid.UUID) -> None:
    """`FOR NO KEY UPDATE` on the org row: concurrent writes of one org serialize."""
    await session.execute(
        select(Organization.id).where(Organization.id == org_id).with_for_update(key_share=True)
    )


async def advisory_lock(session: AsyncSession, key: str) -> None:
    """A transaction-scoped advisory lock (released at commit/rollback)."""
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": key}
    )


async def org_settings(
    session: AsyncSession, org_id: uuid.UUID, *, for_update: bool = False
) -> AiOrgSettings | None:
    return await session.get(AiOrgSettings, org_id, with_for_update=for_update)


async def provider_configs(session: AsyncSession, org_id: uuid.UUID) -> dict[str, AiProviderConfig]:
    rows = await session.scalars(
        select(AiProviderConfig).where(AiProviderConfig.organization_id == org_id)
    )
    return {row.provider: row for row in rows}


async def provider_config(
    session: AsyncSession, org_id: uuid.UUID, provider: str, *, for_update: bool = False
) -> AiProviderConfig | None:
    stmt = select(AiProviderConfig).where(
        AiProviderConfig.organization_id == org_id, AiProviderConfig.provider == provider
    )
    if for_update:
        stmt = stmt.with_for_update()
    return await session.scalar(stmt)


def _usage_number(key: str) -> ColumnElement[Any]:
    """A numeric `ai_runs.usage` key, 0 when missing or not a number."""
    return case(
        (
            func.jsonb_typeof(func.jsonb_extract_path(AiRun.usage, key)) == "number",
            cast(func.jsonb_extract_path_text(AiRun.usage, key), Numeric),
        ),
        else_=0,
    )


def day_start(now: datetime | None = None) -> datetime:
    current = now or datetime.now(UTC)
    return current.replace(hour=0, minute=0, second=0, microsecond=0)


async def usage_today(
    session: AsyncSession, org_id: uuid.UUID
) -> list[tuple[str, int, dict[str, int], int]]:
    """(provider, runs, {usage key: tokens}, cost_micros) for today's (UTC) runs."""
    columns = [func.coalesce(func.sum(_usage_number(k)), 0) for k in USAGE_KEYS]
    rows = await session.execute(
        select(
            AiRun.provider,
            func.count(AiRun.id),
            func.coalesce(func.sum(AiRun.cost_micros), 0),
            *columns,
        )
        .where(AiRun.organization_id == org_id, AiRun.created_at >= day_start())
        .group_by(AiRun.provider)
        .order_by(AiRun.provider)
    )
    out = []
    for provider, runs, cost, *tokens in rows:
        usage = {k: int(v or 0) for k, v in zip(USAGE_KEYS, tokens, strict=True)}
        out.append((str(provider), int(runs), usage, int(cost or 0)))
    return out


async def tokens_today(session: AsyncSession, org_id: uuid.UUID) -> int:
    return sum(sum(usage.values()) for _, _, usage, _ in await usage_today(session, org_id))


async def count_active_runs(session: AsyncSession, org_id: uuid.UUID) -> int:
    """Non-final runs of the org, incident children included (RT8)."""
    active = await session.scalar(
        select(func.count(AiRun.id)).where(
            AiRun.organization_id == org_id, AiRun.status.in_(RUN_ACTIVE)
        )
    )
    return int(active or 0)


def runs_query() -> Select[AiRun, datetime | None, str]:
    return (
        select(AiRun, AiRunIndex.resume_at, User.display_name)
        .outerjoin(
            AiRunIndex,
            (AiRunIndex.run_id == AiRun.id) & (AiRunIndex.organization_id == AiRun.organization_id),
        )
        .join(User, User.id == AiRun.requested_by)
    )


async def get_run_row(
    session: AsyncSession, org_id: uuid.UUID, run_id: uuid.UUID
) -> tuple[AiRun, datetime | None, str] | None:
    row = (
        await session.execute(
            runs_query().where(AiRun.id == run_id, AiRun.organization_id == org_id)
        )
    ).one_or_none()
    return (row[0], row[1], row[2]) if row is not None else None


async def child_counts(
    session: AsyncSession, org_id: uuid.UUID, parent_ids: Sequence[uuid.UUID]
) -> dict[uuid.UUID, int]:
    if not parent_ids:
        return {}
    rows = await session.execute(
        select(AiRun.parent_run_id, func.count(AiRun.id))
        .where(AiRun.organization_id == org_id, AiRun.parent_run_id.in_(parent_ids))
        .group_by(AiRun.parent_run_id)
    )
    return {parent: int(n) for parent, n in rows if parent is not None}


async def children_of(
    session: AsyncSession, org_id: uuid.UUID, parent_id: uuid.UUID
) -> list[tuple[AiRun, list[str]]]:
    """Children of an incident run with the flags of their outputs (RT23)."""
    rows = await session.execute(
        select(AiRun, AiOutput.flags)
        .outerjoin(
            AiOutput,
            (AiOutput.run_id == AiRun.id) & (AiOutput.organization_id == AiRun.organization_id),
        )
        .where(AiRun.organization_id == org_id, AiRun.parent_run_id == parent_id)
        .order_by(AiRun.created_at, AiRun.id)
    )
    return [(run, [f for f in (flags or []) if isinstance(f, str)]) for run, flags in rows]


async def output_of(session: AsyncSession, org_id: uuid.UUID, run_id: uuid.UUID) -> AiOutput | None:
    return await session.scalar(
        select(AiOutput).where(AiOutput.organization_id == org_id, AiOutput.run_id == run_id)
    )


async def citations_of(
    session: AsyncSession, org_id: uuid.UUID, output_id: uuid.UUID
) -> list[AiCitation]:
    rows = await session.scalars(
        select(AiCitation)
        .where(AiCitation.organization_id == org_id, AiCitation.output_id == output_id)
        .order_by(AiCitation.created_at, AiCitation.id)
    )
    return list(rows)


async def inputs_of(
    session: AsyncSession, org_id: uuid.UUID, run_ids: Sequence[uuid.UUID]
) -> list[AiRunInput]:
    rows = await session.scalars(
        select(AiRunInput)
        .where(AiRunInput.organization_id == org_id, AiRunInput.run_id.in_(run_ids))
        .order_by(AiRunInput.run_id, AiRunInput.stage)
    )
    return list(rows)


async def tree_run_ids(session: AsyncSession, org_id: uuid.UUID, run: AiRun) -> list[uuid.UUID]:
    """Every run of the incident tree `run` belongs to (itself when it has none)."""
    root = run.parent_run_id or run.id
    ids = await session.scalars(
        select(AiRun.id).where(
            AiRun.organization_id == org_id,
            (AiRun.id == root) | (AiRun.parent_run_id == root),
        )
    )
    return list(ids)
