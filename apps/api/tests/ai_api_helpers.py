"""Helpers for the AI analyst API tests (M5 phase 7): captured publishes, the builder
doubles over the phase-4 stub (RT12), configured orgs, and outputs "written by the worker".
"""

import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import AsyncClient, Response
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.tenancy import tenant_session
from app.modules.ai import runs, service_providers
from app.modules.ai.context import builder
from app.modules.ai.contracts import (
    AiProviderName,
    AiRunRequest,
    AiScope,
    AiTask,
    BuiltRun,
    CitationResult,
    FrozenContext,
    OutputVerification,
    RefKind,
    RunScope,
)
from app.modules.ai.models import AiCitation, AiOrgSettings, AiOutput, AiRun, AiRunIndex
from tests.ai_doubles import fake_build_run, fake_preview, make_context
from tests.ai_helpers import AI_SENTINEL_KEY, seed_job
from tests.factories import Registered, csrf
from tests.integration.seed import Tenant

API = "/api/v1/orgs"
Builder = Callable[
    [AsyncSession, uuid.UUID, uuid.UUID, AiRunRequest, AiOrgSettings], Awaitable[Any]
]


@dataclass
class AiSent:
    """Publishes captured instead of sent (no live analyst worker in API tests)."""

    runs: list[uuid.UUID] = field(default_factory=list)
    verifies: list[tuple[uuid.UUID, str, int]] = field(default_factory=list)


def capture_ai_sends(monkeypatch: pytest.MonkeyPatch) -> AiSent:
    sent = AiSent()

    async def dispatch(run_ids: Sequence[uuid.UUID]) -> None:
        sent.runs.extend(run_ids)

    async def send_verify(org_id: uuid.UUID, provider: AiProviderName, key_version: int) -> bool:
        sent.verifies.append((org_id, provider.value, key_version))
        return True

    monkeypatch.setattr(runs, "dispatch", dispatch)
    monkeypatch.setattr(service_providers, "send_verify", send_verify)
    return sent


def use_fake_builder(
    monkeypatch: pytest.MonkeyPatch,
    build: Builder = fake_build_run,
    preview: Builder = fake_preview,
) -> None:
    """The `tests/ai_doubles.py` builder stand-ins over the phase-4 entry points (RT12)."""
    monkeypatch.setattr(builder, "build_run", build)
    monkeypatch.setattr(builder, "preview", preview)


def incident_builder(job_ids: Sequence[uuid.UUID]) -> Builder:
    """An incident builder over real jobs (the `ai_runs` / `ai_context_refs` job FKs need
    them): a root with V1 + K1 and one `job_digest` child per job; job requests fall back to
    `fake_build_run`."""

    async def build(
        session: AsyncSession,
        org_id: uuid.UUID,
        user_id: uuid.UUID,
        req: AiRunRequest,
        settings_row: AiOrgSettings,
    ) -> BuiltRun:
        if req.investigation_id is None:
            return await fake_build_run(session, org_id, user_id, req, settings_row)
        scope = RunScope(
            scope=AiScope.INVESTIGATION,
            job_ids=tuple(job_ids),
            investigation_id=req.investigation_id,
        )
        root = make_context(
            task=req.task,
            job_id=job_ids[0],
            scope=scope,
            items=(
                (RefKind.INVESTIGATION, {"title": "Incident case"}),
                (RefKind.EVIDENCE, {"filename": "capture.pcap", "sha256": "a" * 64}),
            ),
        )
        children = tuple(make_context(task=AiTask.JOB_DIGEST, job_id=job) for job in job_ids)
        return BuiltRun(root=root, children=children)

    return build


async def put_provider(
    client: AsyncClient, org_id: uuid.UUID, provider: str = "mock", **body: Any
) -> Response:
    return await client.put(
        f"{API}/{org_id}/ai/providers/{provider}", json=body, headers=csrf(client)
    )


async def put_settings(client: AsyncClient, org_id: uuid.UUID, **body: Any) -> Response:
    return await client.put(f"{API}/{org_id}/ai/settings", json=body, headers=csrf(client))


async def enable_ai(
    client: AsyncClient,
    org_id: uuid.UUID,
    provider: str = "mock",
    key: str = AI_SENTINEL_KEY,
    **settings: Any,
) -> None:
    """AI on for the org (privacy acknowledged) and `provider` keyed, terms acknowledged,
    enabled and the org default."""
    on = await put_settings(
        client,
        org_id,
        ai_enabled=True,
        acknowledge_privacy=True,
        default_provider=provider,
        **settings,
    )
    assert on.status_code == 200, on.text
    configured = await put_provider(
        client, org_id, provider, api_key=key, enabled=True, acknowledge_terms=True
    )
    assert configured.status_code == 200, configured.text


async def request_run(client: AsyncClient, org_id: uuid.UUID, **body: Any) -> Response:
    return await client.post(f"{API}/{org_id}/ai/runs", json=body, headers=csrf(client))


async def preview(client: AsyncClient, org_id: uuid.UUID, **body: Any) -> Response:
    return await client.post(f"{API}/{org_id}/ai/context-preview", json=body, headers=csrf(client))


async def tenant_of(reg: Registered) -> Tenant:
    """A `Tenant` (for `tests/ai_helpers.py`) of a registered owner, with a new case."""
    created = await reg.client.post(
        f"{API}/{reg.org_id}/investigations",
        json={"title": "AI case", "severity": "high"},
        headers=csrf(reg.client),
    )
    assert created.status_code == 201, created.text
    return Tenant(reg.org_id, reg.user_id, uuid.UUID(created.json()["id"]))


async def job_of(
    reg: Registered, analyzer: str = "pcap", *, status: str = "succeeded"
) -> uuid.UUID:
    return await seed_job(await tenant_of(reg), analyzer, status=status)


async def set_usage(org_id: uuid.UUID, run_id: uuid.UUID | str, tokens: int) -> None:
    async with tenant_session(org_id, None) as s:
        await s.execute(
            update(AiRun)
            .where(AiRun.id == uuid.UUID(str(run_id)))
            .values(usage={"input_tokens": tokens, "output_tokens": 0}, cost_micros=tokens)
        )


async def finish_run(
    org_id: uuid.UUID,
    run_id: uuid.UUID | str,
    *,
    status: str = "completed",
    error_code: str | None = None,
    body: dict[str, Any] | None = None,
    citations: Sequence[CitationResult] = (),
    verification: OutputVerification | None = None,
    flags: Sequence[str] = (),
    metrics: dict[str, Any] | None = None,
    usage: dict[str, int] | None = None,
) -> None:
    """What the worker writes: queued -> running -> final, plus the output and citations."""
    rid = uuid.UUID(str(run_id))
    now = datetime.now(UTC)
    async with tenant_session(org_id, None) as s:
        await s.execute(
            update(AiRun).where(AiRun.id == rid).values(status="running", started_at=now)
        )
        values: dict[str, Any] = {"status": status, "error_code": error_code, "finished_at": now}
        if metrics is not None:
            values["metrics"] = metrics
        if usage is not None:
            values["usage"] = usage
        await s.execute(update(AiRun).where(AiRun.id == rid).values(**values))
        await s.execute(update(AiRunIndex).where(AiRunIndex.run_id == rid).values(status=status))
        if body is None:
            return
        output = AiOutput(
            organization_id=org_id,
            run_id=rid,
            body=body,
            verification=(verification or OutputVerification()).model_dump(mode="json"),
            flags=list(flags),
        )
        s.add(output)
        await s.flush()
        for c in citations:
            s.add(
                AiCitation(
                    organization_id=org_id,
                    output_id=output.id,
                    run_id=rid,
                    claim_path=c.claim_path,
                    section=c.section,
                    claim_id=c.claim_id,
                    claim_status=None,
                    label=c.label,
                    kind=c.kind.value if c.kind else None,
                    ref_id=c.ref_id,
                    job_id=c.job_id,
                    status=c.status.value,
                    reason=c.reason.value if c.reason else None,
                    field=c.field,
                    quote=c.quote,
                    stale=c.stale,
                )
            )


def ref_of(ctx: FrozenContext, label: str) -> Any:
    return next(r for r in ctx.refs if r.label == label)
