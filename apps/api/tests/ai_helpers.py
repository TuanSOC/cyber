"""Row seeding for AI analyst schema, worker and API tests (M5 phase 1, FROZEN; RT12).

Rows are inserted directly in tenant sessions (no routes), so any phase can seed an org with
AI enabled, a sealed provider key, a succeeded job and a run with its inputs and refs.
Each phase adds its own helpers in its own module; nobody edits `tests/conftest.py`.
"""

import base64
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cyberlab_jobs.static import Profile
from pydantic import SecretStr

from app.core.sealbox import load_public_key, raw_public
from app.core.tenancy import tenant_session
from app.modules.ai.contracts import AiRunStatus, AiTask, FrozenContext
from app.modules.ai.models import (
    AiContextRef,
    AiOrgSettings,
    AiProviderConfig,
    AiRun,
    AiRunIndex,
    AiRunInput,
)
from app.modules.ai.output_schema import OUTPUT_SCHEMA_VERSION
from app.modules.ai.prompt import PROMPT_VERSION
from app.modules.ai.seal import seal
from app.modules.analysis.models import AnalysisJob, AnalysisStatus, Analyzer
from app.modules.evidence.models import Evidence
from tests.ai_doubles import make_context
from tests.integration.seed import Tenant

AI_SENTINEL_KEY = "CYBERLAB-AI-SENTINEL-KEY-00000000000000000"


@dataclass(frozen=True)
class AiSealKeys:
    kid: str
    private: X25519PrivateKey
    public_b64: str

    @property
    def private_keys(self) -> dict[str, X25519PrivateKey]:
        return {self.kid: self.private}


def new_ai_seal_keys(kid: str = "test-ai-1") -> AiSealKeys:
    private = X25519PrivateKey.generate()
    return AiSealKeys(kid, private, base64.b64encode(raw_public(private.public_key())).decode())


async def seed_ai_settings(t: Tenant, *, enabled: bool = True, **fields: Any) -> None:
    """`ai_org_settings` for the org (privacy acknowledged when enabled)."""
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(
            AiOrgSettings(
                organization_id=t.org_id,
                ai_enabled=enabled,
                privacy_ack_at=datetime.now(UTC) if enabled else None,
                privacy_ack_by=t.owner_id if enabled else None,
                updated_by=t.owner_id,
                **fields,
            )
        )


async def seed_ai_config(
    t: Tenant,
    keys: AiSealKeys | None = None,
    *,
    provider: str = "mock",
    key: str = AI_SENTINEL_KEY,
    enabled: bool = True,
    version: int = 1,
    model: str | None = None,
    sealed: bool = True,
) -> uuid.UUID:
    """A provider config whose key is sealed through the real `ai.seal.seal()`."""
    columns: dict[str, Any] = {"key_version": 0}
    if sealed:
        keys = keys or new_ai_seal_keys()
        box = seal(
            SecretStr(key), t.org_id, provider, keys.kid, version, load_public_key(keys.public_b64)
        )
        columns = {
            "key_kid": box.kid,
            "key_version": box.key_version,
            "key_epk": box.epk,
            "key_nonce": box.nonce,
            "key_ct": box.ct,
            "key_last4": box.last4,
        }
    now = datetime.now(UTC)
    async with tenant_session(t.org_id, t.owner_id) as s:
        config = AiProviderConfig(
            organization_id=t.org_id,
            provider=provider,
            enabled=enabled,
            model=model,
            terms_ack_at=now,
            terms_ack_by=t.owner_id,
            paid_tier_ack_at=now if provider == "gemini" else None,
            paid_tier_ack_by=t.owner_id if provider == "gemini" else None,
            **columns,
        )
        s.add(config)
    return config.id


async def seed_job(t: Tenant, analyzer: str = "pcap", *, status: str = "succeeded") -> uuid.UUID:
    """An evidence row and an analysis job on it (no results)."""
    async with tenant_session(t.org_id, t.owner_id) as s:
        evidence = Evidence(
            organization_id=t.org_id,
            investigation_id=t.investigation_id,
            original_filename="capture.pcap" if analyzer == "pcap" else "sample.bin",
            detected_mime="application/octet-stream",
            detected_description="data",
            size_bytes=1024,
            storage_bucket="evidence-test",
            storage_key=f"{t.org_id}/{uuid.uuid4()}",
            storage_version_id="v1",
            uploaded_by=t.owner_id,
        )
        s.add(evidence)
        await s.flush()
        job = AnalysisJob(
            organization_id=t.org_id,
            evidence_id=evidence.id,
            analyzer=Analyzer(analyzer),
            profile=Profile.FULL if analyzer == "static" else None,
            status=AnalysisStatus(status),
            requested_by=t.owner_id,
            ingest_token_sha256=secrets.token_hex(32),
        )
        s.add(job)
    return job.id


async def seed_ai_run(
    t: Tenant,
    *,
    job_id: uuid.UUID | None = None,
    ctx: FrozenContext | None = None,
    task: AiTask = AiTask.SUMMARIZE_PCAP,
    status: str = AiRunStatus.QUEUED,
    provider: str = "mock",
    model: str = "mock-1",
    parent_run_id: uuid.UUID | None = None,
    deadline_s: int = 1200,
) -> uuid.UUID:
    """A job-scoped run with its index row, its `base` input and its context refs."""
    job_id = job_id or await seed_job(t)
    ctx = ctx or make_context(task=task, job_id=job_id)
    run_id = uuid.uuid4()
    deadline = datetime.now(UTC) + timedelta(seconds=deadline_s)
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(
            AiRun(
                id=run_id,
                organization_id=t.org_id,
                task=task,
                scope="job",
                job_id=job_id,
                parent_run_id=parent_run_id,
                provider=provider,
                model=model,
                prompt_version=PROMPT_VERSION,
                output_schema=OUTPUT_SCHEMA_VERSION,
                status=status,
                context_sha256=ctx.sha256,
                context_stats=ctx.stats.model_dump(mode="json"),
                requested_by=t.owner_id,
                deadline_at=deadline,
            )
        )
        await s.flush()
        s.add(
            AiRunIndex(
                run_id=run_id,
                organization_id=t.org_id,
                status=status,
                deadline_at=deadline,
                dispatched_at=datetime.now(UTC),
            )
        )
        s.add(
            AiRunInput(
                run_id=run_id,
                stage="base",
                organization_id=t.org_id,
                context=ctx.model_dump(mode="json", exclude={"pseudonym_map"}),
                context_sha256=ctx.sha256,
                pseudonym_map=ctx.pseudonym_map,
            )
        )
        for ref in ctx.refs:
            s.add(
                AiContextRef(
                    run_id=run_id,
                    label=ref.label,
                    organization_id=t.org_id,
                    stage=ref.stage,
                    kind=ref.kind,
                    ref_table=ref.ref_table,
                    ref_id=ref.ref_id,
                    # Job-scoped refs are FK-checked: point them at the seeded job.
                    job_id=job_id if ref.job_id is not None else None,
                    fields_sha256=ref.fields_sha256,
                )
            )
    return run_id
