"""The retention executor (M7 phase 3), in-process as `cyberlab_retention` with the purge
MinIO user (no retention-worker container):

- dry-run == enforce on the same seed: what a dry run counts is exactly what enforce purges;
- enforce writes the tombstone, custody (actor: the retention system user), audit and items,
  deletes the versions, and evidence then answers 410 while its hashes, custody, findings,
  IOCs, correlation keys, snapshot and audit remain;
- a purged render frees its slot (re-render, RT11);
- a manual enforce request before `enforce_effective_at` runs as a dry run (RT1);
- the sweep finds the orgs through `retention_policy_index` (RT3);
- an injected delete failure is retried by the next run, and a crash between the tombstone and
  the delete too (RT22); `reconcile_orphans` reports it as `purged_pending_delete`;
- a GOVERNANCE-locked version is skipped.

Shared helpers (`worker`, `captured`, `run_once`, ...) are imported by the other
`test_retention_*` modules.
"""

import hashlib
import io
import uuid
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import pytest_asyncio
from minio.commonconfig import GOVERNANCE
from minio.error import S3Error
from minio.retention import Retention
from sqlalchemy import text, update

from app.core.config import RETENTION_SYSTEM_USER_ID, get_settings
from app.core.tenancy import tenant_session
from app.modules.correlation.models import CorrelationKey
from app.modules.reports import dispatch
from app.modules.reports.models import ReportRender
from app.modules.retention import objects
from app.modules.retention import service as retention_service
from app.modules.retention.models import OrgRetentionPolicy, RetentionRun
from app.modules.retention.select import CandidateSet, EffectivePolicy, candidates
from app.scripts import reconcile_orphans
from app.workers import retention as worker_module
from tests.case_helpers import seed_case
from tests.factories import Registered, csrf, register
from tests.integration.seed import Tenant
from tests.ops_helpers import (
    AgedCase,
    purge_minio,
    retention_session,
    retention_sessionmaker,
    seed_aged_closed_case,
    seed_retention_policy,
)
from tests.report_helpers import (
    purge_reports_test_bucket,
    reports_test_bucket,
    seed_render,
)
from tests.storage_helpers import evidence_test_bucket, purge_test_bucket, root_minio

API = "/api/v1/orgs"
ALL = EffectivePolicy(ti_results_days=30, ai_runs_days=30, closed_case_days=30, enforce=True)

# --- shared helpers ------------------------------------------------------------------------


@dataclass
class Captured:
    """Tasks the API and the worker would have published."""

    enqueued: list[tuple[uuid.UUID, uuid.UUID]] = field(default_factory=list)
    published: list[tuple[str, dict[str, Any]]] = field(default_factory=list)


def clear_legal_holds() -> None:
    """Root: turn every S3 legal hold off in the test buckets (a held version cannot be
    removed, even with governance bypass)."""
    client = root_minio()
    for bucket in (evidence_test_bucket(), reports_test_bucket()):
        for o in client.list_objects(bucket, recursive=True, include_version=True):
            if o.is_delete_marker or not o.object_name:
                continue
            if client.is_object_legal_hold_enabled(bucket, o.object_name, o.version_id):
                client.disable_object_legal_hold(bucket, o.object_name, o.version_id)


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> Iterator[Captured]:
    """The worker runs in-process as the retention role with the purge MinIO user; the API's
    and the worker's publishes are captured."""
    out = Captured()

    async def publish(task: str, message: dict[str, Any]) -> bool:
        out.published.append((task, message))
        return True

    monkeypatch.setattr(worker_module, "_sessionmaker", retention_sessionmaker)
    monkeypatch.setattr(objects, "client", purge_minio)
    monkeypatch.setattr(worker_module, "_enqueue", lambda o, r: out.enqueued.append((o, r)))
    monkeypatch.setattr(retention_service, "publish", publish)
    try:
        yield out
    finally:
        clear_legal_holds()
        purge_test_bucket()
        purge_reports_test_bucket()


async def owner_tenant(name: str = "Retention Org") -> tuple[Registered, Tenant]:
    """A registered owner (can log in) and a Tenant for the row seeders."""
    reg = await register(org_name=name)
    t = Tenant(reg.org_id, reg.user_id, uuid.uuid4())
    case = await seed_case(t, title="First case")
    return reg, Tenant(reg.org_id, reg.user_id, case)


async def run_once(captured: Captured, org_id: uuid.UUID) -> uuid.UUID:
    """One sweep (it must schedule this org) and its run, to the end."""
    before = len(captured.enqueued)
    await worker_module.sweep()
    runs = [r for o, r in captured.enqueued[before:] if o == org_id]
    assert len(runs) == 1, captured.enqueued
    outcome = await worker_module.run_org(org_id, runs[0])
    while outcome.status == "running":  # time-sliced
        outcome = await worker_module.run_org(org_id, runs[0])
    return runs[0]


async def run_row(org_id: uuid.UUID, run_id: uuid.UUID) -> RetentionRun:
    async with tenant_session(org_id, None) as s:
        row = await s.get(RetentionRun, run_id)
    assert row is not None
    return row


async def items(org_id: uuid.UUID, run_id: uuid.UUID) -> list[dict[str, Any]]:
    async with tenant_session(org_id, None) as s:
        rows = await s.execute(
            text(
                "SELECT category, ref_table, ref_id, job_id, rows, bytes, object_key, "
                "object_version_id, outcome FROM retention_run_items WHERE run_id = :r "
                "ORDER BY created_at, id"
            ),
            {"r": run_id},
        )
        return [dict(r._mapping) for r in rows]


async def count(org_id: uuid.UUID, sql: str, **params: Any) -> int:
    async with tenant_session(org_id, None) as s:
        return int((await s.execute(text(sql), params)).scalar_one())


async def select_now(org_id: uuid.UUID, policy: EffectivePolicy = ALL) -> CandidateSet:
    async with retention_session(org_id) as s:
        return await candidates(s, org_id, policy, now=datetime.now(UTC), limit=10_000)


def version_present(bucket: str, key: str, version: str) -> bool:
    try:
        root_minio().stat_object(bucket, key, version_id=version)
    except S3Error as exc:
        if exc.code in ("NoSuchKey", "NoSuchVersion"):
            return False
        raise
    return True


async def proper_render(t: Tenant, aged: AgedCase) -> tuple[uuid.UUID, str, str]:
    """A second succeeded PDF render of the aged version, stored at its real key (the
    frozen helper's rendition uses another key). Returns (render_id, key, version_id)."""
    data = b"%PDF-1.7 proper rendition\n"
    render_id, _ = await seed_render(t, aged.version_id, fmt="html")
    async with tenant_session(t.org_id, t.owner_id) as s:
        number = (
            await s.execute(
                text("SELECT version FROM report_versions WHERE id = :v"), {"v": aged.version_id}
            )
        ).scalar_one()
    key = dispatch.render_key(t.org_id, aged.report_id, number, render_id, "html")
    put = root_minio().put_object(reports_test_bucket(), key, io.BytesIO(data), len(data))
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            update(ReportRender)
            .where(ReportRender.id == render_id)
            .values(status="running", started_at=datetime.now(UTC) - timedelta(days=400))
        )
        await s.execute(
            update(ReportRender)
            .where(ReportRender.id == render_id)
            .values(
                status="succeeded",
                sha256=hashlib.sha256(data).hexdigest(),
                bytes=len(data),
                pages=1,
                object_version_id=str(put.version_id),
                finished_at=datetime.now(UTC) - timedelta(days=400),
            )
        )
    return render_id, key, str(put.version_id)


async def set_enforce(t: Tenant, on: bool) -> None:
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            update(OrgRetentionPolicy)
            .where(OrgRetentionPolicy.organization_id == t.org_id)
            .values(enforce=on)
        )


@pytest_asyncio.fixture(loop_scope="session")
async def aged(captured: Captured) -> AsyncIterator[tuple[Registered, Tenant, AgedCase]]:
    reg, t = await owner_tenant()
    case = await seed_aged_closed_case(t)
    yield reg, t, case


# --- tests ---------------------------------------------------------------------------------


async def test_no_policy_selects_and_purges_nothing(
    captured: Captured, aged: tuple[Registered, Tenant, AgedCase]
) -> None:
    _, t, _ = aged
    empty = EffectivePolicy(None, None, None, enforce=True)
    async with retention_session(t.org_id) as s:
        found = await candidates(s, t.org_id, empty, now=datetime.now(UTC), limit=100)
    assert found.candidates == [] and all(c.candidates == 0 for c in found.counts.values())
    assert await worker_module.sweep() == 0  # not in retention_policy_index
    assert captured.enqueued == []


async def test_dry_run_equals_enforce(
    captured: Captured, aged: tuple[Registered, Tenant, AgedCase]
) -> None:
    reg, t, case = aged
    render_id, render_key, render_version = await proper_render(t, case)
    await seed_retention_policy(t, ti_results_days=30, ai_runs_days=30, closed_case_days=30)
    selected = await select_now(t.org_id)

    dry = await run_once(captured, t.org_id)
    dry_row = await run_row(t.org_id, dry)
    assert (dry_row.mode, dry_row.status, dry_row.trigger) == ("dry_run", "completed", "schedule")
    assert await items(t.org_id, dry) == []  # nothing locked or held: no item
    assert dry_row.sample and len(dry_row.sample) <= 3 * 50
    # Nothing was deleted by the dry run.
    assert await count(t.org_id, "SELECT count(*) FROM evidence_purges") == 0
    assert await count(t.org_id, "SELECT count(*) FROM network_flows") > 0

    await set_enforce(t, True)
    enforce = await run_once(captured, t.org_id)
    row = await run_row(t.org_id, enforce)
    assert (row.mode, row.status, row.error) == ("enforce", "completed", None)
    for category in ("ti_results", "ai_runs", "closed_case"):
        for name in ("candidates", "rows", "bytes"):
            assert row.counts[category][name] == dry_row.counts[category][name], (category, name)
    purged = {
        (i["ref_table"], i["ref_id"])
        for i in await items(t.org_id, enforce)
        if i["outcome"] == "purged" and i["category"] == "closed_case"
    }
    assert purged == {
        (c.ref_table, c.ref_id) for c in selected.candidates if c.category == "closed_case"
    }
    # What was selected for TI and AI is gone, nothing else.
    ai_ids = [uuid.UUID(c.ref_id) for c in selected.candidates if c.category == "ai_runs"]
    assert set(ai_ids) == {case.ai_parent_run_id, case.ai_child_run_id}
    assert await count(t.org_id, "SELECT count(*) FROM ai_runs WHERE id = ANY(:i)", i=ai_ids) == 0
    # The TI answer reused by a recent `cached` item stays (RT10).
    assert not [c for c in selected.candidates if c.category == "ti_results"]
    assert await count(t.org_id, "SELECT count(*) FROM ti_results") == 1

    # The rendition stored at its real key is gone; the snapshot is untouched.
    assert not version_present(reports_test_bucket(), render_key, render_version)
    async with tenant_session(t.org_id, None) as s:
        status = (
            await s.execute(
                text("SELECT status FROM report_renders WHERE id = :r"), {"r": render_id}
            )
        ).scalar_one()
        snapshot = (
            await s.execute(
                text("SELECT object_key, object_version_id FROM report_versions WHERE id = :v"),
                {"v": case.version_id},
            )
        ).one()
    assert status == "purged"
    assert version_present(reports_test_bucket(), snapshot[0], snapshot[1])

    # Running enforce again finds nothing more (idempotent).
    again = await run_once(captured, t.org_id)
    assert (await run_row(t.org_id, again)).counts["closed_case"]["candidates"] == 0
    assert reg.user_id  # the owner stays usable for the evidence checks below


async def test_enforce_purges_bytes_and_keeps_the_record(
    captured: Captured, aged: tuple[Registered, Tenant, AgedCase]
) -> None:
    reg, t, case = aged
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(
            CorrelationKey(
                organization_id=t.org_id,
                investigation_id=case.investigation_id,
                evidence_id=case.pcap_evidence_id,
                job_id=case.pcap_job_id,
                kind="sha256",
                key="b" * 64,
                value_norm="b" * 64,
                source_table="evidence_hashes",
                source_id=str(case.pcap_evidence_id),
                first_seen=datetime.now(UTC),
                last_seen=datetime.now(UTC),
            )
        )
    kept_tables = ("evidence_hashes", "iocs", "analysis_findings", "correlation_keys")
    before = {
        table: await count(t.org_id, f"SELECT count(*) FROM {table}")  # noqa: S608
        for table in kept_tables
    }
    audit_before = await count(t.org_id, "SELECT count(*) FROM audit_logs")
    await seed_retention_policy(t, closed_case_days=30, enforce=True)
    run_id = await run_once(captured, t.org_id)

    run_items = await items(t.org_id, run_id)
    evidence_items = [i for i in run_items if i["ref_table"] == "evidence"]
    assert {i["ref_id"] for i in evidence_items} == {
        str(case.pcap_evidence_id),
        str(case.static_evidence_id),
    }
    assert all(i["outcome"] == "purged" and i["bytes"] > 0 for i in evidence_items)
    assert {i["ref_table"] for i in run_items} >= {
        "network_flows",
        "malware_strings",
        "analysis_jobs",
        "report_renders",
    }
    # The versions are gone.
    bucket, key, version = case.objects[0]
    assert not version_present(bucket, key, version)
    # The tombstone, custody (system actor) and audit.
    async with tenant_session(t.org_id, None) as s:
        tomb = (
            await s.execute(
                text("SELECT run_id, sha256 FROM evidence_purges WHERE evidence_id = :e"),
                {"e": case.pcap_evidence_id},
            )
        ).one()
        custody = (
            await s.execute(
                text(
                    "SELECT actor_id, details FROM evidence_custody_events "
                    "WHERE evidence_id = :e AND action = 'purged'"
                ),
                {"e": case.pcap_evidence_id},
            )
        ).one()
        audited = (
            (
                await s.execute(
                    text(
                        "SELECT action FROM audit_logs WHERE action IN "
                        "('evidence.purged', 'retention.run_completed') ORDER BY action"
                    )
                )
            )
            .scalars()
            .all()
        )
    assert tomb.run_id == run_id and len(tomb.sha256) == 64
    assert custody.actor_id == RETENTION_SYSTEM_USER_ID
    assert custody.details["run_id"] == str(run_id)
    assert custody.details["version_id"]
    assert sorted(set(audited)) == ["evidence.purged", "retention.run_completed"]
    assert await count(t.org_id, "SELECT count(*) FROM audit_logs") > audit_before
    # Bulk rows gone; hashes, IOCs, findings and correlation keys kept (RT9).
    assert await count(t.org_id, "SELECT count(*) FROM network_flows") == 0
    for table in kept_tables:
        assert await count(t.org_id, f"SELECT count(*) FROM {table}") == before[table], table  # noqa: S608

    # The API: 410 on download and verify, purged_at on the read, analyses refused.
    c = reg.client
    base = f"{API}/{t.org_id}/evidence/{case.pcap_evidence_id}"
    download = await c.get(f"{base}/download")
    assert download.status_code == 410, download.text
    body = download.json()["error"]
    assert body["code"] == "evidence_purged" and body["run_id"] == str(run_id)
    verify = await c.post(f"{base}/verify", headers=csrf(c))
    assert verify.status_code == 410
    detail = (await c.get(base)).json()
    assert detail["purged_at"] is not None and detail["hashes"]["sha256"] == tomb.sha256
    # M7 follow-up: the purging run is named on the read (and on the list).
    assert detail["purged_by_run_id"] == str(run_id)
    listed = (
        await c.get(f"{API}/{t.org_id}/investigations/{case.investigation_id}/evidence")
    ).json()
    assert all(e["purged_at"] for e in listed["items"])
    assert {e["purged_by_run_id"] for e in listed["items"]} == {str(run_id)}
    custody_page = (await c.get(f"{base}/custody")).json()
    assert "purged" in [e["action"] for e in custody_page["items"]]
    # Another org still gets 404 (the org check comes first).
    outsider = await register(org_name="Outsider")
    assert (
        await outsider.client.get(f"{API}/{t.org_id}/evidence/{case.pcap_evidence_id}/download")
    ).status_code == 404

    # A purged render frees its slot: the same version and format renders again (RT11).
    rerender, _ = await seed_render(t, case.version_id, fmt="pdf")
    assert rerender != case.render_id


async def test_purged_evidence_refuses_an_analysis(
    captured: Captured, aged: tuple[Registered, Tenant, AgedCase]
) -> None:
    reg, t, case = aged
    await seed_retention_policy(t, closed_case_days=30, enforce=True)
    await run_once(captured, t.org_id)
    response = await reg.client.post(
        f"{API}/{t.org_id}/evidence/{case.static_evidence_id}/analyses",
        json={"analyzer": "static"},
        headers=csrf(reg.client),
    )
    assert response.status_code == 410, response.text
    assert response.json()["error"]["code"] == "evidence_purged"


async def test_manual_enforce_before_the_delay_runs_dry(
    captured: Captured, aged: tuple[Registered, Tenant, AgedCase]
) -> None:
    reg, t, _ = aged
    # Enforce requested, not yet effective (RT1).
    await seed_retention_policy(t, closed_case_days=30, pending_enforce=True)
    c = reg.client
    response = await c.post(f"{API}/{t.org_id}/retention/runs", json={}, headers=csrf(c))
    assert response.status_code == 202, response.text
    assert response.json()["mode"] == "dry_run"
    run_id = uuid.UUID(response.json()["id"])
    assert captured.published == [
        ("retention.run_org", {"org_id": str(t.org_id), "run_id": str(run_id)})
    ]
    assert (await worker_module.run_org(t.org_id, run_id)).status == "completed"
    # A run row that claims enforce (as if inserted directly) is downgraded and audited.
    async with tenant_session(t.org_id, t.owner_id) as s:
        forged = RetentionRun(
            organization_id=t.org_id,
            mode="enforce",
            trigger="manual",
            requested_by=t.owner_id,
            policy={},
        )
        s.add(forged)
    outcome = await worker_module.run_org(t.org_id, forged.id)
    row = await run_row(t.org_id, forged.id)
    assert (outcome.status, row.error) == ("completed", "enforce_not_effective")
    assert await count(t.org_id, "SELECT count(*) FROM evidence_purges") == 0
    assert (
        await count(
            t.org_id, "SELECT count(*) FROM audit_logs WHERE action = 'retention.run_downgraded'"
        )
        == 1
    )


async def test_the_sweep_finds_orgs_through_the_policy_index(captured: Captured) -> None:
    _, a = await owner_tenant("Sweep A")
    _, b = await owner_tenant("Sweep B")
    _, c = await owner_tenant("Sweep C")  # no policy: no run
    await seed_retention_policy(a, ti_results_days=90)
    await seed_retention_policy(b, ai_runs_days=60)
    assert await worker_module.sweep() == 2
    assert {o for o, _ in captured.enqueued} == {a.org_id, b.org_id}
    # One run per org at a time: a second sweep schedules nothing while they are queued.
    assert await worker_module.sweep() == 0
    for org_id, run_id in captured.enqueued:
        assert (await worker_module.run_org(org_id, run_id)).status == "completed"
    assert c.org_id not in {o for o, _ in captured.enqueued}
    # A message for an org outside the index is dropped.
    assert (await worker_module.run_org(c.org_id, uuid.uuid4())).status == "failed"


async def test_a_failed_delete_is_retried_by_the_next_run(
    captured: Captured, aged: tuple[Registered, Tenant, AgedCase], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, t, case = aged
    await seed_retention_policy(t, closed_case_days=30, enforce=True)
    real_delete = objects.delete_version
    evidence_bucket = evidence_test_bucket()

    async def failing(bucket: str, key: str, version_id: str) -> None:
        if bucket == evidence_bucket:
            raise S3Error(None, "InternalError", "injected", key, "req", "host")  # type: ignore[arg-type]
        await real_delete(bucket, key, version_id)

    monkeypatch.setattr(objects, "delete_version", failing)
    first = await run_once(captured, t.org_id)
    row = await run_row(t.org_id, first)
    assert row.status == "partial"
    failed = [i for i in await items(t.org_id, first) if i["outcome"] == "object_delete_failed"]
    assert {i["ref_id"] for i in failed} == {
        str(case.pcap_evidence_id),
        str(case.static_evidence_id),
    }
    assert await count(t.org_id, "SELECT count(*) FROM evidence_purges") == 2
    bucket, key, version = case.objects[0]
    assert version_present(bucket, key, version)

    # The reconcile script sees a pending delete, not an orphan or a missing version (RT22).
    async with tenant_session(t.org_id, None) as s:
        conn = await s.connection()
        recorded = await reconcile_orphans.recorded_versions(
            conn, reconcile_orphans.EVIDENCE_RECORDS
        )
        purged = await reconcile_orphans.recorded_versions(
            conn, reconcile_orphans.EVIDENCE_TOMBSTONES
        )
    stored = await reconcile_orphans.stored_versions(bucket, f"{t.org_id}/")
    report = reconcile_orphans.compare(bucket, stored, recorded, purged)
    assert {(o["key"], o["version_id"]) for o in report["purged_pending_delete"]} >= {
        (key, version)
    }
    assert report["orphaned_versions"] == [] and report["missing_unexplained"] == []

    monkeypatch.setattr(objects, "delete_version", real_delete)
    second = await run_once(captured, t.org_id)
    assert (await run_row(t.org_id, second)).status == "completed"
    retried = [i for i in await items(t.org_id, second) if i["ref_table"] == "evidence"]
    assert {(i["ref_id"], i["outcome"]) for i in retried} == {
        (str(case.pcap_evidence_id), "purged"),
        (str(case.static_evidence_id), "purged"),
    }
    assert not version_present(bucket, key, version)
    stored = await reconcile_orphans.stored_versions(bucket, f"{t.org_id}/")
    report = reconcile_orphans.compare(bucket, stored, recorded, purged)
    assert report["purged_pending_delete"] == [] and report["missing_unexplained"] == []


async def test_a_pinned_version_missing_without_a_tombstone_is_unexplained(
    captured: Captured, aged: tuple[Registered, Tenant, AgedCase]
) -> None:
    _, t, case = aged
    bucket, key, version = case.objects[0]
    root_minio().remove_object(bucket, key, version_id=version)  # outside retention (RT5)
    async with tenant_session(t.org_id, None) as s:
        conn = await s.connection()
        recorded = await reconcile_orphans.recorded_versions(
            conn, reconcile_orphans.EVIDENCE_RECORDS
        )
        purged = await reconcile_orphans.recorded_versions(
            conn, reconcile_orphans.EVIDENCE_TOMBSTONES
        )
    stored = await reconcile_orphans.stored_versions(bucket, f"{t.org_id}/")
    report = reconcile_orphans.compare(bucket, stored, recorded, purged)
    assert report["missing_unexplained"] == [{"key": key, "version_id": version}]
    assert report["purged_pending_delete"] == []


async def test_a_governance_locked_version_is_skipped(
    captured: Captured, aged: tuple[Registered, Tenant, AgedCase]
) -> None:
    _, t, case = aged
    bucket, key, version = case.objects[0]  # the pcap evidence
    until = datetime.now(UTC) + timedelta(days=1)
    root_minio().set_object_retention(bucket, key, Retention(GOVERNANCE, until), version_id=version)
    await seed_retention_policy(t, closed_case_days=30)
    dry = await run_once(captured, t.org_id)
    dry_items = await items(t.org_id, dry)
    assert [(i["ref_id"], i["outcome"]) for i in dry_items] == [
        (str(case.pcap_evidence_id), "skipped_locked")
    ]
    await set_enforce(t, True)
    run_id = await run_once(captured, t.org_id)
    by_ref = {i["ref_id"]: i["outcome"] for i in await items(t.org_id, run_id)}
    assert by_ref[str(case.pcap_evidence_id)] == "skipped_locked"
    assert by_ref[str(case.static_evidence_id)] == "purged"
    assert version_present(bucket, key, version)
    assert (
        await count(
            t.org_id,
            "SELECT count(*) FROM evidence_purges WHERE evidence_id = :e",
            e=case.pcap_evidence_id,
        )
        == 0
    )
    row = await run_row(t.org_id, run_id)
    assert row.counts["closed_case"]["skipped_locked"] == 1
    assert get_settings().evidence_lock_days == 0  # the test env locks nothing by default
