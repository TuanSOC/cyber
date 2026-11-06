"""M7 plumbing, final state: every M7 route exists and none is a 501 stub any more
(membership first, bodies validated), the `/internal/metrics` access rules, the worker and
beat registrations, the purge MinIO user's policy, SSE-S3 on the buckets and the M7 test
helpers."""

import inspect
import io
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.routing import APIRoute
from minio.commonconfig import GOVERNANCE
from minio.deleteobjects import DeleteObject
from minio.error import S3Error
from minio.retention import Retention
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.main import app
from app.modules.ops import internal
from app.workers import retention, retention_tasks  # noqa: F401 (registers the tasks)
from app.workers import tasks as ingest_tasks
from app.workers.celery_app import celery_app
from app.workers.retention_app import celery_app as retention_celery
from tests.factories import Registered, csrf, new_client, register
from tests.integration.seed import seed_tenant
from tests.ops_helpers import (
    SHARED_IOCS,
    purge_minio,
    seed_aged_closed_case,
    seed_correlated_jobs,
    seed_job_outcomes,
)
from tests.report_helpers import purge_reports_test_bucket, reports_test_bucket
from tests.security import (
    idor_cases_correlation,
    idor_cases_memory,
    idor_cases_memory_sensitivity,
    idor_cases_ops,
    idor_cases_retention,
)
from tests.storage_helpers import evidence_test_bucket, lane_key, purge_test_bucket, root_minio

M7_MODULES = (idor_cases_retention, idor_cases_correlation, idor_cases_ops)
# M8 phase 1 froze its routes as 501 stubs (phases 7 and 8 land them): the only stubs allowed.
M8_PENDING_PATHS = frozenset(
    path
    for module in (idor_cases_memory, idor_cases_memory_sensitivity)
    for _, path in module.PENDING_ROUTES
)
ORG = "/api/v1/orgs/{org_id}"


def _org_routes() -> set[tuple[str, str]]:
    return {
        (method.upper(), path)
        for path, item in app.openapi()["paths"].items()
        if path.startswith("/api/v1/orgs/{org_id}")
        for method in item
    }


def test_every_m7_route_exists_and_none_is_pending() -> None:
    routes = frozenset().union(*(module.ROUTE_CASES for module in M7_MODULES))
    assert len(routes) == 14
    assert routes <= _org_routes(), sorted(routes - _org_routes())
    assert all(not module.PENDING_ROUTES for module in M7_MODULES)


def test_no_route_still_raises_the_501_stub() -> None:
    """Generic over the route table: no endpoint body raises `not_implemented()` any more
    (every frozen M6 / M7 stub has been replaced by its phase)."""
    stubbed = sorted(
        route.path
        for route in app.routes
        if isinstance(route, APIRoute)
        and "not_implemented(" in inspect.getsource(route.endpoint)
        and route.path not in M8_PENDING_PATHS
    )
    assert not stubbed, stubbed


def _body(user: Registered, body: dict[str, Any] | None) -> dict[str, Any]:
    return {"json": body, "headers": csrf(user.client)} if body is not None else {}


async def test_m7_routes_check_membership_first_and_none_answers_501() -> None:
    owner = await register(org_name="M7 Org")
    outsider = await register(org_name="Outsider Org")
    base = ORG.format(org_id=owner.org_id)
    job, case, run, hold = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    requests: list[tuple[str, str, dict[str, Any] | None]] = [
        ("GET", f"{base}/retention/policy", None),
        (
            "PUT",
            f"{base}/retention/policy",
            {
                "ti_results_days": 90,
                "ai_runs_days": None,
                "closed_case_days": None,
                "enforce": False,
            },
        ),  # fmt: skip
        ("POST", f"{base}/retention/preview", {}),
        ("GET", f"{base}/retention/runs", None),
        ("GET", f"{base}/retention/runs/{run}", None),
        ("POST", f"{base}/retention/runs", {}),
        ("GET", f"{base}/legal-holds", None),
        ("POST", f"{base}/legal-holds", {"scope": "org", "reason": "Litigation"}),
        ("POST", f"{base}/legal-holds/{hold}/release", {"reason": "Done"}),
        ("GET", f"{base}/analyses/{job}/correlations", None),
        ("POST", f"{base}/correlations/lookup", {"kind": "domain", "value": "example.com"}),
        ("GET", f"{base}/investigations/{case}/related", None),
        ("POST", f"{base}/search", {"q": "beacon"}),
        ("GET", f"{base}/ops/metrics?window=7d", None),
    ]
    anonymous = new_client()
    for method, url, body in requests:
        other = await outsider.client.request(method, url, **_body(outsider, body))
        assert other.status_code == 404, (method, url)
        assert (await anonymous.request(method, url, json=body)).status_code in (401, 403)
        if method == "GET" or url.endswith(("/search", "/correlations/lookup")):
            # The owner's reads (no side effects): implemented, whatever they answer.
            response = await owner.client.request(method, url, **_body(owner, body))
            assert response.status_code != 501, (method, url, response.text)
            assert response.status_code < 500, (method, url, response.text)


@pytest.mark.parametrize(
    ("url", "body"),
    [
        ("/search", {"q": ""}),
        ("/search", {"q": "x", "types": ["everything"]}),
        ("/search", {"q": "x", "extra": 1}),
        ("/legal-holds", {"scope": "investigation", "investigation_id": None, "reason": "x"}),
        ("/legal-holds", {"scope": "org", "reason": "   "}),
        ("/retention/policy", {"ti_results_days": 90}),
        ("/retention/preview", {"ti_results_days": 0}),
    ],
)
async def test_m7_bodies_are_validated(url: str, body: dict[str, object]) -> None:
    owner = await register(org_name="M7 Org")
    method = "PUT" if url == "/retention/policy" else "POST"
    response = await owner.client.request(
        method, ORG.format(org_id=owner.org_id) + url, json=body, headers=csrf(owner.client)
    )
    assert response.status_code == 422, response.text


@pytest.fixture
def metrics_token(tmp_path: Path) -> Iterator[str]:
    token = "test-metrics-token-" + uuid.uuid4().hex
    path = tmp_path / "metrics_token"
    path.write_text(token + "\n", encoding="utf-8")
    settings = get_settings()
    previous = settings.metrics_token_file
    settings.metrics_token_file = str(path)
    internal.metrics_token.cache_clear()
    yield token
    settings.metrics_token_file = previous
    internal.metrics_token.cache_clear()


async def test_internal_metrics_is_off_without_a_token() -> None:
    internal.metrics_token.cache_clear()
    response = await new_client().get("/internal/metrics", headers={"Authorization": "Bearer x"})
    assert response.status_code == 404


async def test_internal_metrics_needs_the_bearer_token(metrics_token: str) -> None:
    client = new_client()
    assert (await client.get("/internal/metrics")).status_code == 401
    bad = await client.get("/internal/metrics", headers={"Authorization": "Bearer wrong"})
    assert bad.status_code == 401
    good = {"Authorization": f"Bearer {metrics_token}"}
    # Defence in depth: never answered for a proxied request (the gateway never forwards it).
    proxied = await client.get("/internal/metrics", headers={**good, "X-Forwarded-For": "1.2.3.4"})
    assert proxied.status_code == 403
    response = await client.get("/internal/metrics", headers=good)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "/internal/metrics" not in {p for p in app.openapi()["paths"] if p.startswith("/api")}


def test_worker_registrations() -> None:
    schedule = celery_app.conf.beat_schedule
    assert schedule["index-correlation-keys"]["task"] == "correlation.index_pending"
    assert schedule["index-correlation-keys"]["schedule"] == 60.0
    assert schedule["retention-sweep"]["task"] == "retention.sweep"
    assert schedule["retention-sweep"]["options"]["queue"].endswith("retention")
    assert ingest_tasks.correlation_index_pending.name == "correlation.index_pending"
    assert "correlation.index_pending" in celery_app.tasks
    names = set(retention_celery.tasks)
    assert {"retention.sweep", "retention.run_org", "retention.sync_holds"} <= names
    assert retention_celery.conf.task_default_queue.endswith("retention")


# --- the purge MinIO user (RT5) and SSE-S3 ----------------------------------------------


def test_purge_user_policy() -> None:
    bucket = evidence_test_bucket()
    purge = purge_minio()
    key = lane_key(f"purge-probe/{uuid.uuid4()}")
    stored = root_minio().put_object(bucket, key, io.BytesIO(b"probe"), 5)
    try:
        with pytest.raises(S3Error, match="AccessDenied|Access Denied"):
            purge.put_object(bucket, lane_key(f"purge-probe/{uuid.uuid4()}"), io.BytesIO(b"x"), 1)
        with pytest.raises(S3Error, match="AccessDenied|Access Denied"):
            purge.set_object_retention(
                bucket,
                key,
                Retention(GOVERNANCE, datetime.now(UTC) + timedelta(days=1)),
                version_id=stored.version_id,
            )
        assert purge.stat_object(bucket, key, version_id=stored.version_id).size == 5
        listed = [
            o.version_id for o in purge.list_objects(bucket, prefix=key, include_version=True)
        ]
        assert listed == [stored.version_id]
        # The hold sync (RT5): set and clear an S3 legal hold.
        purge.enable_object_legal_hold(bucket, key, version_id=stored.version_id)
        assert purge.is_object_legal_hold_enabled(bucket, key, version_id=stored.version_id)
        with pytest.raises(S3Error):
            purge.remove_object(bucket, key, version_id=stored.version_id)  # held
        purge.disable_object_legal_hold(bucket, key, version_id=stored.version_id)
        # A locked version: no governance bypass for this user.
        until = datetime.now(UTC) + timedelta(days=1)
        root_minio().set_object_retention(
            bucket, key, Retention(GOVERNANCE, until), version_id=stored.version_id
        )
        with pytest.raises(S3Error):
            purge.remove_object(bucket, key, version_id=stored.version_id)
        errors = list(
            purge.remove_objects(
                bucket, [DeleteObject(key, stored.version_id)], bypass_governance_mode=True
            )
        )
        assert errors, "the purge user must not bypass governance retention"
        assert root_minio().stat_object(bucket, key, version_id=stored.version_id).size == 5
    finally:
        purge_test_bucket()


def test_purge_user_cannot_delete_a_report_snapshot() -> None:
    bucket = reports_test_bucket()
    key = lane_key(f"{uuid.uuid4()}/{uuid.uuid4()}/1/snapshot.json")
    stored = root_minio().put_object(bucket, key, io.BytesIO(b"{}"), 2)
    rendition = root_minio().put_object(bucket, f"{key}.pdf", io.BytesIO(b"%PDF"), 4)
    try:
        with pytest.raises(S3Error, match="AccessDenied|Access Denied"):
            purge_minio().remove_object(bucket, key, version_id=stored.version_id)
        # Any other object of an expired lock may go (the renditions).
        purge_minio().remove_object(bucket, f"{key}.pdf", version_id=rendition.version_id)
    finally:
        purge_reports_test_bucket()


@pytest.mark.parametrize("which", ["evidence", "results", "reports"])
def test_every_bucket_has_sse_s3(which: str) -> None:
    settings = get_settings()
    bucket = {
        "evidence": settings.minio_bucket,
        "results": settings.results_bucket,
        "reports": settings.reports_bucket,
    }[which]
    config = root_minio().get_bucket_encryption(bucket)
    assert config is not None
    assert config.rule.sse_algorithm == "AES256"


# --- the M7 helpers ---------------------------------------------------------------------


async def test_the_aged_case_helper_seeds_every_category() -> None:
    t = await seed_tenant("aged")
    try:
        aged = await seed_aged_closed_case(t)
    finally:
        purge_reports_test_bucket()
    async with tenant_session(t.org_id, None) as s:
        status = (
            await s.execute(
                text("SELECT status FROM investigations WHERE id = :i"),
                {"i": aged.investigation_id},
            )
        ).scalar_one()
        flows = (await s.execute(text("SELECT count(*) FROM network_flows"))).scalar_one()
        strings = (await s.execute(text("SELECT count(*) FROM malware_strings"))).scalar_one()
        cached = (
            await s.execute(text("SELECT count(*) FROM ti_run_items WHERE state = 'cached'"))
        ).scalar_one()
        children = (
            await s.execute(text("SELECT count(*) FROM ai_runs WHERE parent_run_id IS NOT NULL"))
        ).scalar_one()
        render = (
            await s.execute(
                text("SELECT status FROM report_renders WHERE id = :r"), {"r": aged.render_id}
            )
        ).scalar_one()
    assert (str(status), render, cached, children) == ("closed", "succeeded", 1, 1)
    assert flows > 0 and strings > 0
    assert len(aged.objects) >= 4  # two evidence objects, the rendition, the results


async def test_the_correlation_and_outcome_helpers(owner_engine: AsyncEngine) -> None:
    seed = await seed_correlated_jobs()
    async with tenant_session(seed.org_a.org_id, None) as s:
        values = (await s.execute(text("SELECT count(*) FROM iocs"))).scalar_one()
    assert values == 2 * len(SHARED_IOCS)
    await seed_job_outcomes(
        owner_engine,
        [
            {"kind": "pcap", "status": "succeeded", "queue_ms": 10, "run_ms": 900},
            {"kind": "static", "status": "failed", "error_code": "timed_out"},
        ],
    )
    async with tenant_session(None, None) as s:
        assert (await s.execute(text("SELECT count(*) FROM job_outcomes"))).scalar_one() == 2
