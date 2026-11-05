"""IDOR cases owned by M6 phase 4 (report renditions and downloads).

The victim extender seeds, in the victim org, a report with a signed version (snapshot in
`reports-test`) and a succeeded PDF render whose artifact is stored at its key. The four
rendition routes point at those through `PATH_OVERRIDES` (keys `render_report_id`,
`render_version`, `render_id`), so they do not depend on the report extender of phase 3.
The owner's POST is deduplicated onto the existing render (200, nothing dispatched); the
state hook proves an attacker created no render.
"""

import hashlib
import io
import uuid
from datetime import UTC, datetime
from typing import Any

from cyberlab_jobs.report import RENDER_CONTENT_TYPES
from sqlalchemy import select, update

from app.core.clients import get_minio
from app.core.tenancy import tenant_session
from app.modules.reports import dispatch
from app.modules.reports.models import ReportRender, ReportRenderIndex
from tests.factories import Registered
from tests.integration.seed import Tenant
from tests.report_helpers import (
    new_signing_keys,
    reports_test_bucket,
    seed_render,
    seed_report,
    seed_version,
)
from tests.security.idor_types import (
    PathOverrides,
    RouteCases,
    StateHook,
    Victim,
    VictimExtender,
)

_ORG = "/api/v1/orgs/{org_id}"
_RENDERS = f"{_ORG}/reports/{{report_id}}/versions/{{version}}/renders"
_RENDER = f"{_ORG}/report-renders/{{render_id}}"
ARTIFACT = b"%PDF-1.7 victim rendition"

ROUTE_CASES: RouteCases = {
    ("POST", _RENDERS): lambda v: {"json": {"format": "pdf"}},
    ("GET", _RENDERS): lambda v: {},
    ("GET", _RENDER): lambda v: {},
    ("GET", f"{_RENDER}/download"): lambda v: {},
}


def _version_params(victim: Victim) -> dict[str, str]:
    return {
        "report_id": victim.extra["render_report_id"],
        "version": victim.extra["render_version"],
    }


def _render_params(victim: Victim) -> dict[str, str]:
    return {"render_id": victim.extra["render_id"]}


PATH_OVERRIDES: PathOverrides = {
    _RENDERS: _version_params,
    _RENDER: _render_params,
    f"{_RENDER}/download": _render_params,
}
RESOURCE_PARAMS: tuple[str, ...] = ("{render_id}", "{report_id}")


async def _extend(owner: Registered, victim: Victim) -> dict[str, str]:
    tenant = Tenant(victim.org_id, owner.user_id, uuid.UUID(victim.investigation_id))
    report_id = await seed_report(tenant, title="Victim report")
    version = await seed_version(tenant, report_id, new_signing_keys())
    render_id, _ = await seed_render(tenant, version.version_id, fmt="pdf")
    key = dispatch.render_key(victim.org_id, report_id, version.version, render_id, "pdf")
    put = get_minio().put_object(
        reports_test_bucket(),
        key,
        io.BytesIO(ARTIFACT),
        len(ARTIFACT),
        content_type=RENDER_CONTENT_TYPES["pdf"],
    )
    async with tenant_session(victim.org_id, owner.user_id) as session:
        render = await session.get(ReportRender, render_id)
        assert render is not None
        render.status = "running"
        await session.flush()
        render.status = "succeeded"
        render.sha256 = hashlib.sha256(ARTIFACT).hexdigest()
        render.bytes = len(ARTIFACT)
        render.pages = 1
        render.object_version_id = str(put.version_id)
        render.renderer_version = "report-worker/idor"
        render.finished_at = datetime.now(UTC)
        await session.execute(
            update(ReportRenderIndex)
            .where(ReportRenderIndex.render_id == render_id)
            .values(status="succeeded")
        )
    return {
        "render_report_id": str(report_id),
        "render_version": str(version.version),
        "render_id": str(render_id),
    }


async def _renders(owner: Registered, victim: Victim) -> dict[str, Any]:
    async with tenant_session(victim.org_id, None) as session:
        rows = (
            await session.execute(
                select(ReportRender.id, ReportRender.format, ReportRender.status).order_by(
                    ReportRender.id
                )
            )
        ).all()
    return {"report_renders": [(str(i), f, s) for i, f, s in rows]}


VICTIM_EXTENDERS: list[VictimExtender] = [_extend]
STATE_HOOKS: list[StateHook] = [_renders]
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset()
