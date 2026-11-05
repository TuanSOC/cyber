"""Render creation and dispatch (frozen entry points of M6 phase 1; implemented by phase 4).

- `create_render` (in the caller's tenant transaction): dedupe on (version, format,
  renderer version), the per-org / global active caps under advisory locks
  (`409 render_busy`), a `report_renders` row (`queued`, token hash) and its
  `report_render_index` row (deadline REPORT_RENDER_DEADLINE_S).
- `dispatch_render` (after the commit): builds `ReportRenderMessageV1` (presigned GET of the
  exact snapshot version, presigned POST for the artifact, manifest, signature, kid,
  `finalized_at`, token, deadline) and sends `report.render`. A publish failure leaves the
  render `queued` for the reaper.

Phase 3's finalize calls both (the PDF only, RT5); its lane monkeypatches them.
"""

import uuid
from collections.abc import Sequence

from cyberlab_jobs.report import RenderFormat
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.reports.models import ReportRender, ReportVersion


async def create_render(
    session: AsyncSession,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    version: ReportVersion,
    fmt: RenderFormat,
) -> ReportRender:
    """Phase 4."""
    raise NotImplementedError("reports.dispatch.create_render lands in M6 phase 4")


async def dispatch_render(render_ids: Sequence[uuid.UUID]) -> None:
    """Phase 4."""
    raise NotImplementedError("reports.dispatch.dispatch_render lands in M6 phase 4")
