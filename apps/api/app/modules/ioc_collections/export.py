"""IOC collection exports (M6): CSV, JSON and a STIX 2.1 bundle.

- Every export is marked with the case's TLP (the CSV header line, the JSON `tlp`, the STIX
  marking-definition) and is **never redacted**: internal IPs and names stay in clear (the
  `external` profile applies to reports only, RT8). The response says so
  (`X-Export-Redacted: false`), as the UI does.
- Values are defanged by default; `defang=false` (the only clear-text form) needs
  `evidence.write`, and a refused attempt is audited `ioc_collection.export_refused`. A
  defanged JSON export carries each TI answer without its raw provider `summary` (free
  provider JSON that can repeat the value, related hosts or URLs in clear); the clear-text
  export keeps it.
- CSV cells go through `core.csv_safe` (formula-injection safe, RFC 4180 quoting).
- Served as a streamed attachment (RFC 5987 filename, `nosniff`, `no-store`,
  `Content-Security-Policy: sandbox`) and audited `ioc_collection.exported` (format, count,
  defang).
"""

import json
import re
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime

from cyberlab_jobs.report import TLP, TLP_LABELS
from sqlalchemy import select
from starlette.requests import HTTPConnection

from app.core.csv_safe import write_csv
from app.core.errors import Forbidden, NotFound
from app.core.rbac import ROLE_PERMISSIONS, OrgContext, Permission
from app.modules.audit import service as audit
from app.modules.investigations.schemas import case_ref
from app.modules.ioc_collections import service, stix
from app.modules.ioc_collections.normalize import defang as defang_value
from app.modules.ioc_collections.normalize import ti_eligible
from app.modules.ioc_collections.schemas import ExportFormat, IocExportJson
from app.modules.organizations.models import Organization

CSV_HEADER = ("type", "value", "ioc_key", "source", "job_id", "note", "added_at", "ti_eligible")
CONTENT_TYPES: dict[str, str] = {
    "csv": "text/csv; charset=utf-8",
    "json": "application/json",
    "stix21": "application/stix+json;version=2.1",
}
EXTENSIONS = {"csv": "csv", "json": "json", "stix21": "stix.json"}
_SLUG = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(frozen=True)
class Export:
    chunks: Iterator[bytes]
    filename: str
    content_type: str
    count: int
    skipped: int


def _filename(case_number: int, name: str, fmt: str, tlp: TLP) -> str:
    slug = _SLUG.sub("-", name).strip("-.")[:60] or "collection"
    label = TLP_LABELS[tlp].replace(":", "-").replace("+", "-")
    return f"{case_ref(case_number)}_{slug}_{label}.{EXTENSIONS[fmt]}"


async def export_collection(
    ctx: OrgContext,
    collection_id: uuid.UUID,
    *,
    fmt: ExportFormat,
    defang: bool,
    request: HTTPConnection,
) -> Export:
    row = await service.get_row(ctx.session, ctx.org_id, collection_id)
    if not defang and Permission.EVIDENCE_WRITE not in ROLE_PERMISSIONS[ctx.role]:
        audit.record(
            ctx.session,
            action="ioc_collection.export_refused",
            org_id=ctx.org_id,
            actor_id=ctx.user.id,
            target_type="ioc_collection",
            target_id=row.collection.id,
            details={
                "investigation_id": str(row.collection.investigation_id),
                "format": fmt,
                "defang": False,
                "reason": "missing_permission",
            },
            request=request,
        )
        await ctx.session.commit()
        raise Forbidden("A clear-text (defang=false) export needs evidence.write")
    collection, case = row.collection, row.case
    tlp = TLP(case.tlp)
    rows = await service.item_rows(ctx.session, ctx.org_id, collection_id)
    rows.reverse()  # oldest first in an export
    exported_at = datetime.now(UTC)
    shown = [
        (item, name, defang_value(item.ioc_type, item.value_norm) if defang else item.value_norm)
        for item, name in rows
    ]
    skipped = 0
    if fmt == "csv":
        comment = (
            f"# {TLP_LABELS[tlp]} {case_ref(case.case_number)} IOC collection "
            f"{json.dumps(collection.name, ensure_ascii=False)} exported "
            f"{exported_at.isoformat()} by {ctx.user.id}; not redacted; "
            f"{'defanged' if defang else 'NOT defanged'}"
        )
        lines = [
            (
                item.ioc_type,
                value,
                item.ioc_key,
                item.source,
                item.job_id or "",
                item.note or "",
                item.added_at.isoformat(),
                "true" if ti_eligible(item.ioc_type, item.value_norm) else "false",
            )
            for item, _, value in shown
        ]
        chunks = write_csv([CSV_HEADER, *lines], header_comment=comment)
    elif fmt == "json":
        ti = await service.ti_summaries(ctx.session, ctx.org_id, [i.ioc_key for i, _ in rows])
        if defang:
            # Raw provider JSON is not defanged: a defanged export leaves it out.
            ti = {
                key: [answer.model_copy(update={"summary": None}) for answer in answers]
                for key, answers in ti.items()
            }
        body = IocExportJson(
            tlp=tlp,
            collection=service.collection_out(row),
            exported_at=exported_at,
            defanged=defang,
            items=[
                service.item_out(item, name, ti.get(item.ioc_key, []), value=value)
                for item, name, value in shown
            ],
        )
        chunks = iter([body.model_dump_json().encode()])
    else:
        org = await ctx.session.scalar(select(Organization).where(Organization.id == ctx.org_id))
        if org is None:  # never: the caller is a member of it
            raise NotFound()
        built = stix.build_bundle(
            org_id=ctx.org_id,
            org_name=org.name,
            org_created_at=org.created_at,
            collection_id=collection.id,
            collection_name=collection.name,
            tlp=tlp,
            items=[
                stix.StixItem(
                    item.ioc_type, item.value_norm, item.ioc_key, item.added_at, item.note
                )
                for item, _ in rows
            ],
            exported_at=exported_at,
            defang=defang,
        )
        skipped = built.skipped
        chunks = iter([json.dumps(built.bundle, ensure_ascii=False).encode()])

    audit.record(
        ctx.session,
        action="ioc_collection.exported",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="ioc_collection",
        target_id=collection.id,
        details={
            "investigation_id": str(collection.investigation_id),
            "format": fmt,
            "count": len(rows) - skipped,
            "skipped": skipped,
            "defang": defang,
            "tlp": tlp.value,
            "redacted": False,
        },
        request=request,
    )
    await ctx.session.commit()
    return Export(
        chunks=chunks,
        filename=_filename(case.case_number, collection.name, fmt, tlp),
        content_type=CONTENT_TYPES[fmt],
        count=len(rows) - skipped,
        skipped=skipped,
    )
