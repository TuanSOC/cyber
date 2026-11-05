"""Evaluation cases: committed snapshots of normalized result rows (M5 phase 6).

A case (`tests/fixtures/ai_eval/cases/<name>.json`) holds, for one job (or one investigation
of several jobs), the rows of every result table the context builder reads, in exactly the
table shapes ingest writes (`pcap_analysis.ingest.to_row` / `static_analysis.ingest.to_row`),
plus synthetic `ti_results` rows for its IOCs and, for an injected twin, where each payload was
planted. `seed_case` loads one into a fresh org (tenant-session inserts, RLS on), so the real
builder runs unmodified over it.

Row ids are deterministic per seed: `salt (8 bytes) | group | job | row`, so rows sort by id in
case-file order whatever the salt (the builder breaks ties on `id`; the context hash, and with
it the replay cassette key, must not depend on the org). Every timestamp comes from the case,
never from `now()`, for the same reason.

Format `cyberlab.ai_eval.case.v1`:

    {format, name, clean (twin of, or null), kind (pcap|static|investigation), scenario,
     tasks [AiTask], provenance {source: hand-trimmed|pipeline, ...},
     investigation {title, description, severity, created_at},
     jobs [{key, analyzer, profile, evidence {filename, mime, description, size_bytes,
            uploaded_at}, created_at, finished_at, worker_version, summary,
            tables {table: [row]}}],
     ti [{job, ioc {type, value}, provider, status, found, score, score_scale, tags,
          families, attack_ids, summary, fetched_at}],
     plants [{payload, carrier, value, table?, job?, where?}]}
"""

import datetime as dt
import ipaddress
import json
import secrets
import struct
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from functools import cache
from pathlib import Path
from typing import Any, cast

from sqlalchemy import DateTime, Numeric, Table, insert
from sqlalchemy import Uuid as SaUuid

from app.core.tenancy import tenant_session
from app.modules.analysis.models import AnalysisJob, AnalysisStatus, Analyzer
from app.modules.evidence.models import CustodyAction, Evidence, EvidenceCustodyEvent
from app.modules.investigations.models import Investigation, Severity
from app.modules.pcap_analysis import models as pcap_models
from app.modules.static_analysis import models as static_models
from app.modules.threat_intel.models import TiEnrichmentRun, TiResult
from app.modules.threat_intel.normalize import Normalized, normalize
from app.modules.threat_intel.providers.base import IocType, compute_ioc_key
from app.modules.threat_intel.summaries import SUMMARY_MODELS
from tests.integration.seed import Tenant

FORMAT = "cyberlab.ai_eval.case.v1"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "ai_eval"
CASES_DIR = FIXTURES / "cases"
TWIN_SUFFIX = "__injected"

# Every result table a case may carry, in a fixed order (the id `group` of its rows).
RESULT_TABLES: tuple[Table, ...] = tuple(
    cast(Table, model.__table__)
    for model in (*pcap_models.RESULT_TABLES, *static_models.RESULT_TABLES)
)
TABLES: dict[str, Table] = {t.name: t for t in RESULT_TABLES}
FLOW_TABLE = "network_flows"
TI_TABLE = "ti_results"
FAR_FUTURE = dt.datetime(2099, 1, 1, tzinfo=dt.UTC)

_GROUP_INVESTIGATION = 1
_GROUP_EVIDENCE = 2
_GROUP_JOB = 3
_GROUP_TI_RUN = 4
_GROUP_TI = 5
_GROUP_CUSTODY = 6
_GROUP_ROWS = 16


class CaseError(Exception):
    """A malformed case or an ambiguous / unresolvable natural key (fail loudly)."""


# --- JSON <-> row values -----------------------------------------------------------------------


def to_json_value(value: Any) -> Any:
    """A row value as committed JSON (datetimes ISO 8601, uuids text, decimals ints)."""
    if isinstance(value, dt.datetime):
        return value.astimezone(dt.UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, Decimal):
        return int(value)
    if isinstance(value, dict):
        return {str(k): to_json_value(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [to_json_value(v) for v in value]
    return value


def to_json_row(row: Mapping[str, Any]) -> dict[str, Any]:
    return {k: to_json_value(v) for k, v in row.items() if k not in ("organization_id", "job_id")}


def parse_ts(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def from_json_row(table: Table, row: Mapping[str, Any]) -> dict[str, Any]:
    """Committed JSON -> insert values for `table` (unknown columns are a case error)."""
    out: dict[str, Any] = {}
    for name, value in row.items():
        column = table.columns.get(name)
        if column is None or name in ("id", "organization_id", "job_id"):
            raise CaseError(f"{table.name}: column {name!r} is not allowed in a case row")
        if value is not None and isinstance(column.type, DateTime):
            value = parse_ts(value)
        elif value is not None and isinstance(column.type, SaUuid):
            value = uuid.UUID(str(value))
        elif value is not None and isinstance(column.type, Numeric):
            value = Decimal(value)
        out[name] = value
    return out


# --- the case ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Case:
    name: str
    data: dict[str, Any]

    @property
    def clean(self) -> str | None:
        clean = self.data.get("clean")
        return str(clean) if clean else None

    @property
    def injected(self) -> bool:
        return self.clean is not None

    @property
    def base(self) -> str:
        """The clean case name (the golden file name) for both twins."""
        return self.clean or self.name

    @property
    def kind(self) -> str:
        return str(self.data["kind"])

    @property
    def tasks(self) -> list[str]:
        return [str(t) for t in self.data["tasks"]]

    @property
    def jobs(self) -> list[dict[str, Any]]:
        return cast(list[dict[str, Any]], self.data["jobs"])

    @property
    def plants(self) -> list[dict[str, Any]]:
        return cast(list[dict[str, Any]], self.data.get("plants", []))

    @property
    def ti(self) -> list[dict[str, Any]]:
        return cast(list[dict[str, Any]], self.data.get("ti", []))

    def job(self, key: str) -> dict[str, Any]:
        for job in self.jobs:
            if job["key"] == key:
                return job
        raise CaseError(f"{self.name}: no job {key!r}")

    def rows(self, job: str, table: str) -> list[dict[str, Any]]:
        return cast(list[dict[str, Any]], self.job(job)["tables"].get(table, []))

    def max_severity(self) -> str | None:
        """The highest stored finding severity over every job (None without findings)."""
        order = ("info", "low", "medium", "high")
        found = [
            row["severity"]
            for job in self.jobs
            for row in job["tables"].get("analysis_findings", [])
            if row.get("severity") in order
        ]
        return max(found, key=order.index) if found else None


def validate(data: Mapping[str, Any]) -> None:
    if data.get("format") != FORMAT:
        raise CaseError(f"{data.get('name')}: format must be {FORMAT}")
    for key in ("name", "kind", "tasks", "jobs", "investigation", "provenance"):
        if key not in data:
            raise CaseError(f"{data.get('name')}: missing {key!r}")
    keys = [job["key"] for job in data["jobs"]]
    if len(set(keys)) != len(keys) or not keys:
        raise CaseError(f"{data['name']}: job keys must be unique and non-empty")
    for job in data["jobs"]:
        Analyzer(job["analyzer"])
        for table in job["tables"]:
            if table not in TABLES:
                raise CaseError(f"{data['name']}: unknown table {table!r}")


@cache
def load_case(name: str, directory: Path = CASES_DIR) -> Case:
    path = directory / f"{name}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    validate(data)
    if data["name"] != name:
        raise CaseError(f"{path.name}: name {data['name']!r} does not match the file")
    return Case(name=name, data=data)


def case_names(directory: Path = CASES_DIR) -> list[str]:
    return sorted(p.stem for p in directory.glob("*.json"))


def clean_names(directory: Path = CASES_DIR) -> list[str]:
    return [n for n in case_names(directory) if not n.endswith(TWIN_SUFFIX)]


def _compact(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def dumps_case(data: Mapping[str, Any]) -> str:
    """Committed form: sorted keys, one row / TI entry / plant per line (reviewable diffs)."""
    lines = ["{"]
    keys = sorted(data)
    for n, key in enumerate(keys):
        end = "," if n < len(keys) - 1 else ""
        value = data[key]
        if key == "jobs":
            lines.append(' "jobs": [')
            for j, job in enumerate(value):
                lines.append("  {")
                job_keys = sorted(job)
                for m, jk in enumerate(job_keys):
                    jend = "," if m < len(job_keys) - 1 else ""
                    if jk == "tables":
                        lines.append('   "tables": {')
                        names = sorted(job[jk])
                        for t, name in enumerate(names):
                            rows = job[jk][name]
                            tend = "," if t < len(names) - 1 else ""
                            lines.append(f"    {_compact(name)}: [")
                            lines += [
                                f"     {_compact(r)}{',' if i < len(rows) - 1 else ''}"
                                for i, r in enumerate(rows)
                            ]
                            lines.append(f"    ]{tend}")
                        lines.append(f"   }}{jend}")
                    else:
                        lines.append(f"   {_compact(jk)}: {_compact(job[jk])}{jend}")
                lines.append("  }" + ("," if j < len(value) - 1 else ""))
            lines.append(f" ]{end}")
        elif key in ("ti", "plants") and value:
            lines.append(f" {_compact(key)}: [")
            lines += [
                f"  {_compact(v)}{',' if i < len(value) - 1 else ''}" for i, v in enumerate(value)
            ]
            lines.append(f" ]{end}")
        else:
            lines.append(f" {_compact(key)}: {_compact(value)}{end}")
    lines.append("}")
    return "\n".join(lines) + "\n"


def write_case(data: dict[str, Any], directory: Path = CASES_DIR) -> Path:
    validate(data)
    text = dumps_case(data)
    if json.loads(text) != json.loads(json.dumps(data)):
        raise CaseError(f"{data['name']}: the committed form does not round-trip")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{data['name']}.json"
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


# --- natural keys ------------------------------------------------------------------------------


def _lookup(row: Mapping[str, Any], path: str) -> Any:
    value: Any = row
    for part in path.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return _MISSING
        value = value[part]
    return value


_MISSING = object()


def _equal(actual: Any, expected: Any) -> bool:
    if actual is _MISSING:
        return False
    if isinstance(expected, bool) or isinstance(actual, bool):
        return actual is expected
    if isinstance(expected, int | float) and isinstance(actual, int | float):
        return float(actual) == float(expected)
    return str(actual) == str(expected)


def matching(rows: Iterable[Mapping[str, Any]], where: Mapping[str, Any]) -> list[int]:
    """Indexes of the rows whose every `where` path (dotted into JSON columns) matches."""
    return [
        i
        for i, row in enumerate(rows)
        if all(_equal(_lookup(row, path), value) for path, value in where.items())
    ]


# --- seeding -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class RowRef:
    """One seeded row as the builder's `ContextRef` names it (flows by job + flow_ref)."""

    table: str
    ref_id: str
    job_id: uuid.UUID


@dataclass
class SeededCase:
    case: Case
    tenant: Tenant
    salt: bytes
    investigation_id: uuid.UUID
    job_ids: dict[str, uuid.UUID] = field(default_factory=dict)
    evidence_ids: dict[str, uuid.UUID] = field(default_factory=dict)

    @property
    def org_id(self) -> uuid.UUID:
        return self.tenant.org_id

    @property
    def owner_id(self) -> uuid.UUID:
        return self.tenant.owner_id

    def row_id(self, job: str, table: str, index: int) -> uuid.UUID:
        job_index = [j["key"] for j in self.case.jobs].index(job)
        return case_uuid(self.salt, _GROUP_ROWS + _table_index(table), job_index, index)

    def find(self, table: str, where: Mapping[str, Any], job: str | None = None) -> list[RowRef]:
        """Every row matching `where` (in `job`, or in any job of the case)."""
        if table == TI_TABLE:
            first = self.job_ids[self.case.jobs[0]["key"]]
            return [
                RowRef(table, str(case_uuid(self.salt, _GROUP_TI, 0, i)), first)
                for i in matching(self.case.ti, where)
            ]
        if table not in TABLES:
            raise CaseError(f"{self.case.name}: unknown table {table!r}")
        refs: list[RowRef] = []
        for spec in self.case.jobs:
            if job is not None and spec["key"] != job:
                continue
            rows = spec["tables"].get(table, [])
            refs += [self._ref(spec["key"], table, i) for i in matching(rows, where)]
        return refs

    def resolve(self, table: str, where: Mapping[str, Any], job: str | None = None) -> RowRef:
        """The one row matching `where`; zero or several matches fail loudly."""
        refs = self.find(table, where, job)
        if len(refs) != 1:
            raise CaseError(
                f"{self.case.name}: {table} {dict(where)} matches {len(refs)} rows (need 1)"
            )
        return refs[0]

    def _ref(self, job_key: str, table: str, index: int) -> RowRef:
        job_id = self.job_ids[job_key]
        if table == FLOW_TABLE:  # RT16: flows are named by (job_id, flow_ref)
            flow_ref = self.case.rows(job_key, table)[index].get("flow_ref")
            if not flow_ref:
                raise CaseError(f"{self.case.name}: flow without flow_ref cannot be cited")
            return RowRef(table, str(flow_ref), job_id)
        return RowRef(table, str(self.row_id(job_key, table, index)), job_id)

    def planted_refs(self) -> list[RowRef]:
        """The rows of an injected twin that carry a payload (`plants` with a natural key)."""
        refs: list[RowRef] = []
        for plant in self.case.plants:
            if plant.get("table"):
                for ref in self.find(plant["table"], plant["where"], plant.get("job")):
                    if ref not in refs:
                        refs.append(ref)
        return refs


def _table_index(name: str) -> int:
    return [t.name for t in RESULT_TABLES].index(name)


def case_uuid(salt: bytes, group: int, sub: int, n: int) -> uuid.UUID:
    """Ids that sort (bytewise, as Postgres compares uuids) in case-file order."""
    return uuid.UUID(bytes=salt + struct.pack(">HHI", group, sub, n))


def ti_identity(ioc_type: str, value: str) -> tuple[str, str, str]:
    """(ioc_type, value_norm, ioc_key) as M4 derives them from an `iocs` row."""
    outcome = normalize(ioc_type, value)
    if isinstance(outcome, Normalized):
        return outcome.ioc_type.value, outcome.value_norm, outcome.ioc_key
    kind, norm = outcome.ioc_type, outcome.value_norm
    if kind in (IocType.IPV4, IocType.IPV6) and norm is None:
        # Documentation ranges (RFC 5737) are never sent for real; the fixture rows are
        # synthetic, so they still get the key M4 would compute for a global address.
        norm = ipaddress.ip_address(value.strip()).compressed
    if kind is None or norm is None:
        raise CaseError(f"TI fixture IOC {ioc_type}:{value!r} has no normalized form")
    return kind.value, norm, compute_ioc_key(kind, norm)


def ti_summary(summary: Mapping[str, Any]) -> dict[str, Any]:
    """A fixture summary through the real M4 summary model (cleaning and caps applied)."""
    model = SUMMARY_MODELS[str(summary["provider"])]
    return cast(dict[str, Any], model.model_validate(dict(summary)).model_dump(mode="json"))


async def seed_case(case: Case, tenant: Tenant, *, salt: bytes | None = None) -> SeededCase:
    """Insert the case into the tenant's org (one transaction, the owner's RLS context)."""
    salt = salt if salt is not None else secrets.token_bytes(8)
    org, owner = tenant.org_id, tenant.owner_id
    spec = case.data["investigation"]
    created = parse_ts(spec["created_at"])
    seeded = SeededCase(
        case=case,
        tenant=tenant,
        salt=salt,
        investigation_id=case_uuid(salt, _GROUP_INVESTIGATION, 0, 0),
    )
    async with tenant_session(org, owner) as s:
        s.add(
            Investigation(
                id=seeded.investigation_id,
                organization_id=org,
                case_number=100,
                title=spec["title"],
                description=spec.get("description", ""),
                severity=Severity(spec.get("severity", "medium")),
                created_by=owner,
                created_at=created,
                updated_at=created,
            )
        )
        await s.flush()
        for n, job in enumerate(case.jobs):
            evidence = job["evidence"]
            evidence_id = case_uuid(salt, _GROUP_EVIDENCE, 0, n)
            job_id = case_uuid(salt, _GROUP_JOB, 0, n)
            seeded.evidence_ids[job["key"]] = evidence_id
            seeded.job_ids[job["key"]] = job_id
            uploaded = parse_ts(evidence["uploaded_at"])
            s.add(
                Evidence(
                    id=evidence_id,
                    organization_id=org,
                    investigation_id=seeded.investigation_id,
                    original_filename=evidence["filename"],
                    detected_mime=evidence["mime"],
                    detected_description=evidence["description"],
                    size_bytes=evidence["size_bytes"],
                    storage_bucket="evidence-test",
                    storage_key=f"ai-eval/{evidence_id}",
                    storage_version_id="v1",
                    uploaded_by=owner,
                    uploaded_at=uploaded,
                )
            )
            await s.flush()
            s.add(
                EvidenceCustodyEvent(
                    id=case_uuid(salt, _GROUP_CUSTODY, 0, n),
                    organization_id=org,
                    evidence_id=evidence_id,
                    action=CustodyAction.UPLOADED,
                    actor_id=owner,
                    occurred_at=uploaded,
                    details={},
                )
            )
            s.add(
                AnalysisJob(
                    id=job_id,
                    organization_id=org,
                    evidence_id=evidence_id,
                    analyzer=Analyzer(job["analyzer"]),
                    profile=job.get("profile"),
                    status=AnalysisStatus.SUCCEEDED,
                    requested_by=owner,
                    ingest_token_sha256=secrets.token_hex(32),
                    worker_version=job.get("worker_version", "ai-eval/hand-trimmed"),
                    result_version_id="v1",
                    summary=job.get("summary", {}),
                    created_at=parse_ts(job["created_at"]),
                    started_at=parse_ts(job["created_at"]),
                    finished_at=parse_ts(job["finished_at"]),
                )
            )
            await s.flush()
            scope = {"organization_id": org, "job_id": job_id}
            for table_name, rows in job["tables"].items():
                if not rows:
                    continue
                table = TABLES[table_name]
                values = [
                    {
                        **from_json_row(table, row),
                        **scope,
                        "id": seeded.row_id(job["key"], table_name, i),
                    }
                    for i, row in enumerate(rows)
                ]
                await s.execute(insert(table), values)
        if case.ti:
            await _seed_ti(s, case, seeded)
    return seeded


async def _seed_ti(s: Any, case: Case, seeded: SeededCase) -> None:
    org, owner = seeded.org_id, seeded.owner_id
    first = case.jobs[0]
    run_id = case_uuid(seeded.salt, _GROUP_TI_RUN, 0, 0)
    finished = parse_ts(first["finished_at"])
    providers = sorted({str(r["provider"]) for r in case.ti})
    s.add(
        TiEnrichmentRun(
            id=run_id,
            organization_id=org,
            scope="job",
            job_id=seeded.job_ids[first["key"]],
            requested_by=owner,
            providers=providers,
            status="completed",
            deadline_at=finished + dt.timedelta(hours=1),
            created_at=finished,
            started_at=finished,
            finished_at=finished,
        )
    )
    await s.flush()
    for n, row in enumerate(case.ti):
        ioc = row["ioc"]
        ioc_type, value_norm, ioc_key = ti_identity(ioc["type"], ioc["value"])
        status = row.get("status", "ok")
        s.add(
            TiResult(
                id=case_uuid(seeded.salt, _GROUP_TI, 0, n),
                organization_id=org,
                run_id=run_id,
                provider=row["provider"],
                ioc_type=ioc_type,
                value_norm=value_norm,
                ioc_key=ioc_key,
                status=status,
                found=bool(row.get("found", status == "ok")),
                score=row.get("score"),
                score_scale=row.get("score_scale"),
                tags=list(row.get("tags", [])),
                families=list(row.get("families", [])),
                attack_ids=list(row.get("attack_ids", [])),
                summary=ti_summary(row["summary"]) if row.get("summary") else None,
                fetched_at=parse_ts(row.get("fetched_at", first["finished_at"])),
                expires_at=FAR_FUTURE if status in ("ok", "not_found") else None,
            )
        )
