"""M10 phase 1 schema (0018): the RE job columns and their checks, the source trigger, the
capa locations check, the job guard (write-once), the fixture rows fit every table, and the
retention role's grants."""

import secrets
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError

from app.core.tenancy import tenant_session
from app.modules.analysis.models import AnalysisJob, AnalysisStatus, Analyzer, JobProfile
from app.modules.reverse_engineering.models import (
    BULK_TABLES,
    ReDecompilation,
    ReFunction,
    ReProgram,
)
from app.modules.static_analysis.models import MalwareCapability
from tests.case_helpers import seed_evidence, seed_job_on
from tests.integration.seed import Tenant, seed_tenant
from tests.reverse_helpers import seed_re_job, seed_static_source_job


def _job(t: Tenant, evidence_id: uuid.UUID, **fields: object) -> AnalysisJob:
    values: dict[str, object] = {
        "organization_id": t.org_id,
        "evidence_id": evidence_id,
        "analyzer": Analyzer.REVERSE,
        "profile": JobProfile.FULL,
        "re_params": {"decompile_addresses": []},
        "status": AnalysisStatus.QUEUED,
        "requested_by": t.owner_id,
        "ingest_token_sha256": secrets.token_hex(32),
    }
    values.update(fields)
    return AnalysisJob(**values)


async def _insert(t: Tenant, job: AnalysisJob) -> None:
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(job)


async def test_a_fixture_job_fits_every_re_table() -> None:
    t = await seed_tenant("re-alpha")
    job_id = await seed_re_job(t, decompile_addresses=(0x140001000,))
    async with tenant_session(t.org_id, t.owner_id) as s:
        program = await s.get(ReProgram, job_id)
        assert program is not None and program.engine == "replay"
        functions = (await s.execute(text("SELECT count(*) FROM re_functions"))).scalar_one()
        code = (
            await s.execute(text("SELECT count(*) FROM re_decompilations WHERE code IS NOT NULL"))
        ).scalar_one()
    assert functions >= 25 and code == 5


@pytest.mark.parametrize(
    "fields",
    [
        {"source_job_id": None},  # NOT NULL iff reverse
        {"re_params": None},
        {"profile": JobProfile.TRIAGE},  # reverse takes quick / full only (RT10)
        {"profile": JobProfile.QUICK, "re_params": {"decompile_addresses": ["4198400"]}},
        {"re_params": {"decompile_addresses": [4198400]}},  # decimal strings only
        {"re_params": {"decompile_addresses": ["18446744073709551616"]}},
        {"re_params": {"decompile_addresses": [], "extra": 1}},
        {"re_params": {"decompile_addresses": [str(i) for i in range(65)]}},
    ],
)
async def test_re_job_checks(fields: dict[str, object]) -> None:
    t = await seed_tenant("re-beta")
    source = await seed_static_source_job(t)
    async with tenant_session(t.org_id, t.owner_id) as s:
        evidence_id = (await s.get(AnalysisJob, source)).evidence_id  # type: ignore[union-attr]
    with pytest.raises((IntegrityError, DBAPIError)):
        await _insert(t, _job(t, evidence_id, source_job_id=source, **fields))


async def test_other_analyzers_take_no_re_fields() -> None:
    t = await seed_tenant("re-gamma")
    source = await seed_static_source_job(t)
    evidence_id = await seed_evidence(t, filename="c.pcap")
    with pytest.raises((IntegrityError, DBAPIError)):
        await _insert(
            t, _job(t, evidence_id, analyzer=Analyzer.PCAP, profile=None, source_job_id=source)
        )


async def test_the_source_is_a_static_job_of_the_same_evidence() -> None:
    t = await seed_tenant("re-delta")
    source = await seed_static_source_job(t)
    other_evidence = await seed_evidence(t, filename="other.exe")
    with pytest.raises(DBAPIError, match="static job of the same evidence"):
        await _insert(t, _job(t, other_evidence, source_job_id=source))
    pcap_evidence = await seed_evidence(t, filename="x.pcap")
    pcap_job = await seed_job_on(t, pcap_evidence, "pcap")
    with pytest.raises(DBAPIError, match="static job of the same evidence"):
        await _insert(t, _job(t, pcap_evidence, source_job_id=pcap_job))


async def test_re_fields_are_write_once() -> None:
    t = await seed_tenant("re-epsilon")
    job_id = await seed_re_job(t, status="running", fixture=None)
    for statement in (
        "UPDATE analysis_jobs SET re_params = '{\"decompile_addresses\": [\"1\"]}' WHERE id = :id",
        "UPDATE analysis_jobs SET source_job_id = NULL WHERE id = :id",
    ):
        with pytest.raises(DBAPIError):
            async with tenant_session(t.org_id, t.owner_id) as s:
                await s.execute(text(statement), {"id": job_id})


@pytest.mark.parametrize(
    "locations", [[1] * 1, ["0x401000"], [str(i) for i in range(33)], ["18446744073709551616"]]
)
async def test_capability_locations_check(locations: list[object]) -> None:
    t = await seed_tenant("re-zeta")
    source = await seed_static_source_job(t, capabilities=())
    with pytest.raises((IntegrityError, DBAPIError)):
        async with tenant_session(t.org_id, t.owner_id) as s:
            s.add(
                MalwareCapability(
                    organization_id=t.org_id,
                    job_id=source,
                    name="x",
                    namespace=None,
                    attack=[],
                    mbc=[],
                    matches=1,
                    locations=locations,
                )
            )


async def test_decompilation_code_rules() -> None:
    t = await seed_tenant("re-eta")
    job_id = await seed_re_job(t, fixture=None)
    base = {"organization_id": t.org_id, "job_id": job_id, "function_entry": 0x1000, "lines": 1}
    for bad in (
        {"status": "ok", "code_kind": "pseudo_c", "code": None, "code_sha256": None},
        {"status": "timeout", "code_kind": "pseudo_c", "code": "x", "code_sha256": "0" * 64},
        {"status": "ok", "code_kind": "pseudo_c", "code": "x" * 65_537, "code_sha256": "0" * 64},
        {"status": "ok", "code_kind": "asm", "code": "x", "code_sha256": "0" * 64},
    ):
        with pytest.raises((IntegrityError, DBAPIError)):
            async with tenant_session(t.org_id, t.owner_id) as s:
                s.add(ReDecompilation(**base, **bad))


async def test_function_names_and_ranks_are_bounded() -> None:
    t = await seed_tenant("re-theta")
    job_id = await seed_re_job(t, fixture=None)
    base = {
        "organization_id": t.org_id,
        "job_id": job_id,
        "entry": 0x401000,
        "rva": 0x1000,
        "name": "f",
        "name_source": "generated",
        "size": 1,
        "instructions": 1,
        "callers": 0,
        "callees": 0,
        "decompile_status": "not_selected",
    }
    for bad in ({"name_source": "guess"}, {"priority_rank": 20_000}, {"entry": 2**64}):
        with pytest.raises((IntegrityError, DBAPIError)):
            async with tenant_session(t.org_id, t.owner_id) as s:
                s.add(ReFunction(**{**base, **bad}))


async def test_retention_grants(owner_engine) -> None:  # type: ignore[no-untyped-def]
    query = text(
        "SELECT table_name, privilege_type FROM information_schema.role_table_grants "
        "WHERE grantee = 'cyberlab_retention' AND table_name LIKE 're\\_%'"
    )
    async with owner_engine.connect() as conn:
        grants = {(r[0], r[1]) for r in await conn.execute(query)}
    assert {("re_programs", "SELECT")} <= grants and ("re_programs", "DELETE") not in grants
    for table in BULK_TABLES:
        assert {(table, "SELECT"), (table, "DELETE")} <= grants, table
