"""M10 phase 7: the trusted ingest of an `re.v1` result, all rows or none, and the capa join.

The RE job is requested through the API from a real static source (capabilities with capa
locations inside the `pe_full` fixture's functions); the worker's report is simulated with a
phase-1 fixture retargeted to the job and its evidence. Each hostile stream fails the job
`invalid_result` and leaves every RE table empty.
"""

import uuid
from datetime import timedelta
from typing import Any

import pytest
from cyberlab_jobs import IngestMessageV1
from sqlalchemy import func, select

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis import dispatch
from app.modules.analysis.lifecycle import now
from app.modules.analysis.models import AnalysisJob, AnalysisJobIndex, AnalysisStatus, Analyzer
from app.modules.audit.models import AuditLog
from app.modules.pcap_analysis.models import AnalysisFinding, Ioc
from app.modules.reverse_engineering import ingest as re_ingest
from app.modules.reverse_engineering.models import (
    RESULT_TABLES,
    ReFunction,
    ReFunctionCapability,
    ReImport,
    ReImportRef,
    ReProgram,
    ReString,
    ReStringRef,
)
from app.modules.static_analysis.models import MalwareCapability
from app.workers import ingest
from tests import memory_results as mr
from tests import reverse_results as rr
from tests.pcap_results import put_result
from tests.analysis_helpers import SentJobs, new_case, pe_bytes, upload
from tests.case_helpers import seed_job_on
from tests.factories import Registered, register
from tests.integration.seed import Tenant
from tests.reverse_helpers import seed_re_job

TABLES = tuple(model.__tablename__ for model in RESULT_TABLES)
EMPTY = dict.fromkeys(TABLES, 0)


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> SentJobs:
    captured = SentJobs()

    async def capture(item: dispatch.DispatchInput) -> None:
        captured.append(item)

    monkeypatch.setattr(dispatch, "send", capture)
    return captured


async def _queued(
    sent: SentJobs, *, name: str = "RE Ingest Org", profile: str = "full", **source: Any
) -> tuple[Registered, dispatch.DispatchInput]:
    reg = await register(org_name=name)
    evidence_id, _ = await rr.static_source(sent, reg, **source)
    response = await rr.request_re(reg, evidence_id, profile=profile)
    assert response.status_code == 201, response.text
    item = sent[-1]
    assert item.analyzer == Analyzer.REVERSE
    return reg, item


async def _objs(item: dispatch.DispatchInput, name: str = rr.PE) -> list[dict[str, Any]]:
    size, sha256 = await mr.evidence_identity(item.organization_id, item.job_id)
    return rr.retarget(rr.parsed(name), item.job_id, size=size, sha256=sha256)


async def _row_counts(org_id: uuid.UUID, job_id: uuid.UUID) -> dict[str, int]:
    async with tenant_session(org_id, None) as session:
        out = {}
        for model in RESULT_TABLES:
            out[model.__tablename__] = int(
                await session.scalar(
                    select(func.count()).select_from(model).where(model.job_id == job_id)
                )
                or 0
            )
        return out


def _expected_tables(name: str = rr.PE, links: int = 0) -> dict[str, int]:
    counts = rr.fixture_counts(name)
    return {
        "re_programs": 1,
        "re_functions": counts.get("function", 0),
        "re_call_edges": counts.get("call_edge", 0),
        "re_imports": counts.get("import", 0),
        "re_import_refs": counts.get("import_ref", 0),
        "re_strings": counts.get("string", 0),
        "re_string_refs": counts.get("string_ref", 0),
        "re_decompilations": counts.get("decompiled", 0),
        "re_function_capabilities": links,
    }


async def _job(item: dispatch.DispatchInput) -> AnalysisJob:
    async with tenant_session(item.organization_id, None) as session:
        job = await session.get(AnalysisJob, item.job_id)
    assert job is not None
    return job


async def _refused(item: dispatch.DispatchInput, objs: list[dict[str, Any]]) -> None:
    await mr.deliver(item, rr.encode(objs))
    job = await _job(item)
    assert (job.status, job.error_code) == ("failed", "invalid_result")
    assert job.result_version_id is None and job.summary == {}
    assert await _row_counts(item.organization_id, item.job_id) == EMPTY


# --- success --------------------------------------------------------------------------------


async def test_an_re_result_is_written_in_one_transaction(sent: SentJobs) -> None:
    reg, item = await _queued(sent)
    message = await mr.deliver(item, rr.encode(await _objs(item)))
    job = await _job(item)
    assert (job.status, job.error_code) == ("succeeded", None)
    assert job.result_version_id == message["result_version_id"]
    assert await _row_counts(reg.org_id, item.job_id) == _expected_tables(links=2)

    counts = rr.fixture_counts()
    summary = job.summary
    assert summary["schema_version"] == "re.v1" and summary["profile"] == "full"
    assert (summary["engine"], summary["code_kind"]) == ("replay", "pseudo_c")
    assert summary["source_job_id"] == str(item.re_source.job_id)
    size, sha256 = await mr.evidence_identity(reg.org_id, item.job_id)
    assert summary["sample"] == {"size_bytes": size, "sha256": sha256}
    assert summary["counts"]["functions"] == counts["function"] == 31
    assert summary["counts"]["decompiled"] == 6 and summary["counts"]["findings"] == 2
    # inject thread (2 locations) + runtime linking (1); the 4th location is in no function.
    assert (summary["counts"]["capa_linked"], summary["counts"]["capa_unlocated"]) == (3, 1)
    assert summary["counts"]["capabilities_linked"] == 2
    assert summary["decompile_budget"]["used"] == 6
    assert summary["peak_memory_bytes"] == 1_610_612_736
    assert [s["stage"] for s in summary["stages"]] == ["analyze", "decompile"]

    async with tenant_session(reg.org_id, None) as session:
        program = await session.get(ReProgram, item.job_id)
        assert program is not None
        assert int(program.preferred_base) == int(program.image_base) == rr.CAPA_BASE
        assert program.counts["capa_linked"] == 3 and program.counts["capa_unlocated"] == 1
        assert program.engine == "replay" and program.engine_version == "12.2"
        assert program.peak_memory_bytes == 1_610_612_736 and len(program.jvm_args) == 15
        statuses = dict(
            (int(e), s)
            for e, s in await session.execute(
                select(ReFunction.entry, ReFunction.decompile_status).where(
                    ReFunction.job_id == item.job_id
                )
            )
        )
        assert statuses[0x140001000] == "ok" and statuses[0x140001440] == "timeout"
        assert list(statuses.values()).count("not_selected") == 31 - 6
        # Every reference points at a row of this job (stream index -> row id).
        orphan_imports = await session.scalar(
            select(func.count())
            .select_from(ReImportRef)
            .outerjoin(ReImport, ReImport.id == ReImportRef.import_id)
            .where(ReImportRef.job_id == item.job_id, ReImport.job_id.is_(None))
        )
        orphan_strings = await session.scalar(
            select(func.count())
            .select_from(ReStringRef)
            .outerjoin(ReString, ReString.id == ReStringRef.string_id)
            .where(ReStringRef.job_id == item.job_id, ReString.job_id.is_(None))
        )
        assert orphan_imports == 0 and orphan_strings == 0
        links = (
            await session.execute(
                select(
                    MalwareCapability.name,
                    ReFunctionCapability.function_entry,
                    ReFunctionCapability.file_va,
                )
                .join(MalwareCapability, MalwareCapability.id == ReFunctionCapability.capability_id)
                .where(ReFunctionCapability.job_id == item.job_id)
                .order_by(MalwareCapability.name)
            )
        ).all()
        assert [(n, int(e), int(v)) for n, e, v in links] == [
            ("inject thread", rr.INJECT_REMOTE, 0x140001280),
            ("link function at runtime on Windows", rr.RESOLVE_APIS, 0x140001400),
        ]
        findings = await session.scalar(
            select(func.count()).select_from(AnalysisFinding).where(
                AnalysisFinding.job_id == item.job_id
            )
        )
        iocs = await session.scalar(
            select(func.count()).select_from(Ioc).where(Ioc.job_id == item.job_id)
        )
        assert (findings, iocs) == (counts["finding"], counts["ioc"])
        audits = await session.scalars(
            select(AuditLog).where(
                AuditLog.action == "analysis.succeeded", AuditLog.target_id == item.job_id
            )
        )
        assert len(list(audits)) == 1

    # A redelivered success report changes nothing.
    await ingest.handle_event(message)
    assert await _row_counts(reg.org_id, item.job_id) == _expected_tables(links=2)


async def test_an_elf_and_a_quick_result_are_ingested(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    reg, item = await _queued(
        sent,
        name="RE ELF Ingest Org",
        content=rr.elf_bytes(),
        filename="a.elf",
        info=rr.elf_info(),
        records=rr.elf_sections(),
        capa_base=None,
    )
    await mr.deliver(item, rr.encode(await _objs(item, rr.ELF)))
    assert (await _job(item)).status == "succeeded"
    assert await _row_counts(reg.org_id, item.job_id) == _expected_tables(rr.ELF)

    monkeypatch.setattr(get_settings(), "re_quick_enabled", True)
    reg, item = await _queued(sent, name="RE Quick Ingest Org", profile="quick")
    await mr.deliver(item, rr.encode(await _objs(item, rr.QUICK)))
    job = await _job(item)
    assert job.status == "succeeded", job.error_code
    assert job.summary["code_kind"] == "disasm" and job.summary["counts"]["decompiled"] == 0


async def test_a_purged_source_still_ingests_without_links(sent: SentJobs) -> None:
    """M7 retention may have purged the source job's rows: no format check, no join."""
    reg = await register(org_name="RE Purged Source Org")
    case_id = await new_case(reg)
    evidence = await upload(reg.client, reg.org_id, case_id, pe_bytes(), "p.exe")
    t = Tenant(reg.org_id, reg.user_id, uuid.UUID(case_id))
    # A succeeded static job without any result row stands for a purged one.
    source = await seed_job_on(t, uuid.UUID(evidence["id"]), "static")
    job_id = await seed_re_job(t, source, status="queued", fixture=None)
    async with tenant_session(reg.org_id, reg.user_id) as s:
        s.add(
            AnalysisJobIndex(
                job_id=job_id,
                organization_id=reg.org_id,
                analyzer=Analyzer.REVERSE,
                status=AnalysisStatus.QUEUED,
                deadline_at=now() + timedelta(hours=1),
            )
        )
    size, sha256 = await mr.evidence_identity(reg.org_id, job_id)
    data = rr.stream(job_id, size=size, sha256=sha256)
    version = put_result(reg.org_id, job_id, data)
    async with tenant_session(reg.org_id, None) as session:
        job = await session.get(AnalysisJob, job_id)
    assert job is not None
    await ingest.ingest_success(job, _message(reg.org_id, job_id, version))
    async with tenant_session(reg.org_id, None) as session:
        done = await session.get(AnalysisJob, job_id)
    assert done is not None and done.status == "succeeded", done and done.error_code
    assert done.summary["counts"]["capa_linked"] == 0
    assert (await _row_counts(reg.org_id, job_id))["re_function_capabilities"] == 0


def _message(org_id: uuid.UUID, job_id: uuid.UUID, version: str) -> IngestMessageV1:
    return IngestMessageV1.model_validate(
        {
            "job_id": str(job_id),
            "organization_id": str(org_id),
            "ingest_token": "t" * 43,
            "event": "finished",
            "outcome": "succeeded",
            "result_version_id": version,
            "worker_version": rr.WORKER,
        }
    )


# --- diagnostic -----------------------------------------------------------------------------


async def test_an_unsupported_architecture_report_stores_the_program_and_fails(
    sent: SentJobs,
) -> None:
    reg, item = await _queued(
        sent,
        name="RE Diagnostic Org",
        content=rr.elf_bytes(),
        filename="d.elf",
        info=rr.elf_info(),
        records=[],
    )
    data = rr.encode(await _objs(item, rr.DIAGNOSTIC))
    await mr.deliver(item, data, outcome="failed", error_code="unsupported_architecture")
    job = await _job(item)
    assert (job.status, job.error_code) == ("failed", "unsupported_architecture")
    assert job.summary["program"]["arch"] == "other"
    assert await _row_counts(reg.org_id, item.job_id) == {**EMPTY, "re_programs": 1}


async def test_a_diagnostic_with_records_or_another_code_is_refused(sent: SentJobs) -> None:
    _, item = await _queued(sent, name="RE Bad Diagnostic Org")
    data = rr.encode(await _objs(item))  # a full stream, sent as a diagnostic
    await mr.deliver(item, data, outcome="failed", error_code="unsupported_managed_code")
    job = await _job(item)
    assert (job.status, job.error_code) == ("failed", "invalid_result")
    assert await _row_counts(item.organization_id, item.job_id) == EMPTY

    _, item = await _queued(sent, name="RE Other Code Org")
    data = rr.encode(await _objs(item, rr.DIAGNOSTIC))
    await mr.deliver(item, data, outcome="failed", error_code="analysis_timeout")
    job = await _job(item)
    assert (job.status, job.error_code) == ("failed", "invalid_result")  # read never


# --- refused --------------------------------------------------------------------------------


def _hostile_cases() -> list[str]:
    return [
        "identity",
        "format",
        "profile",
        "unknown_function",
        "duplicate_finding",
        "code_sha",
        "jvm_args",
        "replay",
    ]


@pytest.mark.parametrize("case", _hostile_cases())
async def test_a_hostile_stream_fails_the_job_and_writes_nothing(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    _, item = await _queued(sent, name=f"RE Hostile {case}")
    objs = await _objs(item)
    if case == "identity":
        objs[1]["sha256"] = "f" * 64
    elif case == "format":
        objs[1]["format"] = "elf"
    elif case == "profile":
        objs[0]["profile"] = "quick"
        objs = [o for o in objs if o["kind"] != "decompiled"]
    elif case == "unknown_function":
        ref = next(i for i, o in enumerate(objs) if o["kind"] == "string_ref")
        objs[ref] = {**objs[ref], "function_entry": 0x1}
    elif case == "duplicate_finding":
        finding = next(i for i, o in enumerate(objs) if o["kind"] == "finding")
        objs.insert(finding, objs[finding])
    elif case == "code_sha":
        code = next(i for i, o in enumerate(objs) if o.get("code"))
        objs[code] = {**objs[code], "code": objs[code]["code"] + "\n// edited"}
    elif case == "jvm_args":
        objs[0]["jvm_args"] = [f"-Dx{i}=" + "v" * 400 for i in range(64)]
    else:
        monkeypatch.setattr(re_ingest, "replay_allowed", lambda: False)
    await _refused(item, objs)

