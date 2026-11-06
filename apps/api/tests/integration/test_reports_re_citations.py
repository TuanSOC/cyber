"""Reverse-engineering rows in reports (M10 phase 9).

RE function rows are citable (`function`, `re_functions`: name, entry, size, signature,
linked capabilities), from a verified `explain_function` citation or the draft's selection;
a verified `Q` citation (`code`, `re_decompilations`) renders as "decompiled code of <name>
(sha256 …)" and the decompiled text itself never enters a snapshot. Both link to the
function of the RE job page. The snapshot schema is unchanged, so existing snapshots keep
their bytes (`tests/unit/test_report_canonical_golden.py`).
"""

import uuid
from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.reports.citations import fields_sha256
from app.modules.reverse_engineering.models import (
    ReDecompilation,
    ReFunction,
    ReFunctionCapability,
)
from app.modules.static_analysis.models import MalwareCapability
from tests.integration.test_report_citations import _report
from tests.report_helpers import SigningKeys, purge_reports_test_bucket, use_signing_keys
from tests.reverse_helpers import seed_re_job, seed_static_source_job
from tests.security.idor_cases_reports import ai_run_on, api_preview, fake_case_iocs, owner_case

INJECT_REMOTE = 0x1400011E0
RESOLVE_APIS = 0x140001320


@pytest.fixture
def keys(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[SigningKeys]:
    installed = use_signing_keys(monkeypatch, tmp_path)
    fake_case_iocs(monkeypatch)
    yield installed
    purge_reports_test_bucket()


async def test_function_and_code_citations_never_carry_the_code(keys: SigningKeys) -> None:
    reg, t = await owner_case(org_name="RE Report Org")
    static_job = await seed_static_source_job(t)
    re_job = await seed_re_job(t, static_job)
    async with tenant_session(t.org_id, t.owner_id) as s:
        fn = await s.scalar(
            select(ReFunction).where(ReFunction.job_id == re_job, ReFunction.entry == INJECT_REMOTE)
        )
        other = await s.scalar(
            select(ReFunction).where(ReFunction.job_id == re_job, ReFunction.entry == RESOLVE_APIS)
        )
        code = await s.scalar(
            select(ReDecompilation).where(
                ReDecompilation.job_id == re_job, ReDecompilation.function_entry == INJECT_REMOTE
            )
        )
        cap = await s.scalar(
            select(MalwareCapability).where(
                MalwareCapability.job_id == static_job, MalwareCapability.name == "inject thread"
            )
        )
        assert fn is not None and other is not None and code is not None and cap is not None
        s.add(
            ReFunctionCapability(
                organization_id=t.org_id,
                job_id=re_job,
                function_entry=Decimal(INJECT_REMOTE),
                capability_id=cap.id,
                file_va=Decimal(0x140001280),
            )
        )
        code_text, code_sha = code.code, code.code_sha256
        fn_id, other_id, code_id = str(fn.id), str(other.id), str(code.id)
    assert code_text and code_sha
    run = await ai_run_on(
        t,
        re_job,
        claims=[
            ("o1", "inject_remote calls VirtualAllocEx", [("function", fn_id), ("code", code_id)])
        ],
    )
    report_id = await _report(
        reg, t, ai_runs=[str(run)], cited_rows=[{"kind": "function", "ref_id": other_id}]
    )
    response = await api_preview(reg, report_id)
    assert response.status_code == 200, response.text
    snap = response.json()["snapshot"]
    cited = {c["ref_id"]: c for c in snap["citations"]["items"]}
    assert set(cited) == {fn_id, code_id, other_id}

    function = cited[fn_id]
    assert function["kind"] == "function" and function["ref_table"] == "re_functions"
    assert function["source"] == "ai" and function["job_id"] == str(re_job)
    assert function["fields"]["name"] == "inject_remote"
    assert function["fields"]["entry"] == "0x1400011e0"
    assert function["fields"]["capabilities"] == "inject thread"
    assert fields_sha256(function["fields"]) == function["fields_sha256"]
    page = f"/o/{reg.org_id}/reverse-engineering/{re_job}?fn=0x1400011e0"
    assert function["path"] == f"{page}&tab=facts"

    decompiled = cited[code_id]
    assert decompiled["kind"] == "code" and decompiled["ref_table"] == "re_decompilations"
    assert decompiled["fields"]["description"] == (
        f"decompiled code of inject_remote (sha256 {code_sha})"
    )
    assert decompiled["fields"]["code_sha256"] == code_sha
    assert "code" not in decompiled["fields"]
    assert decompiled["path"] == f"{page}&tab=code"

    selected = cited[other_id]
    assert selected["source"] == "selection" and selected["fields"]["name"] == "resolve_apis"

    # The decompiled text never reaches the snapshot, in any section.
    text = str(snap)
    for line in code_text.splitlines():
        if len(line.strip()) >= 12:
            assert line.strip() not in text, line


async def test_rows_of_another_case_are_never_resolved(keys: SigningKeys) -> None:
    reg, t = await owner_case(org_name="RE Report Scope Org")
    _, other_t = await owner_case(org_name="RE Report Foreign Org")
    foreign_job = await seed_re_job(other_t)
    async with tenant_session(other_t.org_id, other_t.owner_id) as s:
        foreign = await s.scalar(select(ReFunction.id).where(ReFunction.job_id == foreign_job))
    report_id = await _report(
        reg, t, cited_rows=[{"kind": "function", "ref_id": str(foreign or uuid.uuid4())}]
    )
    snap = (await api_preview(reg, report_id)).json()["snapshot"]
    assert snap["citations"]["items"] == []
    assert snap["citations"]["dropped_out_of_scope"] == 1
