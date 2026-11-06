"""M10 phase 7: the reverse-engineering request and its job message.

The source is a real static `full` job finished through the static ingest (PE / ELF facts,
capabilities with capa locations, the capa base). Dispatch is captured (no RE worker); the
message is built by `build_message` exactly as the dispatch thread does (presigned URLs).
Every refusal answers its code and creates nothing; no upload ever creates a `reverse` job.
"""

import uuid
from typing import Any

import pytest
from cyberlab_jobs.reverse import ReJobV1
from sqlalchemy import select

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis import dispatch
from app.modules.analysis.models import AnalysisJob, Analyzer
from app.modules.analysis.service import auto_choice
from app.modules.audit.models import AuditLog
from app.modules.organizations.models import MemberRole
from app.modules.reverse_engineering.dispatch import re_limits
from tests import pcap_results as pr
from tests import reverse_results as rr
from tests import static_results as sr
from tests.analysis_helpers import SentJobs, jobs_for, new_case, pe_bytes, upload
from tests.factories import (
    Registered,
    add_member,
    csrf,
    login,
    make_user,
    register,
    unique_email,
)
from tests.integration.seed import Tenant
from tests.reverse_helpers import seed_re_job

INJECT = [0x140001280, 0x1400012A0]


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> SentJobs:
    captured = SentJobs()

    async def capture(item: dispatch.DispatchInput) -> None:
        captured.append(item)

    monkeypatch.setattr(dispatch, "send", capture)
    return captured


async def _reverse_jobs(org_id: uuid.UUID) -> list[AnalysisJob]:
    async with tenant_session(org_id, None) as session:
        rows = await session.scalars(
            select(AnalysisJob).where(AnalysisJob.analyzer == Analyzer.REVERSE)
        )
        return list(rows)


async def _audits(org_id: uuid.UUID, action: str) -> list[AuditLog]:
    async with tenant_session(org_id, None) as session:
        rows = await session.execute(select(AuditLog).where(AuditLog.action == action))
        return list(rows.scalars())


async def _refused(reg: Registered, evidence_id: str, status: int, code: str, **body: Any) -> None:
    response = await rr.request_re(reg, evidence_id, **body)
    assert response.status_code == status, response.text
    assert response.json()["error"]["code"] == code
    assert await _reverse_jobs(reg.org_id) == []


# --- accepted -------------------------------------------------------------------------------


async def test_a_full_request_pins_the_latest_static_job_and_its_capa_vas(
    sent: SentJobs,
) -> None:
    reg = await register(org_name="RE Request Org")
    evidence_id, static_job = await rr.static_source(sent, reg)
    response = await rr.request_re(reg, evidence_id, decompile_addresses=["0x1400011E0"])
    assert response.status_code == 201, response.text
    job = response.json()
    assert (job["analyzer"], job["profile"], job["status"]) == ("reverse", "full", "queued")
    assert job["source_job_id"] == str(static_job) and job["auto"] is False

    item = sent[-1]
    assert item.analyzer == Analyzer.REVERSE and item.decompile_addresses == (0x1400011E0,)
    source = item.re_source
    assert (source.job_id, source.file_format, source.preferred_base) == (
        static_job,
        "pe",
        rr.CAPA_BASE,
    )
    # capa base = ImageBase: file VAs are the locations, sorted, unique.
    assert source.capa_file_vas == (0x140001280, 0x1400012A0, 0x140001400, 0x140009000)

    [stored] = await _reverse_jobs(reg.org_id)
    assert stored.source_job_id == static_job
    assert stored.re_params == {"decompile_addresses": [str(0x1400011E0)]}

    [audit] = [
        a
        for a in await _audits(reg.org_id, "analysis.requested")
        if a.details and a.details.get("analyzer") == "reverse"
    ]
    assert audit.details is not None
    assert audit.details["source_job_id"] == str(static_job)
    assert audit.details["decompile_addresses"] == 1  # a count, never the addresses
    assert "0x1400011e0" not in str(audit.details).lower()
    assert str(0x1400011E0) not in str(audit.details)


async def test_the_job_message_carries_the_source_and_the_limits(sent: SentJobs) -> None:
    reg = await register(org_name="RE Message Org")
    evidence_id, static_job = await rr.static_source(sent, reg)
    response = await rr.request_re(reg, evidence_id, decompile_addresses=["0x140001320"])
    assert response.status_code == 201, response.text
    message = dispatch.build_message(sent[-1])
    assert isinstance(message, ReJobV1)
    assert message.source_job_id == static_job and message.file_format == "pe"
    assert message.decompile_addresses == [0x140001320]
    assert message.capa_file_vas == [0x140001280, 0x1400012A0, 0x140001400, 0x140009000]
    assert message.limits == re_limits(get_settings())
    assert message.size_bytes == len(pe_bytes())
    assert message.result_post.fields["key"].endswith(f"/{message.job_id}.ndjson.gz")
    task, queue = dispatch.task_and_queue(Analyzer.REVERSE, get_settings())
    assert (task, queue.split(".")[-1]) == ("reverse.analyze", "reverse")


async def test_an_explicit_source_job_is_used(sent: SentJobs) -> None:
    reg = await register(org_name="RE Explicit Org")
    case_id = await new_case(reg)
    evidence_id, first = await rr.static_source(sent, reg, case_id=case_id)
    response = await rr.request_re(reg, evidence_id, source_job_id=str(first))
    assert response.status_code == 201, response.text
    assert sent[-1].re_source.job_id == first


async def test_an_elf_source_uses_its_lowest_allocated_section(sent: SentJobs) -> None:
    reg = await register(org_name="RE ELF Org")
    locations = {"create socket": [0x401020, 0x401010]}
    evidence_id, _ = await rr.static_source(
        sent,
        reg,
        content=rr.elf_bytes(),
        filename="sample.elf",
        info=rr.elf_info(),
        records=[*rr.elf_sections(), *rr.capabilities(locations)],
        capa_base=0x400000,
    )
    response = await rr.request_re(reg, evidence_id)
    assert response.status_code == 201, response.text
    source = sent[-1].re_source
    assert (source.file_format, source.preferred_base) == ("elf", 0x400000)
    assert source.capa_file_vas == (0x401010, 0x401020)


async def test_a_source_without_a_capa_base_sends_no_file_vas(sent: SentJobs) -> None:
    """A static job from before M10 (or capa reported no base): nothing to normalize."""
    reg = await register(org_name="RE No Base Org")
    evidence_id, _ = await rr.static_source(sent, reg, capa_base=None)
    response = await rr.request_re(reg, evidence_id)
    assert response.status_code == 201, response.text
    assert sent[-1].re_source.capa_file_vas == ()


async def test_quick_is_accepted_when_enabled(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "re_quick_enabled", True)
    reg = await register(org_name="RE Quick Org")
    evidence_id, _ = await rr.static_source(sent, reg)
    response = await rr.request_re(reg, evidence_id, profile="quick")
    assert response.status_code == 201, response.text
    assert sent[-1].profile == "quick" and sent[-1].decompile_addresses == ()
    refused = await rr.request_re(
        reg, evidence_id, profile="quick", decompile_addresses=["0x1400011e0"]
    )
    assert refused.status_code == 422


# --- refused --------------------------------------------------------------------------------


async def test_no_static_job_is_static_analysis_required(sent: SentJobs) -> None:
    reg = await register(org_name="RE No Static Org")
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), pe_bytes(), "a.exe")
    # The automatic static job is still queued: not a source.
    await _refused(reg, evidence["id"], 409, "static_analysis_required")
    # A plain file gets a static `av` job: never a source either.
    other = await upload(reg.client, reg.org_id, await new_case(reg), b"notes\n", "n.txt")
    await _refused(reg, other["id"], 409, "static_analysis_required")


async def test_an_explicit_source_must_qualify(sent: SentJobs) -> None:
    reg = await register(org_name="RE Bad Source Org")
    case_id = await new_case(reg)
    evidence_id, static_job = await rr.static_source(sent, reg, case_id=case_id)
    other_evidence, other_static = await rr.static_source(sent, reg, case_id=case_id)
    # Another evidence's static job, an unknown id, a non-static job.
    await _refused(reg, evidence_id, 409, "static_analysis_required",
                   source_job_id=str(other_static))  # fmt: skip
    await _refused(reg, evidence_id, 409, "static_analysis_required",
                   source_job_id=str(uuid.uuid4()))  # fmt: skip
    pcap = await upload(reg.client, reg.org_id, case_id, b"\xd4\xc3\xb2\xa1" + b"\0" * 20, "c.pcap")
    pcap_job = (await jobs_for(reg.client, reg.org_id, pcap["id"]))[0]["id"]
    await _refused(reg, evidence_id, 409, "static_analysis_required", source_job_id=pcap_job)
    assert static_job != other_static and other_evidence != evidence_id


async def test_another_orgs_static_job_is_not_a_source(sent: SentJobs) -> None:
    victim = await register(org_name="RE Victim Org")
    _, victim_static = await rr.static_source(sent, victim)
    reg = await register(org_name="RE Attacker Org")
    evidence_id, _ = await rr.static_source(sent, reg)
    await _refused(reg, evidence_id, 409, "static_analysis_required",
                   source_job_id=str(victim_static))  # fmt: skip


async def test_a_static_av_or_other_format_job_is_not_a_source(sent: SentJobs) -> None:
    reg = await register(org_name="RE Other Format Org")
    case_id = await new_case(reg)
    evidence = await upload(reg.client, reg.org_id, case_id, b"\x00" * 512, "blob.bin")
    item = sent[-1]
    assert item.profile == "av"
    raw = sr.lines(item.job_id, sr.sample_for(b"\x00" * 512), [], with_pe=False,
                   profile="av", file_format="other")  # fmt: skip
    await pr.deliver(item, pr.encode(raw))
    await _refused(reg, evidence["id"], 409, "static_analysis_required")


@pytest.mark.parametrize(
    ("info", "content", "filename"),
    [
        (lambda: rr.pe_info(machine="arm64"), pe_bytes, "arm.exe"),
        (lambda: rr.pe_info(machine="0x01c2"), pe_bytes, "thumb.exe"),
        (lambda: rr.elf_info(machine="EM_AARCH64"), rr.elf_bytes, "arm.elf"),
    ],
)
async def test_a_non_x86_source_is_unsupported_architecture(
    sent: SentJobs, info: Any, content: Any, filename: str
) -> None:
    reg = await register(org_name="RE Arch Org")
    evidence_id, _ = await rr.static_source(
        sent, reg, content=content(), filename=filename, info=info()
    )
    await _refused(reg, evidence_id, 422, "unsupported_architecture")


async def test_a_dotnet_pe_is_unsupported_managed_code(sent: SentJobs) -> None:
    reg = await register(org_name="RE Managed Org")
    evidence_id, _ = await rr.static_source(sent, reg, records=rr.managed_imports())
    await _refused(reg, evidence_id, 422, "unsupported_managed_code")


async def test_an_oversized_sample_is_refused(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    reg = await register(org_name="RE Size Org")
    evidence_id, _ = await rr.static_source(sent, reg)
    monkeypatch.setattr(get_settings(), "re_max_bytes", len(pe_bytes()) - 1)
    await _refused(reg, evidence_id, 413, "re_sample_too_large")


async def test_the_per_org_cap_refuses_a_second_active_job(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "re_max_active_per_org", 1)
    reg = await register(org_name="RE Org Cap Org")
    case_id = await new_case(reg)
    evidence_id, _ = await rr.static_source(sent, reg, case_id=case_id)
    t = Tenant(reg.org_id, reg.user_id, uuid.UUID(case_id))
    await seed_re_job(t, status="running", fixture=None)  # another evidence of the org
    response = await rr.request_re(reg, evidence_id)
    assert response.status_code == 429, response.text
    assert response.json()["error"]["code"] == "analysis_queue_full"
    assert len(await _reverse_jobs(reg.org_id)) == 1  # only the seeded one


async def test_a_second_request_on_the_same_evidence_is_analysis_active(sent: SentJobs) -> None:
    reg = await register(org_name="RE Active Org")
    evidence_id, _ = await rr.static_source(sent, reg)
    assert (await rr.request_re(reg, evidence_id)).status_code == 201
    again = await rr.request_re(reg, evidence_id)
    assert again.status_code == 409 and again.json()["error"]["code"] == "analysis_active"


async def test_a_viewer_cannot_request(sent: SentJobs) -> None:
    reg = await register(org_name="RE Reader Org")
    evidence_id, _ = await rr.static_source(sent, reg)
    email = unique_email()
    viewer_id = await make_user(email)
    await add_member(reg.org_id, viewer_id, MemberRole.VIEWER)
    viewer = await login(email)
    response = await viewer.post(
        f"/api/v1/orgs/{reg.org_id}/evidence/{evidence_id}/analyses",
        json={"analyzer": "reverse"},
        headers=csrf(viewer),
    )
    assert response.status_code == 403, response.text
    assert await _reverse_jobs(reg.org_id) == []


# --- never automatic ------------------------------------------------------------------------


async def test_no_upload_creates_a_reverse_job(sent: SentJobs) -> None:
    reg = await register(org_name="RE Never Auto Org")
    case_id = await new_case(reg)
    for content, name in ((pe_bytes(), "a.exe"), (rr.elf_bytes(), "a.elf"), (b"x" * 10, "t")):
        await upload(reg.client, reg.org_id, case_id, content, name)
    assert all(item.analyzer != Analyzer.REVERSE for item in sent)
    assert await _reverse_jobs(reg.org_id) == []
    settings = get_settings()
    for head in (pe_bytes(), rr.elf_bytes(), b"x" * 10):
        choice = auto_choice(head, len(head), settings)
        assert choice is None or choice[0] != Analyzer.REVERSE
