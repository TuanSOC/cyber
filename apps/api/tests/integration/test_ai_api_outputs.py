"""The output read model (M5 phase 7): claim statuses, citations resolved from the stored
rows, deep links for verified citations only, pseudonyms reversed vs kept, canary-leak
bodies never returned, refusal categories and incident child summaries (RT23)."""

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from app.core.tenancy import tenant_session
from app.modules.ai.contracts import (
    CitationReason,
    CitationResult,
    CitationStatus,
    ClaimStatus,
    ClaimVerdict,
    FrozenContext,
    OutputVerification,
    RefKind,
)
from app.modules.ai.service_outputs import reverser
from app.modules.analysis.models import AnalysisJob
from app.modules.pcap_analysis.models import NetworkRecord, TimelineEntry
from tests.ai_api_helpers import (
    API,
    AiSent,
    capture_ai_sends,
    enable_ai,
    finish_run,
    incident_builder,
    ref_of,
    request_run,
    tenant_of,
    use_fake_builder,
)
from tests.ai_doubles import make_context
from tests.ai_helpers import seed_job
from tests.factories import Registered, register

BODY: dict[str, Any] = {
    "observed": [
        {
            "id": "o1",
            "text": "Periodic beacon from INT_IP_1 to 203.0.113.50",
            "confidence": "high",
            "citations": [
                {"ref": "F1", "field": "title", "quote": "Periodic beacon from INT_IP_1"}
            ],
        },
        {
            "id": "o2",
            "text": "Host INT_IP_12 is clean",
            "confidence": "low",
            "citations": [{"ref": "F9", "quote": "clean host"}],
        },
    ],
    "interpretation": [
        {
            "id": "i1",
            "text": "Likely command and control",
            "confidence": "medium",
            "citations": [
                {"ref": "A1", "field": "signature", "quote": "Generic beacon pattern"},
                {"ref": "I1", "field": "value", "quote": "203"},
            ],
        }
    ],
    "hypotheses": [
        {
            "id": "h1",
            "text": "A commodity implant on INT_IP_1",
            "confidence": "low",
            "supporting": [{"ref": "N1"}],
            "contradicting": [],
        }
    ],
    "overall_confidence": {"level": "medium", "rationale": "INT_IP_1 beacons regularly"},
    "next_steps": [
        {"text": "Isolate INT_IP_1", "rationale": "Stops beaconing", "refs": ["F1", "Z9"]}
    ],
    "limitations": ["No payload bytes for INT_IP_1"],
    "attack_techniques": [
        {
            "technique_id": "T1071.001",
            "rationale": "HTTP C2",
            "citations": [{"ref": "C1", "field": "attack_ids", "quote": "T1071.001"}],
        }
    ],
    "timeline": [
        {
            "text": "First beacon",
            "citations": [
                {"ref": "E1", "field": "title", "quote": "First beacon connection observed"}
            ],
        }
    ],
}
CLAIMS = {
    "o1": ClaimVerdict(status=ClaimStatus.SUPPORTED),
    "o2": ClaimVerdict(status=ClaimStatus.UNSUPPORTED, reason=CitationReason.NO_VERIFIED_CITATION),
    "i1": ClaimVerdict(status=ClaimStatus.SUPPORTED),
    "h1": ClaimVerdict(status=ClaimStatus.HYPOTHESIS),
    "attack:T1071.001": ClaimVerdict(status=ClaimStatus.SUPPORTED),
    "timeline:0": ClaimVerdict(status=ClaimStatus.SUPPORTED),
}


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> AiSent:
    use_fake_builder(monkeypatch)
    return capture_ai_sends(monkeypatch)


def _cite(
    ctx: FrozenContext,
    path: str,
    label: str,
    status: CitationStatus = CitationStatus.VERIFIED,
    reason: CitationReason | None = None,
    **extra: Any,
) -> CitationResult:
    section = path.split("[", 1)[0]
    ref = next((r for r in ctx.refs if r.label == label), None)
    return CitationResult(
        claim_path=path,
        section=section,
        label=label,
        kind=ref.kind if ref else None,
        ref_id=ref.ref_id if ref else None,
        job_id=ref.job_id if ref else None,
        status=status,
        reason=reason,
        **extra,
    )


def _citations(ctx: FrozenContext) -> list[CitationResult]:
    invalid, unverified = CitationStatus.INVALID, CitationStatus.UNVERIFIED
    return [
        _cite(
            ctx,
            "observed[0].citations[0]",
            "F1",
            field="title",
            quote="Periodic beacon from INT_IP_1",
        ),
        _cite(ctx, "observed[1].citations[0]", "F9", invalid, CitationReason.UNKNOWN_LABEL),
        _cite(ctx, "interpretation[0].citations[0]", "A1", field="signature"),
        _cite(
            ctx, "interpretation[0].citations[1]", "I1", unverified, CitationReason.QUOTE_TOO_SHORT
        ),
        _cite(ctx, "hypotheses[0].supporting[0]", "N1"),
        _cite(ctx, "next_steps[0].refs[0]", "F1"),
        _cite(ctx, "next_steps[0].refs[1]", "Z9", invalid, CitationReason.UNKNOWN_LABEL),
        _cite(ctx, "attack_techniques[0].citations[0]", "C1"),
        _cite(ctx, "timeline[0].citations[0]", "E1", stale=True),
    ]


async def _completed(owner: Registered, **finish: Any) -> tuple[str, uuid.UUID, FrozenContext]:
    job_id = await seed_job(await tenant_of(owner))
    created = await request_run(
        owner.client, owner.org_id, task="summarize_pcap", job_id=str(job_id)
    )
    assert created.status_code == 202, created.text
    run_id = created.json()["run"]["id"]
    ctx = make_context(job_id=job_id)
    defaults: dict[str, Any] = {
        "body": BODY,
        "citations": _citations(ctx),
        "verification": OutputVerification(
            claims=CLAIMS,
            citations={CitationStatus.VERIFIED: 6, CitationStatus.INVALID: 2},
            dropped_refs=1,
        ),
        "metrics": {"version": "v1", "citations_total": 9, "citation_accuracy": 0.67},
        "usage": {"input_tokens": 900, "output_tokens": 100},
    }
    await finish_run(owner.org_id, run_id, **{**defaults, **finish})
    return run_id, job_id, ctx


async def test_claims_citations_and_deep_links(sent: AiSent) -> None:
    owner = await register()
    await enable_ai(owner.client, owner.org_id)
    run_id, job_id, ctx = await _completed(owner)
    response = await owner.client.get(f"{API}/{owner.org_id}/ai/runs/{run_id}")
    assert response.status_code == 200, response.text
    detail = response.json()
    assert detail["status"] == "completed" and detail["output_withheld"] is False
    assert detail["usage"]["total_tokens"] == 1000 and detail["citation_accuracy"] == 0.67
    out = detail["output"]
    observed = out["observed"]
    assert [c["status"] for c in observed] == ["supported", "unsupported"]
    assert observed[1]["reason"] == "no_verified_citation"
    f1 = observed[0]["citations"][0]
    assert f1["status"] == "verified" and f1["kind"] == "finding" and f1["field"] == "title"
    assert f1["link"] == {
        "route": "pcap",
        "job_id": str(job_id),
        "tab": "findings",
        "ref": ref_of(ctx, "F1").ref_id,
    }
    invalid = observed[1]["citations"][0]
    assert invalid["status"] == "invalid" and invalid["reason"] == "unknown_label"
    assert invalid["link"] is None and invalid["ref_id"] is None
    [alert, ioc] = out["interpretation"][0]["citations"]
    assert alert["link"]["tab"] == "alerts" and alert["link"]["ref"] == ref_of(ctx, "A1").ref_id
    assert ioc["status"] == "unverified" and ioc["reason"] == "quote_too_short"
    assert ioc["link"] is None  # never a link for an unverified citation
    [hypothesis] = out["hypotheses"]
    assert hypothesis["status"] == "hypothesis"
    assert hypothesis["supporting"][0]["link"]["tab"] == "flows"
    [step] = out["next_steps"]
    assert [r["status"] for r in step["refs"]] == ["verified", "invalid"]
    assert step["refs"][0]["link"]["tab"] == "findings" and step["refs"][1]["link"] is None
    [attack] = out["attack_techniques"]
    assert attack["status"] == "supported" and attack["citations"][0]["link"] is None  # C on pcap
    [entry] = out["timeline"]
    assert entry["citations"][0]["stale"] is True
    assert entry["citations"][0]["link"]["tab"] == "timeline"
    assert entry["ts"] is None  # the cited row does not exist: no time is invented
    assert out["verification"]["citations"] == {"verified": 6, "invalid": 2}
    assert out["verification"]["dropped_refs"] == 1

    def keys(node: Any) -> set[str]:
        if isinstance(node, dict):
            return set(node) | {k for v in node.values() for k in keys(v)}
        if isinstance(node, list):
            return {k for v in node for k in keys(v)}
        return set()

    assert not keys(out) & {"url", "href", "uri", "link_url"}  # no free-form URL field


async def test_pseudonyms_are_reversed_unless_kept(sent: AiSent) -> None:
    owner = await register()
    await enable_ai(owner.client, owner.org_id)
    run_id, _, _ = await _completed(owner)
    url = f"{API}/{owner.org_id}/ai/runs/{run_id}"
    reversed_ = (await owner.client.get(url)).json()["output"]
    assert reversed_["pseudonyms"] == "reversed"
    assert reversed_["observed"][0]["text"] == "Periodic beacon from 10.0.2.20 to 203.0.113.50"
    assert reversed_["observed"][0]["citations"][0]["quote"] == "Periodic beacon from 10.0.2.20"
    assert reversed_["observed"][1]["text"] == "Host INT_IP_12 is clean"  # whole tokens only
    assert reversed_["overall_confidence"]["rationale"] == "10.0.2.20 beacons regularly"
    assert reversed_["next_steps"][0]["text"] == "Isolate 10.0.2.20"
    assert reversed_["limitations"] == ["No payload bytes for 10.0.2.20"]
    kept = (await owner.client.get(url, params={"pseudonyms": "keep"})).json()["output"]
    assert kept["pseudonyms"] == "kept" and "10.0.2.20" not in json.dumps(kept)
    assert kept["observed"][0]["text"] == BODY["observed"][0]["text"]


async def test_timeline_time_comes_from_the_first_verified_cited_row(sent: AiSent) -> None:
    owner = await register()
    await enable_ai(owner.client, owner.org_id)
    tenant = await tenant_of(owner)
    pcap_job, static_job = await seed_job(tenant), await seed_job(tenant, "static")
    seen = datetime(2026, 11, 5, 10, 0, 7, tzinfo=UTC)
    async with tenant_session(owner.org_id, None) as s:
        row = TimelineEntry(
            organization_id=owner.org_id,
            job_id=pcap_job,
            ts=seen,
            event="alert",
            title="First beacon connection observed",
        )
        s.add(row)
        await s.flush()
        timeline_id = str(row.id)
        job = await s.get(AnalysisJob, static_job)
        assert job is not None
        job_time = job.finished_at or job.created_at
    created = await request_run(
        owner.client, owner.org_id, task="summarize_pcap", job_id=str(pcap_job)
    )
    run_id = created.json()["run"]["id"]
    ctx = make_context(job_id=pcap_job)
    body = {
        "timeline": [
            {"text": "First beacon", "citations": [{"ref": "F9"}, {"ref": "E1"}]},
            {"text": "Model says 1999-01-01", "citations": [{"ref": "A1"}]},
            {"text": "Sample analyzed", "citations": [{"ref": "S1"}]},
        ],
        "overall_confidence": {"level": "low", "rationale": "-"},
    }
    e1 = _cite(ctx, "timeline[0].citations[1]", "E1").model_copy(update={"ref_id": timeline_id})
    signature = CitationResult(
        claim_path="timeline[2].citations[0]",
        section="timeline",
        label="S1",
        kind=RefKind.SIGNATURE,
        ref_id=str(uuid.uuid4()),
        job_id=static_job,
        status=CitationStatus.VERIFIED,
    )
    citations = [
        _cite(ctx, "timeline[0].citations[0]", "F9", CitationStatus.INVALID),
        e1,
        _cite(ctx, "timeline[1].citations[0]", "A1"),  # its row does not exist
        signature,
    ]
    await finish_run(owner.org_id, run_id, body=body, citations=citations)
    out = (await owner.client.get(f"{API}/{owner.org_id}/ai/runs/{run_id}")).json()["output"]
    first, second, third = out["timeline"]
    assert datetime.fromisoformat(first["ts"]) == seen  # the row's time, not model text
    assert second["ts"] is None
    assert datetime.fromisoformat(third["ts"]) == job_time  # static rows: the analysis time


def test_reverser_replaces_whole_tokens_only() -> None:
    swap = reverser({"INT_IP_1": "10.0.0.1", "INT_IP_12": "10.0.0.12", "USER_2": "alice"})
    assert swap("INT_IP_12 and INT_IP_1, USER_2/USER_23 xINT_IP_1") == (
        "10.0.0.12 and 10.0.0.1, alice/USER_23 xINT_IP_1"
    )
    assert reverser({})("INT_IP_1") == "INT_IP_1"


async def test_canary_leak_body_is_never_returned(sent: AiSent) -> None:
    owner = await register()
    await enable_ai(owner.client, owner.org_id)
    run_id, _, _ = await _completed(
        owner, status="failed", error_code="canary_leak", flags=["canary_leak"]
    )
    response = await owner.client.get(f"{API}/{owner.org_id}/ai/runs/{run_id}")
    detail = response.json()
    assert detail["status"] == "failed" and detail["error_code"] == "canary_leak"
    assert detail["output"] is None and detail["output_withheld"] is True
    assert detail["flags"] == ["canary_leak"]
    assert "Periodic beacon" not in response.text and "INT_IP_1 beacons" not in response.text
    # A completed run whose output carries the flag is withheld too (defence in depth).
    other, _, _ = await _completed(owner, flags=["canary_leak", "verdict_language"])
    flagged = (await owner.client.get(f"{API}/{owner.org_id}/ai/runs/{other}")).json()
    assert flagged["output"] is None and flagged["output_withheld"] is True


async def test_refused_run_returns_its_category(sent: AiSent) -> None:
    owner = await register()
    await enable_ai(owner.client, owner.org_id)
    job_id = await seed_job(await tenant_of(owner))
    created = await request_run(
        owner.client, owner.org_id, task="summarize_pcap", job_id=str(job_id)
    )
    run_id = created.json()["run"]["id"]
    await finish_run(
        owner.org_id,
        run_id,
        status="refused",
        error_code="refused",
        metrics={"version": "v1", "refusal_category": "cyber"},
    )
    detail = (await owner.client.get(f"{API}/{owner.org_id}/ai/runs/{run_id}")).json()
    assert detail["status"] == "refused" and detail["refusal_category"] == "cyber"
    assert detail["output"] is None and detail["output_withheld"] is False
    listing = (await owner.client.get(f"{API}/{owner.org_id}/ai/runs")).json()
    assert listing["items"][0]["refusal_category"] == "cyber"


async def test_static_evidence_and_record_links(
    sent: AiSent, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = await register()
    await enable_ai(owner.client, owner.org_id)
    tenant = await tenant_of(owner)
    static_job = await seed_job(tenant, "static")
    pcap_job = await seed_job(tenant)
    async with tenant_session(owner.org_id, None) as s:
        record = NetworkRecord(
            organization_id=owner.org_id,
            job_id=pcap_job,
            ts=datetime.now(UTC),
            kind="http",
            summary="GET /",
            details={},
        )
        s.add(record)
        await s.flush()
        record_id = str(record.id)
    items = (
        (RefKind.SAMPLE, {"sha256": "b" * 64, "size": 1024}),
        (RefKind.SIGNATURE, {"engine": "yara", "rule": "Packed_Generic"}),
        (RefKind.STRING, {"value": "hxxp://evil[.]example/x"}),
        (RefKind.EVIDENCE, {"filename": "sample.bin"}),
        (RefKind.DIGEST_CLAIM, {"text": "a child claim"}),
    )
    ctx = make_context(task="explain_static", job_id=static_job, items=items)  # type: ignore[arg-type]
    created = await request_run(
        owner.client, owner.org_id, task="explain_static", job_id=str(static_job)
    )
    run_id = created.json()["run"]["id"]
    labels = ["M1", "S1", "X1", "K1", "D1"]
    body = {
        "observed": [
            {
                "id": f"o{n}",
                "text": f"claim {label}",
                "confidence": "low",
                "citations": [{"ref": label}],
            }
            for n, label in enumerate([*labels, "R1"])
        ],
        "overall_confidence": {"level": "low", "rationale": "-"},
    }
    citations = [_cite(ctx, f"observed[{n}].citations[0]", label) for n, label in enumerate(labels)]
    record_ref = CitationResult(
        claim_path="observed[5].citations[0]",
        section="observed",
        label="R1",
        kind=RefKind.RECORD,
        ref_id=record_id,
        job_id=pcap_job,
        status=CitationStatus.VERIFIED,
    )
    await finish_run(owner.org_id, run_id, body=body, citations=[*citations, record_ref])
    out = (await owner.client.get(f"{API}/{owner.org_id}/ai/runs/{run_id}")).json()["output"]
    links = [c["citations"][0]["link"] for c in out["observed"]]
    sample, signature, string, evidence, digest, rec = links
    assert sample == {"route": "malware", "job_id": str(static_job), "tab": "overview", "ref": None}
    assert signature["tab"] == "signatures" and signature["ref"] == ref_of(ctx, "S1").ref_id
    assert string["tab"] == "strings"
    assert evidence == {
        "route": "evidence",
        "job_id": None,
        "tab": None,
        "ref": ref_of(ctx, "K1").ref_id,
    }
    assert digest is None  # digest claims are never evidence
    assert rec == {"route": "pcap", "job_id": str(pcap_job), "tab": "http", "ref": record_id}
    # Claims without a stored verdict are never shown as backed by evidence.
    assert {c["status"] for c in out["observed"]} == {"unsupported"}


async def test_incident_parent_shows_child_flags(
    sent: AiSent, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = await register()
    await enable_ai(owner.client, owner.org_id)
    tenant = await tenant_of(owner)
    jobs = [await seed_job(tenant), await seed_job(tenant)]
    use_fake_builder(monkeypatch, build=incident_builder(jobs))
    created = await request_run(
        owner.client,
        owner.org_id,
        task="incident_summary",
        investigation_id=str(tenant.investigation_id),
    )
    parent = created.json()["run"]["id"]
    detail = (await owner.client.get(f"{API}/{owner.org_id}/ai/runs/{parent}")).json()
    children = {c["job_id"]: c["id"] for c in detail["child_runs"]}
    minimal = {"overall_confidence": {"level": "low", "rationale": "-"}}
    await finish_run(
        owner.org_id,
        children[str(jobs[0])],
        body=minimal,
        flags=["verdict_language"],
        metrics={"version": "v1", "citation_accuracy": 1.0},
    )
    await finish_run(owner.org_id, children[str(jobs[1])], status="failed", error_code="max_tokens")
    await finish_run(owner.org_id, parent, status="partial", body=minimal)
    detail = (await owner.client.get(f"{API}/{owner.org_id}/ai/runs/{parent}")).json()
    assert detail["status"] == "partial" and detail["output"] is not None
    by_job = {c["job_id"]: c for c in detail["child_runs"]}
    assert by_job[str(jobs[0])]["flags"] == ["verdict_language"]
    assert by_job[str(jobs[0])]["citation_accuracy"] == 1.0
    assert by_job[str(jobs[1])]["status"] == "failed"
    assert by_job[str(jobs[1])]["error_code"] == "max_tokens"
    # A child's own detail reverses with the tree's map too.
    child = (
        await owner.client.get(f"{API}/{owner.org_id}/ai/runs/{children[str(jobs[0])]}")
    ).json()
    assert child["parent_run_id"] == parent and child["task"] == "job_digest"
