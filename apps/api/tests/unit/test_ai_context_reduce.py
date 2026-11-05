"""Incident reduce context: digest-claim items and copied child items (M5 phase 4)."""

import uuid

import pytest

from app.core.config import get_settings
from app.modules.ai.context.estimate import PROMPT_OVERHEAD_TOKENS
from app.modules.ai.context.reduce import build_reduce_context
from app.modules.ai.contracts import (
    AiScope,
    AiTask,
    CitationResult,
    CitationStatus,
    ClaimStatus,
    ClaimVerdict,
    DigestInput,
    FrozenContext,
    OutputFlag,
    RefKind,
    RunScope,
)
from app.modules.ai.labels import parse_label
from app.modules.ai.output_schema import AnalysisOutput
from tests.ai_doubles import fields_sha256, make_context

INVESTIGATION = uuid.UUID(int=99)
JOBS = (uuid.UUID(int=1), uuid.UUID(int=2))


def _base() -> FrozenContext:
    scope = RunScope(scope=AiScope.INVESTIGATION, job_ids=JOBS, investigation_id=INVESTIGATION)
    return make_context(
        task=AiTask.INCIDENT_SUMMARY,
        job_id=JOBS[0],
        scope=scope,
        items=(
            (RefKind.INVESTIGATION, {"case_ref": "CASE-00001"}),
            (RefKind.JOB, {"analyzer": "pcap"}),
        ),
        pseudonym_map={},
    )


def _citation(
    claim_id: str, label: str, status: CitationStatus, section: str = "observed"
) -> CitationResult:
    return CitationResult(
        claim_path=f"{section}[0].citations[0]",
        section=section,  # type: ignore[arg-type]
        claim_id=claim_id,
        label=label,
        status=status,
    )


def _digest(n: int, flags: tuple[OutputFlag, ...] = ()) -> DigestInput:
    child = make_context(task=AiTask.JOB_DIGEST, job_id=JOBS[n - 1])
    body = AnalysisOutput.model_validate(
        {
            "observed": [
                {"id": "o1", "text": "Beacon from INT_IP_1 to 203.0.113.50", "confidence": "high"},
                {"id": "o2", "text": "Unsupported statement", "confidence": "low"},
            ],
            "interpretation": [{"id": "i1", "text": "Likely C2 polling", "confidence": "medium"}],
            "hypotheses": [{"id": "h1", "text": "Implant on the host", "confidence": "low"}],
            "overall_confidence": {"level": "medium", "rationale": "r"},
        }
    )
    return DigestInput(
        run_id=uuid.UUID(int=100 + n),
        job_id=JOBS[n - 1],
        job_label=f"J{n}",
        context=child,
        body=body,
        claims={
            "o1": ClaimVerdict(status=ClaimStatus.SUPPORTED),
            "o2": ClaimVerdict(status=ClaimStatus.UNSUPPORTED),
            "i1": ClaimVerdict(status=ClaimStatus.SUPPORTED),
            "h1": ClaimVerdict(status=ClaimStatus.HYPOTHESIS),
        },
        citations=(
            _citation("o1", "F1", CitationStatus.VERIFIED),
            _citation("o1", "N1", CitationStatus.VERIFIED),
            _citation("o1", "A1", CitationStatus.UNVERIFIED),
            _citation("o2", "I1", CitationStatus.VERIFIED),
            _citation("i1", "F1", CitationStatus.VERIFIED, "interpretation"),
            _citation("i1", "X9", CitationStatus.INVALID, "interpretation"),
        ),
        flags=flags,
    )


def test_digest_claims_and_copied_items() -> None:
    base = _base()
    ctx = build_reduce_context(base, [_digest(1), _digest(2, (OutputFlag.VERDICT_LANGUAGE,))])
    labels = [i.label for i in ctx.items]
    assert labels[:2] == ["V1", "J1"]
    assert labels[2:] == [
        "J1:D1",
        "J1:D2",
        "J1:D3",
        "J2:D1",
        "J2:D2",
        "J2:D3",
        "J1:F1",
        "J1:N1",
        "J2:F1",
        "J2:N1",
    ]
    d1 = ctx.item("J1:D1")
    assert d1 is not None and d1.kind is RefKind.DIGEST_CLAIM
    assert d1.fields == {
        "kind": "digest_claim",
        "section": "observed",
        "text": "Beacon from INT_IP_1 to 203.0.113.50",
        "confidence": "high",
        "citations": "J1:F1, J1:N1",
        "untrusted": "model_output",
        "flags": "",
    }
    assert ctx.item("J1:D3").fields["section"] == "hypothesis"  # type: ignore[union-attr]
    assert ctx.item("J2:D2").fields["flags"] == "verdict_language"  # type: ignore[union-attr]
    # Unsupported claims and non-verified citations never make it in.
    assert all("Unsupported statement" not in str(i.fields) for i in ctx.items)
    assert ctx.item("J1:I1") is None and ctx.item("J1:A1") is None


def test_copied_items_keep_the_child_values_and_refs() -> None:
    digest = _digest(1)
    ctx = build_reduce_context(_base(), [digest])
    child_f1 = digest.context.item("F1")
    copied = ctx.item("J1:F1")
    assert child_f1 is not None and copied is not None
    assert copied.fields == child_f1.fields
    ref = next(r for r in ctx.refs if r.label == "J1:F1")
    child_ref = next(r for r in digest.context.refs if r.label == "F1")
    assert (ref.ref_id, ref.ref_table, ref.job_id, ref.stage) == (
        child_ref.ref_id,
        child_ref.ref_table,
        child_ref.job_id,
        "reduce",
    )
    assert ref.fields_sha256 == fields_sha256(copied.fields)
    d_ref = next(r for r in ctx.refs if r.label == "J1:D1")
    assert (d_ref.kind, d_ref.ref_table, d_ref.ref_id, d_ref.stage) == (
        RefKind.DIGEST_CLAIM,
        "ai_runs",
        str(digest.run_id),
        "reduce",
    )
    assert all(parse_label(i.label) is not None for i in ctx.items)


def test_stats_hash_and_pseudonyms() -> None:
    base = _base()
    digests = [_digest(1), _digest(2)]
    a = build_reduce_context(base, digests)
    b = build_reduce_context(base, digests)
    assert a.canonical_json() == b.canonical_json() and a.sha256 == b.sha256
    assert a.sha256 != base.sha256
    assert a.stats.per_kind[RefKind.DIGEST_CLAIM].model_dump() == {"included": 6, "total": 6}
    assert a.stats.per_kind[RefKind.FINDING].model_dump() == {"included": 2, "total": 2}
    assert a.stats.per_kind[RefKind.INVESTIGATION] == base.stats.per_kind[RefKind.INVESTIGATION]
    assert a.pseudonym_map == {"INT_IP_1": "10.0.2.20"}  # from the child maps, used in the text
    assert a.stats.pseudonymized == {"ip": 1}
    assert (a.task, a.scope) == (base.task, base.scope)


def test_budget_cuts_copies_after_claims(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "ai_max_input_tokens", PROMPT_OVERHEAD_TOKENS + 300)
    ctx = build_reduce_context(_base(), [_digest(1), _digest(2)])
    kinds = [i.kind for i in ctx.items[2:]]
    assert kinds and kinds[0] is RefKind.DIGEST_CLAIM
    assert ctx.stats.omitted > 0 and ctx.stats.truncated
    assert len(ctx.canonical_json()) <= 300 * 3


def test_no_digests_is_the_base() -> None:
    base = _base()
    ctx = build_reduce_context(base, [])
    assert ctx.items == base.items and ctx.sha256 == base.sha256
