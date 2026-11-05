"""The harness over the phase-1 doubles (reference context, trivial render, pass-through
verifier): the plumbing works before group B is merged, and the floors catch a permissive
verifier (the pass-through verifier marks every known-label citation verified)."""

from pathlib import Path

from app.modules.ai.contracts import (
    ProviderRequest,
    ProviderResult,
    VerifyOutcome,
    VerifyStatus,
)
from app.modules.ai.providers.fake import FakeProvider
from tests.ai_eval import harness, scoring
from tests.ai_eval.providers import (
    SCRIPTS,
    Cassette,
    CassetteKey,
    CassetteStore,
    EvalHints,
    PendingRequest,
    ReplayProvider,
    sanitize_result,
)

CASES = (
    "pcap_beacon",
    "pcap_beacon__injected",
    "static_downloader_imports__injected",
    "incident_beacon_downloader",
)


async def test_fake_over_doubles_is_fully_cited_and_recalls_the_golden_rows() -> None:
    pipeline = harness.doubles_pipeline()
    scores = []
    for name in CASES:
        scores += [scoring.score_run(r) for r in await harness.run_fake(name, pipeline)]
    print("\n" + harness.report("FakeProvider (doubles: reference context, pass-through)", scores))
    finals = [s for s in scores if s.final]
    assert {s.task for s in finals} >= {"summarize_pcap", "explain_finding", "incident_summary"}
    for s in scores:
        assert s.outcome == "ok" and s.citation_accuracy == 1.0 and not s.violations, s
    beacon = next(s for s in finals if s.case == "pcap_beacon" and s.task == "summarize_pcap")
    assert beacon.must_total == 1 and beacon.recall == 1.0
    incident = [s for s in scores if s.case == "incident_beacon_downloader"]
    assert [s.stage for s in incident] == ["child:1", "child:2", "reduce"]


async def test_floors_catch_a_permissive_verifier() -> None:
    pipeline = harness.doubles_pipeline()
    scores = []
    for name in ("pcap_beacon", "incident_beacon_downloader"):
        records = await harness.run_hostile(name, pipeline, list(SCRIPTS))
        scores += [scoring.score_run(r) for r in records]
    print(
        "\n" + harness.report("HostileProvider (doubles: pass-through verifier)", scores, detail=10)
    )
    kinds = {v.split(":", 1)[0] for s in scores for v in s.violations}
    # Each floor fires at least once against a verifier that checks only labels and schema.
    assert {
        "verified_bad_citation",
        "verified_trivial_quote",
        "verified_quote_not_in_field",
        "supported_without_verified",
        "supported_unanchored",
        "expected_unsupported_supported",
        "bad_ref_kept",
        "cross_org_accepted",
        "rendered_link",
        "strip_residue",
        "canary_missed",
    } <= kinds, kinds
    # The pass-through verifier still validates the schema: breaks are never persisted.
    breaking = [s for s in scores if s.script in ("schema_break", "extra_fields")]
    assert breaking and all(s.outcome == "invalid_output" and not s.violations for s in breaking)
    # Child stages of the incident are attacked too, and the reduce is the final answer.
    assert any(s.stage.startswith("child:") and s.provider == "hostile" for s in scores)


class Recorder:
    """A live stand-in: answers with FakeProvider and records sanitized cassettes."""

    name = "recorder"

    def __init__(self, store: CassetteStore, run: int) -> None:
        self.store, self.run, self.inner = store, run, FakeProvider()

    def set_hints(self, hints: EvalHints) -> None:
        self.hints = hints

    async def analyze(self, request: ProviderRequest) -> ProviderResult:
        result = await self.inner.analyze(request)
        assert request.context is not None
        key = CassetteKey("anthropic", "claude-sonnet-5", "doubles", request.context.sha256)
        cassette = self.store.get(key) or Cassette(
            key=key, case=self.hints.case, stage=self.hints.stage, task=self.hints.task
        )
        if len(cassette.runs) == self.run:
            cassette.runs.append(sanitize_result(result))
        self.store.put(cassette)
        return result

    async def count_tokens(self, request: ProviderRequest) -> int | None:
        return None

    async def verify(self) -> VerifyOutcome:
        return VerifyOutcome(status=VerifyStatus.VALID)

    async def aclose(self) -> None:
        return None


async def test_recorded_answers_replay_to_identical_metrics(tmp_path: Path) -> None:
    """The live path end to end without egress: record (n=2), then a fresh org replays the
    cassettes to the same metrics; a context that was never recorded is a miss, queued."""
    store = CassetteStore(tmp_path)
    pipeline = harness.doubles_pipeline()
    name = "incident_beacon_downloader__injected"

    def recorder(run: int) -> harness.CallSpec:
        return harness.CallSpec(Recorder(store, run), "anthropic", "claude-sonnet-5", run=run)

    first = [scoring.score_run(r) for r in await harness.run_provider(name, pipeline, recorder, 2)]
    pending: list[PendingRequest] = []

    def replay(run: int) -> harness.CallSpec:
        provider = ReplayProvider(
            store,
            provider="anthropic",
            model="claude-sonnet-5",
            prompt_version="doubles",
            run=run,
            pending=pending,
        )
        return harness.CallSpec(provider, "anthropic", "claude-sonnet-5", run=run)

    second = [scoring.score_run(r) for r in await harness.run_provider(name, pipeline, replay, 2)]
    assert pending == []
    assert [s.metrics() for s in first] == [s.metrics() for s in second]
    assert len(store.all()) == 3 and all(len(c.runs) == 2 for c in store.all())
    third = await harness.run_provider(name, pipeline, replay, 3)  # run 2 was never recorded
    assert {r.outcome for r in third if r.run == 2} == {"pending"}
    assert {p.run for p in pending} == {2} and pending[0].system and pending[0].user
