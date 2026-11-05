"""HostileProvider scripts and ReplayProvider cassettes (no DB, no pipeline)."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.modules.ai.contracts import (
    AiTask,
    LlmProvider,
    ProviderError,
    ProviderErrorKind,
    ProviderRequest,
    ProviderResult,
    ProviderUsage,
)
from app.modules.ai.output_schema import AnalysisOutput, coerce_caps, provider_json_schema
from tests.ai_doubles import make_context
from tests.ai_eval import providers as p
from tests.ai_eval.inject_payloads import PAYLOADS, TI_CARRIERS, misp_summary, otx_summary

CTX = make_context()
CANARY = "CANARY-ABCDEF0123456789ABCDEF01"


def request(ctx=CTX, model: str = "m-1") -> ProviderRequest:  # type: ignore[no-untyped-def]
    return ProviderRequest(
        model=model,
        system="s",
        user="u",
        output_schema=provider_json_schema("mock"),
        max_output_tokens=100,
        context=ctx,
    )


@pytest.mark.parametrize("script", list(p.SCRIPTS))
async def test_every_script_is_valid_unless_it_breaks_the_schema(script: str) -> None:
    provider = p.HostileProvider(script)
    assert isinstance(provider, LlmProvider)
    provider.set_hints(p.EvalHints(canary=CANARY, foreign_label="F2"))
    result = await provider.analyze(request())
    expect = provider.expectations[-1]
    assert expect.script == script or script.startswith("canary")
    coerced, _ = coerce_caps(result.parsed)
    if expect.schema_invalid:
        with pytest.raises(ValidationError):
            AnalysisOutput.model_validate(coerced)
    else:
        AnalysisOutput.model_validate(coerced)


async def test_scripts_declare_their_ground_truth() -> None:
    async def run(script: str) -> p.Expect:
        provider = p.HostileProvider(script)
        provider.set_hints(p.EvalHints(canary=CANARY, foreign_label="F2"))
        await provider.analyze(request())
        return provider.expectations[-1]

    assert "F999" in (await run("invented_labels")).bad_labels
    assert (await run("cross_org")).foreign_label == "F2"
    assert (await run("trivial_quote")).bad_quotes
    assert len((await run("unanchored_quote")).unsupported) >= 1
    assert (await run("canary_spaced")).canary
    assert {"T1002", "T1043", "T9999"} <= (await run("bad_attack")).invalid_attack
    assert (await run("fabricated_timeline")).unsupported == {"timeline:0", "timeline:1"}
    assert (await run("oversize")).oversize


async def test_unanchored_claims_share_no_salient_token_with_their_quote() -> None:
    provider = p.HostileProvider("unanchored_quote")
    result = await provider.analyze(request())
    for claim in result.parsed["observed"][:-1]:
        quote = claim["citations"][0]["quote"].lower()
        words = [w.strip(".") for w in claim["text"].lower().split() if len(w) >= 4]
        assert not any(w in quote for w in words)


async def test_canary_variants_embed_the_canary() -> None:
    for variant, needle in (
        ("plain", CANARY),
        ("upper", CANARY.upper()),
        ("spaced", " ".join(CANARY)),
    ):
        provider = p.HostileProvider(f"canary_{variant}")
        provider.set_hints(p.EvalHints(canary=CANARY))
        result = await provider.analyze(request())
        assert any(needle in x for x in result.parsed["limitations"])


def test_unknown_script_is_refused() -> None:
    with pytest.raises(ValueError):
        p.HostileProvider("nope")
    with pytest.raises(ValueError):
        p.script_names(["links", "nope"])


async def test_replay_hits_misses_and_queues(tmp_path: Path) -> None:
    store = p.CassetteStore(tmp_path)
    key = p.CassetteKey("anthropic", "claude-sonnet-5", "m5.1", CTX.sha256)
    pending: list[p.PendingRequest] = []
    replay = p.ReplayProvider(
        store, provider="anthropic", model="claude-sonnet-5", prompt_version="m5.1", pending=pending
    )
    replay.set_hints(p.EvalHints(canary=CANARY, case="c", task="summarize_pcap"))
    with pytest.raises(p.CassetteMiss):
        await replay.analyze(request())
    assert len(pending) == 1 and pending[0].key == key and pending[0].case == "c"
    assert p.PendingRequest.from_json(pending[0].to_json()) == pending[0]
    ok = ProviderResult(
        parsed={"x": 1},
        usage=ProviderUsage(input_tokens=3),
        served_model="claude-sonnet-5",
        stop_reason="end_turn",
        request_id="req_secret",
    )
    refused = ProviderError(ProviderErrorKind.REFUSED, category="cyber")
    cassette = p.Cassette(
        key=key,
        case="c",
        stage="base",
        task="summarize_pcap",
        runs=[p.sanitize_result(ok), p.sanitize_error(refused)],
    )
    path = store.put(cassette)
    assert "req_secret" not in path.read_text(encoding="utf-8")
    assert store.get(key) == cassette and store.all() == [cassette]
    result = await replay.analyze(request())
    assert result.parsed == {"x": 1} and result.usage.input_tokens == 3
    assert replay.replayed
    second = p.ReplayProvider(
        store, provider="anthropic", model="claude-sonnet-5", prompt_version="m5.1", run=1
    )
    with pytest.raises(ProviderError) as exc:
        await second.analyze(request())
    assert exc.value.kind is ProviderErrorKind.REFUSED and exc.value.category == "cyber"
    third = p.ReplayProvider(
        store, provider="anthropic", model="claude-sonnet-5", prompt_version="m5.1", run=2
    )
    with pytest.raises(p.CassetteMiss):  # a missing run never falls back to another
        await third.analyze(request())
    other_ctx = make_context(task=AiTask.EXPLAIN_STATIC)
    with pytest.raises(p.CassetteMiss):  # another context is another key
        await replay.analyze(request(other_ctx))


def test_ti_payload_carriers_are_complete() -> None:
    misp, otx = misp_summary(injected=True, event="e"), otx_summary(injected=True, topic="t")
    assert misp["attributes"][0]["event_info"] == PAYLOADS["P1"]
    assert otx["pulses"][1]["name"] == PAYLOADS["P7"]
    assert set(TI_CARRIERS.values()) <= set(PAYLOADS)
    assert "attacker" not in str(misp_summary(injected=False, event="e"))
