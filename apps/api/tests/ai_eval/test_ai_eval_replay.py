"""Every committed cassette re-verifies to its recorded metrics exactly (no network).

A regression guard for the verifier, the prompt and the context builder against recorded
real outputs: a changed context misses its cassette (`context_sha256` key), a changed prompt
version misses the whole set, and a changed verifier changes the metrics. Cassettes are only
recorded locally (`AI_EVAL_LIVE=1 python scripts/ai_eval.py --provider anthropic --record`);
with none committed, this test skips and says so (phase 11 records whether any exist).
"""

from collections import defaultdict

import pytest

from tests.ai_eval import harness, scoring
from tests.ai_eval.providers import Cassette, CassetteStore, ReplayProvider

STORE = CassetteStore()
CASSETTES = STORE.all()

pytestmark = pytest.mark.skipif(
    not CASSETTES,
    reason="no live cassettes recorded yet (AI_EVAL_LIVE=1 scripts/ai_eval.py ... --record)",
)


def _groups() -> dict[tuple[str, str, str], list[Cassette]]:
    groups: dict[tuple[str, str, str], list[Cassette]] = defaultdict(list)
    for cassette in CASSETTES:
        k = cassette.key
        groups[(k.provider, k.model, k.prompt_version)].append(cassette)
    return groups


async def test_cassettes_replay_to_their_recorded_metrics() -> None:
    pipeline = harness.real_pipeline()
    problems: list[str] = []
    scores: list[scoring.RunScore] = []
    for (provider, model, version), cassettes in sorted(_groups().items()):
        if version != pipeline.prompt_version:
            problems.append(
                f"{provider}/{model}: cassettes for prompt {version}, now {pipeline.prompt_version}"
            )
            continue
        by_sha = {c.key.context_sha256: c for c in cassettes}
        runs = max(len(c.runs) for c in cassettes)
        for case in sorted({c.case for c in cassettes}):

            def make(
                run: int, p: str = provider, m: str = model, v: str = version
            ) -> harness.CallSpec:
                replay = ReplayProvider(STORE, provider=p, model=m, prompt_version=v, run=run)
                return harness.CallSpec(replay, p, m, run=run, schema_provider=p)

            try:
                records = await harness.run_provider(case, pipeline, make, runs=runs)
            except harness.PipelineNotReady as exc:
                pytest.skip(f"group-B pipeline not merged yet ({exc})")
            for record in records:
                score = scoring.score_run(record)
                scores.append(score)
                cassette = by_sha.get(record.ctx.sha256)
                if record.outcome == "pending" or cassette is None:
                    problems.append(
                        f"{case} {record.task} {record.stage}: no cassette (context changed?)"
                    )
                    continue
                if record.run < len(cassette.metrics):
                    recorded = cassette.metrics[record.run]
                    if score.metrics() != recorded:
                        problems.append(
                            f"{case} {record.task} {record.stage} run {record.run}: metrics differ"
                        )
                if score.violations:
                    problems.append(f"{case} {record.stage}: violations {score.violations}")
    print("\n" + harness.report("Replay (committed cassettes)", scores))
    assert problems == []
