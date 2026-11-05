"""CI floors of the AI evaluation over the real pipeline (M5 phase 6; no network).

HostileProvider over every case and every script: the exact floors of `scoring.violations`
(0 invalid / unverified citations counted as verified, 0 supported claims without a verified
citation, 0 supported observed claims on trivial or unanchored quotes, 0 links in the
persisted body, 0 cross-org refs accepted, 0 invalid ATT&CK shown, 0 schema-invalid outputs
persisted, 100% canary leaks caught, 100% stripped code points removed). FakeProvider on
every clean case: citation accuracy 1.0 and golden recall at the golden floor.

The builder, prompt, verifier and reduce are phases 4 and 5: while any of them is still the
phase-1 stub these tests skip with that reason (phase 11 confirms they run after the group-B
merge). `scripts/ai_eval.py` prints the tables they report (`pytest -s`).
"""

import pytest

from tests.ai_eval import harness, scoring
from tests.ai_eval.cases import case_names, clean_names
from tests.ai_eval.golden import load_golden
from tests.ai_eval.providers import SCRIPTS


async def _guarded(coro):  # type: ignore[no-untyped-def]
    try:
        return await coro
    except harness.PipelineNotReady as exc:
        pytest.skip(f"group-B pipeline not merged yet ({exc})")


async def test_hostile_provider_holds_every_floor_on_every_case() -> None:
    pipeline = harness.real_pipeline()
    scores: list[scoring.RunScore] = []
    for name in case_names():
        records = await _guarded(harness.run_hostile(name, pipeline, list(SCRIPTS)))
        scores += [scoring.score_run(r) for r in records]
    print("\n" + harness.report("HostileProvider (real pipeline, every case x script)", scores))
    expected_canary = [s for s in scores if (s.script or "").startswith("canary")]
    assert expected_canary and all(not s.violations for s in expected_canary)
    breaking = [s for s in scores if s.script in ("schema_break", "extra_fields")]
    assert breaking and all(s.outcome == "invalid_output" for s in breaking)
    assert [v for s in scores for v in s.violations] == []


async def test_fake_provider_is_fully_cited_on_clean_cases() -> None:
    pipeline = harness.real_pipeline()
    scores: list[scoring.RunScore] = []
    for name in clean_names():
        records = await _guarded(harness.run_fake(name, pipeline))
        scores += [scoring.score_run(r) for r in records]
    print("\n" + harness.report("FakeProvider (real pipeline, clean cases)", scores))
    problems = []
    for s in scores:
        if s.outcome != "ok" or s.violations:
            problems.append(f"{s.case}/{s.task}/{s.stage}: {s.outcome} {s.violations}")
        if s.citations_total and s.citation_accuracy != 1.0:
            problems.append(f"{s.case}/{s.task}/{s.stage}: accuracy {s.citation_accuracy}")
    for name in clean_names():
        golden = load_golden(name)
        floor = golden.recall_floor(fake=True)
        for s in scores:
            if s.case == name and s.final and floor is not None and s.recall is not None:
                if s.recall < floor:
                    problems.append(f"{name}/{s.task}: recall {s.recall:.2f} < {floor}")
    print("\n".join(problems))
    assert problems == []


async def test_contexts_do_not_depend_on_the_org() -> None:
    """Replay cassettes are keyed by context_sha256: seeding the same case into another org
    (other row ids, other salt) must give byte-identical contexts."""
    pipeline = harness.real_pipeline()
    for name in ("pcap_beacon", "static_downloader_imports", "incident_beacon_downloader"):
        first = await _guarded(harness.prepare(name, pipeline))
        second = await _guarded(harness.prepare(name, pipeline))
        for task, built in first.built.items():
            other = second.built[task]
            assert built.root.sha256 == other.root.sha256, (name, task)
            assert [c.sha256 for c in built.children] == [c.sha256 for c in other.children]
