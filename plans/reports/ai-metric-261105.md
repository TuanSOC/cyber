# AI evidence citation accuracy (M5 metric), 2026-11-05

Requirement §14 "AI evidence citation accuracy". Command: `python scripts/ai_eval.py` (offline, the main test lane), after `python scripts/ai_eval_snapshot.py` regenerated the 51 cases (26 clean, 25 injected twins with payloads P1–P8) from the real pcap and static pipelines.

| Provider (label) | Runs | Citation accuracy mean / min | Unsupported mean | Invalid-ref mean | ATT&CK invalid proposed / shown | ATT&CK precision mean | Golden recall mean / min | Refused / invalid / error | ASR | Utility under attack | Floor violations |
|---|---|---|---|---|---|---|---|---|---|---|---|
| FakeProvider (**fake**, pipeline only; 26 clean cases, 31 case × task runs) | 31 | 1.000 / 1.000 | 0.005 | 0.000 | 0 / 0 | 1.000 | 0.895 / 0.000 (each case at its `fake_min_recall` floor) | 0 / 0 / 0 | n/a (clean cases) | n/a | **0** |
| HostileProvider (**hostile**, adversarial scripts; every case × 20 scripts) | 1220 | 0.772 / 0.111 | 0.241 | 0.154 | 488 / **0** | 0.361 | 0.048 / 0.000 | 0 / 122 / 0 | 0.290 (canary leak 84, external URL 28, forbidden verdict 20, severity downgrade 14: each caught and withheld, flagged or hidden) | 1.000 | **0** |
| Replay (**replayed**) | 0 | no cassettes committed | | | | | | | | | |
| Live Anthropic / Gemini (**live**) | 0 | **none recorded**: no key available locally | | | | | | | | | |

Recorded 2026-11-05 (`python scripts/ai_eval.py`, offline) over the cases regenerated that day from the real pipelines (`scripts/ai_eval_snapshot.py`: pcap-worker-test and static-worker-test on the synthetic dataset and samples, normalized rows only; `provenance.source = pipeline`). Tokens, cost and latency (p50 / p95) and the per-payload ASR (P1–P8) are only meaningful for a model and have no value until a live or replayed run exists. The HostileProvider "ASR" counts the attacks its scripts attempt, not attacks that got through: the floor violations column (0) is the gate.

Provenance labels: **fake** = FakeProvider, a rule-based baseline that proves the pipeline only; **hostile** = HostileProvider, adversarial scripts that prove the verifier's floors; **replayed** = recorded cassettes (none); **live** = a real model (none: no key was available locally, so nothing was recorded). The CI floors (exact invariants, `tests/ai_eval/test_ai_eval_invariants.py`) all hold. The live floors (citation accuracy ≥ 0.95, unsupported ≤ 0.05, integrity ASR ≤ 0.05, utility ≥ 0.9) have no value yet: run `AI_EVAL_LIVE=1 python scripts/ai_eval.py --provider anthropic --model claude-sonnet-5 --runs 3 --record --write` with a key in `.secrets/`.
