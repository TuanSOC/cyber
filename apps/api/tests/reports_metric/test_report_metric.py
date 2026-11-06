"""M6 §14 report metrics (phase 9): citation resolution accuracy, render success and latency
per format, deterministic render rate, hostile escapes, and `scripts/verify_report.py` pass
and tamper-detection rates, over a synthetic dataset (see `harness`).

Opt-in and heavy (real renders: ~20 cases x 2 versions x 3 formats, each rendered twice):
needs REPORT_METRIC=1, the `metric` marker, `scripts/` mounted (api-test: /srv/scripts) and
`report-worker-test` consuming this lane's broker db. Run it with the host wrapper, which
prints the table and writes `plans/reports/report-metric-<YYMMDD>.md`:

  python scripts/report_metric.py --write

or directly (default lane, `docker compose --profile test up -d report-worker-test` first):

  docker compose --profile test run --rm --no-deps -e REPORT_METRIC=1 api-test \\
      uv run pytest -q -s -p no:cacheprovider -m metric tests/reports_metric

Environment: REPORT_METRIC_CASES (default 20, at least 4); REPORT_METRIC_OUT (a directory:
the golden PDF is written there for the wrapper's optional veraPDF run).

Floors (asserted): no case setup error; citation resolution accuracy 1.0; render success
1.0 per format on non-hostile cases; hostile renders end `succeeded` or a typed failure;
deterministic render rate 1.0; hostile escapes 0; verify pass rate 1.0; tamper detection 1.0.
"""

import asyncio
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.analysis_helpers import purge_test_queues
from tests.report_helpers import SigningKeys, purge_reports_test_bucket, use_signing_keys
from tests.reports_metric.harness import DEFAULT_CASES, Runner, floors, render_table
from tests.unit.test_verify_report_script import SCRIPT

BEGIN = "=== REPORT METRIC BEGIN ==="
END = "=== REPORT METRIC END ==="
REAL_TIMEOUT_S = 3 * 3600

pytestmark = [
    pytest.mark.metric,
    pytest.mark.skipif(
        not os.environ.get("REPORT_METRIC") or SCRIPT is None,
        reason="REPORT_METRIC=1, scripts/ mounted, report-worker-test on this lane's broker db",
    ),
]


@pytest.fixture
def keys(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[SigningKeys]:
    yield use_signing_keys(monkeypatch, tmp_path)
    purge_reports_test_bucket()


async def test_report_metric(keys: SigningKeys, tmp_path: Path) -> None:
    assert SCRIPT is not None
    cases = int(os.environ.get("REPORT_METRIC_CASES") or DEFAULT_CASES)
    purge_test_queues()
    runner = Runner(keys, tmp_path, SCRIPT, cases)
    async with asyncio.timeout(REAL_TIMEOUT_S):
        metric = await runner.run()

    out = os.environ.get("REPORT_METRIC_OUT")
    if out and metric.golden_pdf is not None:
        target = Path(out)
        target.mkdir(parents=True, exist_ok=True)
        (target / "golden.pdf").write_bytes(metric.golden_pdf)

    print(f"\n{BEGIN}\n{render_table(metric)}\n{END}")
    failed = [f"{f.name}: {f.detail}" for f in floors(metric) if not f.ok]
    assert not failed, failed
