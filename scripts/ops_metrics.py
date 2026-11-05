"""`pnpm ops:metrics` (M7 phase 5): replay the M2 dataset and the M3 sample set through the
real workers and write plans/reports/ops-metric-YYMMDD.md from `job_outcomes`. A heavy step,
run alone. Phase 1 stub."""

import sys


def main() -> int:
    print("ops_metrics: not implemented in phase 1 (M7 phase 5 implements it)", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
