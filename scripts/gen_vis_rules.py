#!/usr/bin/env python3
"""Generate the materialized "make visible" range table (M6, RT24).

The ranges are computed once from the M5 character categories plus the vis-only extras
(`app.modules.ai.text.vis_category`: variation selectors, Hangul fillers, U+034F, U+2028 /
U+2029) under the api image's Python 3.12 `unicodedata`, and written to two byte-identical
copies:

- `packages/py-jobs/src/cyberlab_jobs/vis_rules.json` (renderer, API);
- `apps/web/lib/vis-rules.json` (report viewer).

Neither side evaluates "category Cf" at runtime, so browser ICU versions cannot drift.
Run it with the api image from the repo root:

  docker compose --profile test run --rm --no-deps -T -v "$PWD:/repo" -w /repo api-test \
    python scripts/gen_vis_rules.py          # write both copies
  ... python scripts/gen_vis_rules.py --check  # exit 1 when a copy differs

`apps/api/tests/unit/test_vis_rules.py` regenerates the table and compares both copies.
"""

import argparse
import json
import sys
import unicodedata
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUTPUTS = (
    REPO / "packages/py-jobs/src/cyberlab_jobs/vis_rules.json",
    REPO / "apps/web/lib/vis-rules.json",
)


def build() -> bytes:
    sys.path.insert(0, str(REPO / "apps/api"))
    from app.modules.ai.text import vis_category  # noqa: PLC0415 - needs the api on sys.path

    ranges: list[list[object]] = []
    for cp in range(0x110000):
        category = vis_category(cp)
        if category is None:
            continue
        if ranges and ranges[-1][1] == cp - 1 and ranges[-1][2] == category:
            ranges[-1][1] = cp
        else:
            ranges.append([cp, cp, category])
    data = {
        "version": 1,
        "source": "apps/api/app/modules/ai/text.py:vis_category",
        "unicode_version": unicodedata.unidata_version,
        "marker": "⟨U+XXXX⟩",
        "ranges": ranges,
    }
    return (json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="compare instead of writing")
    args = parser.parse_args()
    content = build()
    if args.check:
        stale = [str(p.relative_to(REPO)) for p in OUTPUTS if not p.exists() or p.read_bytes() != content]
        if stale:
            print(f"stale vis rules: {', '.join(stale)} (run scripts/gen_vis_rules.py)")
            return 1
        return 0
    for path in OUTPUTS:
        path.write_bytes(content)
        print(f"wrote {path.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
