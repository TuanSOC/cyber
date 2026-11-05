"""The materialized "make visible" table (M6 phase 1, RT24): `vis_rules.json` in py-jobs is
exactly what `scripts/gen_vis_rules.py` computes from the M5 `ai/text.py` categories under
this image's Python 3.12 `unicodedata`; `cyberlab_jobs.vis.vis` applies it. The web copy
(`apps/web/lib/vis-rules.json`) is compared byte for byte by `apps/web/lib/tlp.test.ts`."""

import json
import unicodedata
from importlib import resources

from cyberlab_jobs import vis

from app.modules.ai.text import _category


def _expected() -> bytes:
    ranges: list[list[object]] = []
    for cp in range(0x110000):
        category = _category(cp)
        if category is None:
            continue
        if ranges and ranges[-1][1] == cp - 1 and ranges[-1][2] == category:
            ranges[-1][1] = cp
        else:
            ranges.append([cp, cp, category])
    data = {
        "version": 1,
        "source": "apps/api/app/modules/ai/text.py:_category",
        "unicode_version": unicodedata.unidata_version,
        "marker": "⟨U+XXXX⟩",
        "ranges": ranges,
    }
    return (json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def test_the_committed_table_is_the_generated_one() -> None:
    committed = resources.files("cyberlab_jobs").joinpath(vis.VIS_RULES_FILE).read_bytes()
    assert committed == _expected(), "run scripts/gen_vis_rules.py (api image)"


def test_vis_makes_invisible_characters_visible() -> None:
    assert vis.vis("evil‮gnp.exe") == "evil⟨U+202E⟩gnp.exe"
    assert vis.vis("a​b﻿c") == "a⟨U+200B⟩b⟨U+FEFF⟩c"
    assert vis.vis("tag\U000e0041") == "tag⟨U+E0041⟩"
    assert vis.vis("bell\x07 del\x7f c1\x85") == "bell⟨U+0007⟩ del⟨U+007F⟩ c1⟨U+0085⟩"
    assert vis.vis("soft­hyphen") == "soft⟨U+00AD⟩hyphen"


def test_vis_keeps_ordinary_text() -> None:
    for text in ("plain", "line\nbreak\ttab", "Tiếng Việt", "日本語", "emoji 🙂", ""):
        assert vis.vis(text) == text
