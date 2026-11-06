"""Engine tests of the TSK probe (M9 phase 2, `--heavy` lanes) on phase 4's generated images.

Skipped unless `DISK_ENGINE_IMAGES` names the generator's output directory (in the test
tmpfs): one sub-directory per image with its segments (`image.raw`, `image.001`...,
`image.E01`...) and a `ground_truth.json`. The probe code runs in-process here (pytsk3 /
pyewf, no sandbox), so the comparison isolates the engine; the sandboxed path is covered by
`tests/unit/test_offline.py` and `test_stage_isolation.py`.

Ground-truth fields read (phase 4 writes them; extra fields are ignored):
- `format` (`raw` | `split_raw` | `ewf`), optional `media_hash_status` (E01 sets);
- `partitions`: `[{index, fs_type | null, fs_status, os}]`;
- `files`: `[{partition_index, path, stream?, size?, deleted?, orphan?, hard_linked?,
  sha256?}]` (every listed entry must be found with these values);
- `never_collect_meta`: `[{partition_index, path}]` (e.g. the hard link to `etc/shadow`):
  every name of that inode must be refused by `never_collect()` over all its names (RT7).
"""

import json
import os
from pathlib import Path
from typing import Any

import pytest

pytsk3 = pytest.importorskip("pytsk3")
pytest.importorskip("pyewf")

from disk_worker.normalize.models import FileRow, HashRow, PartitionRow  # noqa: E402
from disk_worker.normalize.records import build_index, file_record  # noqa: E402
from disk_worker.probe import image, layout, verify  # noqa: E402
from disk_worker.probe.tsk import Fs  # noqa: E402
from disk_worker.probe.walk import WalkArgs, Walker  # noqa: E402
from tests.unit.phase2_helpers import ListWriter  # noqa: E402

pytestmark = pytest.mark.engine
ROOT = os.environ.get("DISK_ENGINE_IMAGES")
CASE_INSENSITIVE = {"ntfs", "fat12", "fat16", "fat32", "exfat"}


def _images() -> list[Path]:
    if not ROOT or not Path(ROOT).is_dir():
        return []
    return sorted(p for p in Path(ROOT).iterdir() if (p / "ground_truth.json").is_file())


def _segments(d: Path, fmt: str) -> list[str]:
    pattern = {"raw": "image.raw", "split_raw": "image.[0-9][0-9][0-9]", "ewf": "image.E[0-9][0-9]"}
    return sorted(str(p) for p in d.glob(pattern[fmt]))


@pytest.mark.skipif(not _images(), reason="DISK_ENGINE_IMAGES (phase 4 output) not set")
@pytest.mark.parametrize("case", _images(), ids=lambda p: p.name)
def test_an_image_matches_its_ground_truth(case: Path) -> None:
    truth: dict[str, Any] = json.loads((case / "ground_truth.json").read_text())
    fmt = truth["format"]
    opened = image.open_image(
        {"format": fmt, "paths": _segments(case, fmt), "max_media": 2 * 1024**4}
    )
    try:
        rows = list(
            layout.run(opened.img, opened.reader, {"max_partitions": 128, "max_filesystems": 32})
        )
        parts = {r["index"]: PartitionRow.model_validate(r) for r in rows}
        for want in truth["partitions"]:
            got = parts[want["index"]]
            assert (got.fs_type, got.fs_status, got.os) == (
                want["fs_type"],
                want["fs_status"],
                want["os"],
            ), want
        records = []
        for p in parts.values():
            if p.fs_status != "ok" or p.fs_type is None:
                continue
            family = {"ntfs": "ntfs", "ext2": "ext", "ext3": "ext", "ext4": "ext"}.get(
                p.fs_type, "fat"
            )
            fs = Fs(opened.img, p.start_sector * p.sector_size, family)
            files, hashes = ListWriter(), ListWriter()
            walker = Walker(
                fs,
                WalkArgs(
                    max_rows=10**6,
                    max_bytes=10**10,
                    hash_max_file_bytes=64 * 1024**2,
                    hash_budget_bytes=10**10,
                ),
                files,
            )  # type: ignore[arg-type]
            walker.run()
            walker.hash_pending(hashes)  # type: ignore[arg-type]
            deferred = {h["n"]: h for h in hashes.items}
            for raw in files.items:
                row = FileRow.model_validate(raw)
                h = deferred.get(row.n)
                records.append(file_record(row, p.index, HashRow.model_validate(h) if h else None))
        index = build_index(records)
        by_path = {(r.partition_index, r.path, r.stream): r for r in records}
        for want in truth["files"]:
            got = by_path[(want["partition_index"], want["path"], want.get("stream"))]
            if "size" in want:
                assert got.size == want["size"], want
            if "sha256" in want:
                assert got.sha256 == want["sha256"], want
            for flag in ("deleted", "orphan", "hard_linked"):
                if flag in want:
                    linked = flag == "hard_linked" and index.hard_linked(
                        got.partition_index, got.meta_addr
                    )
                    assert (got.has_flag(flag) or linked) == want[flag], (flag, want)
        for want in truth.get("never_collect_meta", []):
            got = by_path[(want["partition_index"], want["path"], None)]
            fs_type = parts[got.partition_index].fs_type
            assert index.refused(got.partition_index, got.meta_addr, fs_type in CASE_INSENSITIVE)
        if fmt == "ewf" and "media_hash_status" in truth:
            out = verify.verify(opened.reader.read, opened.reader.size, opened.reader.handle, 600)  # type: ignore[attr-defined]
            assert out["media_hash_status"] == truth["media_hash_status"]
    finally:
        opened.close()
