"""M9 phase 13: the test hash lists derived from the generated images' ground truth (pure)."""

import hashlib
import json
from pathlib import Path
from typing import Any

from disk_worker.hashsets.importer import parse_digest
from samples.diskgen import hashlists


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _truth(out: Path, image_id: str, files: list[dict[str, Any]]) -> None:
    d = out / image_id
    d.mkdir(parents=True)
    (d / "ground_truth.json").write_text(json.dumps({"id": image_id, "files": files}))


def _reg(path: str, data: bytes, **extra: Any) -> dict[str, Any]:
    return {"partition_index": 0, "path": path, "type": "reg", "sha256": _sha(data), **extra}


def _digests(path: Path) -> list[str]:
    lines = path.read_text().splitlines()
    return [x for x in lines if x and not x.startswith("#")]


def test_lists_and_expectation_from_the_linux_and_windows_truth(tmp_path: Path) -> None:
    _truth(
        tmp_path,
        "ext4_linux",
        [
            {"partition_index": 0, "path": "/etc", "type": "dir"},
            _reg("/etc/os-release", b"PRETTY_NAME=x\n"),
            _reg("/tmp/.x/upd", b"\x7fELF"),
            # A named stream of the same path never stands for the file itself.
            _reg("/etc/os-release", b"stream", stream="s"),
        ],
    )
    _truth(tmp_path, "ntfs_windows", [_reg("/Windows/System32/drivers/etc/hosts", b"h")])
    assert hashlists.main(["--out", str(tmp_path)]) == 0

    out = tmp_path / "hashsets"
    assert _digests(out / hashlists.GOOD_FILE) == [_sha(b"PRETTY_NAME=x\n"), _sha(b"h")]
    assert _digests(out / hashlists.BAD_FILE) == [_sha(b"\x7fELF")]
    for name in (hashlists.GOOD_FILE, hashlists.BAD_FILE):
        assert all(parse_digest(d, "sha256") for d in _digests(out / name))
    expected = json.loads((out / hashlists.EXPECTED_FILE).read_text())
    assert expected["known_bad"] == [
        {"image": "ext4_linux", "path": "/tmp/.x/upd", "sha256": _sha(b"\x7fELF")}
    ]
    assert [r["image"] for r in expected["known_good"]] == ["ext4_linux", "ntfs_windows"]


def test_windows_is_optional(tmp_path: Path) -> None:
    _truth(tmp_path, "ext4_linux", [_reg("/etc/os-release", b"a"), _reg("/tmp/.x/upd", b"b")])
    expected = hashlists.write(tmp_path)
    assert [r["path"] for r in expected["known_good"]] == ["/etc/os-release"]


def test_missing_linux_truth_exits_2(tmp_path: Path) -> None:
    assert hashlists.main(["--out", str(tmp_path)]) == 2
    _truth(tmp_path, "ext4_linux", [_reg("/etc/os-release", b"a")])  # no /tmp/.x/upd
    assert hashlists.main(["--out", str(tmp_path)]) == 2
