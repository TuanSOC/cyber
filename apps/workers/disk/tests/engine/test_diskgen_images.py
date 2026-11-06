"""The generated images checked with the generating tools' own readers (M9 phase 4, `--heavy`,
dev / test image only): `fsck.fat -n`, `fsck.exfat -n`, `e2fsck -fn`, `debugfs`, `ntfsfix -n`,
`ntfscat`, `ewfverify`, `sfdisk --json`, `hivexget`; the determinism of the tool-built images;
every hostile mutation. Not TSK: phase 2's `test_tsk_images.py` compares TSK with the ground
truth (point `DISK_ENGINE_IMAGES` at a `python -m samples.diskgen` output for it).

Heavy (the whole set, twice for the determinism check, plus a 300 000-entry directory): runs
only with `DISKGEN_ENGINE=1` and every tool of `docker/diskgen-packages.txt` installed, e.g.

    docker compose --profile test run --rm --no-deps -e DISKGEN_ENGINE=1 disk-worker-test
        pytest -q -p no:cacheprovider tests/engine/test_diskgen_images.py   (one command line)

Images go to `DISKGEN_WORK` (default `/work`, the test container's 1 GiB tmpfs), never to the
repository.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from samples.diskgen import SECTOR, hives, images, mutate, tools
from samples.diskgen.images import Built, Generator

pytestmark = pytest.mark.engine
TOOLS = (
    "mke2fs", "debugfs", "e2fsck", "mkfs.exfat", "fsck.exfat", "fsck.fat", "mkntfs", "ntfscp",
    "ntfsinfo", "ntfsfix", "ntfscat", "ewfacquirestream", "ewfverify", "sfdisk",
)  # fmt: skip
if os.environ.get("DISKGEN_ENGINE") != "1" or not tools.have(*TOOLS):
    pytest.skip("heavy: DISKGEN_ENGINE=1 in the disk worker dev image", allow_module_level=True)


def _workdir(prefix: str) -> Path:
    base = os.environ.get("DISKGEN_WORK", "/work")
    return Path(tempfile.mkdtemp(prefix=prefix, dir=base if os.access(base, os.W_OK) else None))


@pytest.fixture(scope="module")
def gen() -> Iterator[Generator]:
    out = _workdir("diskgen-engine-")
    try:
        yield Generator(out)
    finally:
        shutil.rmtree(out, ignore_errors=True)


@pytest.fixture(scope="module")
def built(gen: Generator) -> dict[str, Built]:
    return {i: gen.build(i) for i in images.BUILDERS}


def _run(*argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv), capture_output=True, text=True, env=tools.env(), timeout=300, check=False
    )


def _volume(b: Built, index: int, out: Path) -> Path:
    """One partition of `b` copied to its own file (the fsck tools check a file system)."""
    part = b.truth["partitions"][index]
    with b.raw.open("rb") as src, out.open("wb") as dst:
        src.seek(part["start_sector"] * SECTOR)
        dst.write(src.read(part["length_sectors"] * SECTOR))
    return out


def test_every_image_is_built_within_the_limits(built: dict[str, Built]) -> None:
    for image_id, b in built.items():
        assert [p.name for p in b.segments] == b.truth["segments"], image_id
        assert all(p.stat().st_size <= 64 * 1024 * 1024 for p in b.segments), image_id
        on_disk = json.loads((b.directory / "ground_truth.json").read_text(encoding="utf-8"))
        assert on_disk["id"] == image_id and on_disk["format"] == b.truth["format"]
    multi = built["ewf_multi"].segments
    assert len(multi) > 1 and multi[0].name == "image.E01"


def test_fat_volumes_pass_fsck_fat(built: dict[str, Built], tmp_path: Path) -> None:
    volumes = [("fat_basic", 0), ("fat12", 0), ("fat16", 0), ("multi_gpt", 1)]
    if built["ntfs_windows"].truth["ntfs_route"] == "fat32":
        volumes.append(("ntfs_windows", 0))
    for image_id, index in volumes:
        vol = _volume(built[image_id], index, tmp_path / f"{image_id}.vol")
        result = _run("fsck.fat", "-n", "-v", str(vol))
        assert result.returncode == 0, (image_id, result.stdout[-2000:], result.stderr[-2000:])


def test_exfat_passes_fsck_exfat(built: dict[str, Built], tmp_path: Path) -> None:
    vol = _volume(built["exfat_basic"], 0, tmp_path / "exfat.vol")
    result = _run("fsck.exfat", "-n", str(vol))
    assert result.returncode == 0, result.stdout + result.stderr


def test_ext_volumes_pass_e2fsck(built: dict[str, Built], tmp_path: Path) -> None:
    for image_id, index in (("ext2", 0), ("ext3", 0), ("ext4_linux", 0), ("multi_gpt", 0)):
        vol = _volume(built[image_id], index, tmp_path / f"{image_id}.vol")
        result = _run("e2fsck", "-fn", str(vol))
        assert result.returncode == 0, (image_id, result.stdout[-2000:], result.stderr[-2000:])


def test_ext4_linux_times_owner_and_hard_link(built: dict[str, Built], tmp_path: Path) -> None:
    vol = _volume(built["ext4_linux"], 0, tmp_path / "ext4.vol")
    files = {f["path"]: f for f in built["ext4_linux"].truth["files"]}
    shadow = _run("debugfs", "-R", "stat /etc/shadow", str(vol)).stdout
    assert "Links: 2" in shadow
    old = _run("debugfs", "-R", "stat /var/log/old.log", str(vol)).stdout
    assert old.split("\n", 1)[0] == shadow.split("\n", 1)[0]  # the same inode
    stat = _run("debugfs", "-R", "stat /var/log/syslog", str(vol)).stdout
    for key in ("mtime", "atime", "ctime", "crtime"):
        line = next(x for x in stat.splitlines() if x.strip().startswith(f"{key}:"))
        assert f"0x{files['/var/log/syslog']['times'][key]:08x}" in line, (key, line)
    alice = _run("debugfs", "-R", "stat /home/alice/.ssh/authorized_keys", str(vol)).stdout
    assert re.search(r"User:\s+1000", alice), alice[:300]
    elf = _run("debugfs", "-R", "cat /tmp/.x/upd", str(vol))
    assert elf.returncode == 0


def test_ntfs_volumes_pass_ntfsfix_and_keep_their_streams(
    built: dict[str, Built], tmp_path: Path
) -> None:
    flat = _volume(built["ntfs_flat"], 0, tmp_path / "flat.vol")
    result = _run("ntfsfix", "-n", str(flat))
    assert result.returncode == 0, result.stdout + result.stderr
    streams = {
        (f["path"], f.get("stream")): f for f in built["ntfs_flat"].truth["files"] if "sha256" in f
    }
    for (path, stream), want in streams.items():
        argv = ["ntfscat"] + (["-n", stream] if stream else []) + [str(flat), path]
        got = subprocess.run(argv, capture_output=True, env=tools.env(), timeout=60, check=False)
        assert got.returncode == 0, (path, stream, got.stderr[-500:])
        assert hashlib.sha256(got.stdout).hexdigest() == want["sha256"], (path, stream)


def test_windows_tree_route_is_recorded_and_consistent(
    built: dict[str, Built], tmp_path: Path
) -> None:
    truth = built["ntfs_windows"].truth
    assert truth["ntfs_route"] in ("libntfs", "fat32")
    assert truth["partitions"][0]["os"] == "windows"
    if truth["ntfs_route"] != "libntfs":
        pytest.skip("libntfs route unavailable: the FAT32 fallback is checked by fsck.fat")
    vol = _volume(built["ntfs_windows"], 0, tmp_path / "win.vol")
    assert _run("ntfsfix", "-n", str(vol)).returncode == 0
    sam = _run("ntfscat", str(vol), "/Windows/System32/config/SAM")
    second = _run("ntfscat", str(vol), "/Users/Public/Documents/backup.dat")
    assert sam.returncode == 0 and sam.stdout == second.stdout
    assert truth["never_collect_meta"] == [
        {
            "partition_index": 0,
            "path": "/Users/Public/Documents/backup.dat",
            "link_to": "/Windows/System32/config/SAM",
        }
    ]


def test_ewf_sets_verify_and_the_patched_hash_does_not(built: dict[str, Built]) -> None:
    for image_id in ("ewf_single", "ewf_multi"):
        b = built[image_id]
        result = _run("ewfverify", "-q", str(b.segments[0]))
        assert result.returncode == 0, (image_id, result.stdout[-1500:])
    bad = _run("ewfverify", "-q", str(built["ewf_bad_hash"].segments[0]))
    assert bad.returncode != 0, bad.stdout[-1500:]


def test_partition_tables_read_by_sfdisk(built: dict[str, Built]) -> None:
    for image_id, b in built.items():
        if b.truth["volume_system"] == "none" or b.truth["format"] != "raw":
            continue
        result = _run("sfdisk", "--json", str(b.raw))
        assert result.returncode == 0, (image_id, result.stderr)
        table = json.loads(result.stdout)["partitiontable"]
        assert table["label"] == b.truth["volume_system"], image_id
        got = [(p["start"], p["size"]) for p in table["partitions"]]
        want = [(p["start_sector"], p["length_sectors"]) for p in b.truth["partitions"]]
        assert got == want, image_id


def test_merged_hives_open_with_hivex() -> None:
    if not tools.have("hivexregedit", "hivexget"):
        pytest.skip("hivex not installed: the hives stay base hives (recorded as hive_outcome)")
    data, outcome = hives.build("SOFTWARE", images.HIVE_TIME)
    assert outcome == "merged"
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "SOFTWARE"
        path.write_bytes(data)
        result = _run("hivexget", str(path), r"Microsoft\Windows\CurrentVersion\Run", "Updater")
        assert result.returncode == 0 and "tool.exe" in result.stdout, result.stderr
    again, _ = hives.build("SOFTWARE", images.HIVE_TIME)
    assert again == data  # normalized key times: deterministic


def test_tool_built_images_are_deterministic(built: dict[str, Built]) -> None:
    out = _workdir("diskgen-again-")
    try:
        second = Generator(out)
        for image_id in ("ext2", "ext3", "ext4_linux", "exfat_basic", "multi_gpt"):
            again = second.build(image_id)
            assert again.truth["media_sha256"] == built[image_id].truth["media_sha256"], image_id
    finally:
        shutil.rmtree(out, ignore_errors=True)


def test_hostile_mode_builds_every_mutation(gen: Generator, built: dict[str, Built]) -> None:
    """Reuses the module's base images (the test tmpfs is 1 GiB)."""
    try:
        cases, skipped = mutate.hostile(gen, len(mutate.CATALOG), 11)
        assert skipped == []
        assert sorted(c.name for c in cases) == sorted(mutate.CATALOG)
        for case in cases:
            doc = json.loads((case.directory / "mutation.json").read_text(encoding="utf-8"))
            assert doc["segments"] == [p.name for p in case.segments]
            assert all(p.is_file() for p in case.segments)
        huge = next(c for c in cases if c.name == "huge_dir")
        listing = _run("debugfs", "-R", "ls -c /big", str(huge.segments[0])).stdout
        assert listing.count("\n") > 1000
    finally:
        shutil.rmtree(gen.out / "hostile", ignore_errors=True)
