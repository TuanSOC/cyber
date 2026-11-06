"""Store layout and the write transaction (M8 phase 5): deterministic paths from validated
identities, a verified atomic move from staging, conflicts refused unless replacing, every
change recorded, a failed session leaves the old manifest in force, modes 0444 / 0555."""

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest
from cyberlab_jobs.memory import LinuxBanner, SymbolManifestV1, WindowsPdb

from memory_worker.symbols.manifest import (
    StoreError,
    StoreWriter,
    banner_key,
    isf_relpath,
    read_manifest,
)
from tests.symbols_helpers import BANNER, GUID, new_store, put, tamper

WIN = WindowsPdb(name="ntkrnlmp.pdb", guid=GUID, age=26)
LIN = LinuxBanner(banner=BANNER)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_store_paths_come_from_validated_identities() -> None:
    assert isf_relpath(WIN) == f"windows/ntkrnlmp.pdb/{GUID}-26.json.xz"  # decimal age
    assert isf_relpath(LIN) == f"linux/{banner_key(BANNER)}.json.xz"
    hostile = LinuxBanner(banner="../../etc/passwd $(id)")
    assert isf_relpath(hostile).startswith("linux/") and ".." not in isf_relpath(hostile)


def test_add_writes_file_manifest_and_change_log(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    sha = put(root, WIN, b"isf bytes")
    manifest = read_manifest(root)
    assert isinstance(manifest, SymbolManifestV1)
    (entry,) = manifest.files
    assert entry.path == isf_relpath(WIN) and entry.sha256 == sha and entry.source == "operator"
    assert entry.os == "windows" and entry.identity == WIN
    assert entry.tool_version.startswith("memory-symbols/")
    assert (root / entry.path).read_bytes() == b"isf bytes"
    (change,) = [json.loads(line) for line in (root / "changes.jsonl").read_text().splitlines()]
    assert change["action"] == "added" and change["sha256"] == sha
    assert not (root / ".staging").exists()


def test_same_content_again_is_unchanged(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    put(root, WIN, b"isf bytes")
    with StoreWriter(root) as writer:
        staged = writer.work_dir("t") / "f"
        staged.write_bytes(b"isf bytes")
        change = writer.stage(staged, WIN, _sha(b"isf bytes"), "msdl")
        writer.commit()
    assert change.action == "unchanged"
    assert read_manifest(root).files[0].source == "operator"  # the original record stays


def test_different_content_is_refused_unless_replacing(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    old = put(root, WIN, b"old")
    with StoreWriter(root) as writer:
        staged = writer.work_dir("t") / "f"
        staged.write_bytes(b"new")
        with pytest.raises(StoreError, match="already holds"):
            writer.stage(staged, WIN, _sha(b"new"), "operator")
    assert read_manifest(root).files[0].sha256 == old
    with StoreWriter(root) as writer:
        staged = writer.work_dir("t") / "f"
        staged.write_bytes(b"new")
        change = writer.stage(staged, WIN, _sha(b"new"), "operator", replace=True)
        writer.commit()
    assert change.action == "replaced" and change.old_sha256 == old
    assert (root / isf_relpath(WIN)).read_bytes() == b"new"
    lines = (root / "changes.jsonl").read_text().splitlines()
    assert json.loads(lines[-1])["old_sha256"] == old


def test_tampered_disk_with_the_manifest_content_is_repaired(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    put(root, WIN, b"good")
    tamper(root / isf_relpath(WIN))
    with StoreWriter(root) as writer:
        staged = writer.work_dir("t") / "f"
        staged.write_bytes(b"good")
        assert writer.stage(staged, WIN, _sha(b"good"), "operator").action == "repaired"
        writer.commit()
    assert (root / isf_relpath(WIN)).read_bytes() == b"good"


def test_an_unlisted_file_blocks_a_plain_add(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    planted = root / isf_relpath(WIN)
    planted.parent.mkdir(parents=True)
    planted.write_bytes(b"planted")
    with StoreWriter(root) as writer:
        staged = writer.work_dir("t") / "f"
        staged.write_bytes(b"real")
        with pytest.raises(StoreError, match="unlisted"):
            writer.stage(staged, WIN, _sha(b"real"), "operator")


def test_a_staged_file_is_rehashed(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    with StoreWriter(root) as writer:
        staged = writer.work_dir("t") / "f"
        staged.write_bytes(b"what the child wrote")
        with pytest.raises(StoreError, match="changed"):
            writer.stage(staged, WIN, _sha(b"what the child claimed"), "operator")


def test_only_staged_files_can_be_placed(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_bytes(b"x")
    with StoreWriter(root) as writer, pytest.raises(StoreError, match="staging"):
        writer.stage(elsewhere, WIN, _sha(b"x"), "operator")


def test_two_inputs_for_one_identity_are_refused(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    with StoreWriter(root) as writer:
        work = writer.work_dir("t")
        (work / "a").write_bytes(b"a")
        (work / "b").write_bytes(b"b")
        writer.stage(work / "a", WIN, _sha(b"a"), "operator")
        with pytest.raises(StoreError, match="same identity"):
            writer.stage(work / "b", WIN, _sha(b"b"), "operator", replace=True)


def test_an_uncommitted_session_changes_nothing(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    before = (root / "manifest.json").read_bytes()
    with pytest.raises(RuntimeError), StoreWriter(root) as writer:
        staged = writer.work_dir("t") / "f"
        staged.write_bytes(b"x")
        writer.stage(staged, WIN, _sha(b"x"), "operator")
        raise RuntimeError("crash before commit")
    assert (root / "manifest.json").read_bytes() == before
    assert not (root / isf_relpath(WIN)).exists()
    assert not (root / ".staging").exists()


def test_a_leftover_staging_dir_is_discarded(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    (root / ".staging" / "old").mkdir(parents=True)
    (root / ".staging" / "old" / "x.json.xz").write_bytes(b"stale")
    put(root, WIN, b"isf")
    assert not (root / ".staging").exists()


def test_the_manifest_is_created_when_absent(tmp_path: Path) -> None:
    root = tmp_path / "fresh"
    root.mkdir()
    put(root, LIN, b"linux")
    assert [f.identity for f in read_manifest(root).files] == [LIN]


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
def test_files_are_0444_and_directories_0555(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    put(root, WIN, b"win")
    put(root, LIN, b"lin")
    for path in [root, *root.rglob("*")]:
        if path.name == ".lock":
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == (0o555 if path.is_dir() else 0o444), path
