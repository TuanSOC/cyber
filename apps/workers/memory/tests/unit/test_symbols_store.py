"""The worker-side symbol store (M8 phase 5): lookup by path and by banner, sha256 checked
against the manifest, a tampered or inconsistent store is `SymbolsCorrupt`, never a fetch."""

import os
import shutil
from pathlib import Path

import pytest
from cyberlab_jobs.memory import LinuxBanner, WindowsPdb

from memory_worker.symbols.manifest import isf_relpath
from memory_worker.symbols.store import SymbolsCorrupt, SymbolStore, normalize_banner
from tests.symbols_helpers import BANNER, CONTRACT_FIXTURES, GUID, new_store, put, tamper

WIN = WindowsPdb(name="ntkrnlmp.pdb", guid=GUID, age=1)
LIN = LinuxBanner(banner=BANNER)


def test_windows_and_linux_hits_carry_path_and_sha256(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    win_sha = put(root, WIN, b"windows isf")
    lin_sha = put(root, LIN, b"linux isf")
    store = SymbolStore(root)
    hit = store.lookup(WIN)
    assert hit is not None and hit.sha256 == win_sha and hit.identity == WIN
    assert hit.path.is_absolute()
    assert hit.path.relative_to(root.absolute()).as_posix() == (
        f"windows/ntkrnlmp.pdb/{GUID}-1.json.xz"
    )
    lin = store.lookup(LIN)
    assert lin is not None and lin.sha256 == lin_sha
    assert lin.path.parent.name == "linux" and len(lin.path.name) == 64 + len(".json.xz")
    assert len(store.manifest().files) == 2


def test_a_missing_identity_is_none(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    put(root, WIN, b"windows isf")
    store = SymbolStore(root)
    assert store.lookup(WIN.model_copy(update={"age": 2})) is None
    assert store.lookup(LinuxBanner(banner="Linux version 9.9")) is None


@pytest.mark.parametrize("identity", [WIN, LIN])
def test_a_tampered_file_is_corrupt(tmp_path: Path, identity: WindowsPdb | LinuxBanner) -> None:
    root = new_store(tmp_path)
    put(root, identity, b"original")
    tamper(root / isf_relpath(identity))
    with pytest.raises(SymbolsCorrupt, match="sha256"):
        SymbolStore(root).lookup(identity)


def test_a_listed_but_deleted_file_is_corrupt(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    put(root, WIN, b"original")
    path = root / isf_relpath(WIN)
    os.chmod(path, 0o644)
    os.chmod(path.parent, 0o755)
    path.unlink()
    with pytest.raises(SymbolsCorrupt, match="missing"):
        SymbolStore(root).lookup(WIN)


def test_an_unlisted_file_at_the_lookup_path_is_corrupt(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    path = root / isf_relpath(WIN)
    path.parent.mkdir(parents=True)
    path.write_bytes(b"planted, not in the manifest")
    with pytest.raises(SymbolsCorrupt, match="not in the manifest"):
        SymbolStore(root).lookup(WIN)


def test_an_invalid_manifest_is_corrupt(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    shutil.copyfile(CONTRACT_FIXTURES / "hostile" / "manifest_dotdot.json", root / "manifest.json")
    with pytest.raises(SymbolsCorrupt):
        SymbolStore(root).lookup(WIN)
    (root / "manifest.json").write_text("not json")
    with pytest.raises(SymbolsCorrupt):
        SymbolStore(root).manifest()
    (root / "manifest.json").unlink()
    with pytest.raises(SymbolsCorrupt):
        SymbolStore(root).manifest()


def test_a_manifest_entry_at_the_wrong_path_is_corrupt(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    (root / "manifest.json").write_bytes(
        (CONTRACT_FIXTURES / "manifest.json")
        .read_bytes()
        .replace(b"00000000000000000000000000000000-1", b"00000000000000000000000000000000-2")
    )
    with pytest.raises(SymbolsCorrupt, match="store path"):
        SymbolStore(root).lookup(WIN)


@pytest.mark.skipif(os.name != "posix", reason="symlinks need POSIX")
def test_a_symlinked_store_file_is_corrupt(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    put(root, WIN, b"original")
    path = root / isf_relpath(WIN)
    outside = tmp_path / "outside"
    outside.write_bytes(b"original")
    os.chmod(path.parent, 0o755)
    os.chmod(path, 0o644)
    path.unlink()
    path.symlink_to(outside)
    with pytest.raises(SymbolsCorrupt, match="symlink"):
        SymbolStore(root).lookup(WIN)


def test_normalize_banner() -> None:
    assert normalize_banner(b"Linux version 6.1\n\x00") == "Linux version 6.1"
    assert normalize_banner(b"Linux version 6.1\x00\x00") == "Linux version 6.1"
    assert normalize_banner(b" Linux version 6.1 \n\x00junk") == "Linux version 6.1"
    assert normalize_banner(b"Linux\nversion\n\x00") is None  # an inner newline
    assert normalize_banner(b"Linux \x1b[2J\n\x00") is None  # terminal escape
    assert normalize_banner("Linux é".encode()) is None
    assert normalize_banner(b"L" * 513) is None
    assert normalize_banner(b"\n\x00") is None
