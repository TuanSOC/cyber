"""M9 phase 5: the `disk-hashsets` importer (in-process; the forked child is exercised by the
integration test in the image). Synthetic fixtures only; nothing is downloaded."""

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cyberlab_jobs.disk import HashSetManifestV1

from disk_worker.hashsets import importer
from disk_worker.hashsets import manifest as mf
from disk_worker.hashsets.__main__ import main
from disk_worker.hashsets.importer import ImportRefused, import_set, remove_set, verify_store
from tests.hashsets_fixtures import digests, make_list, make_rdsv3

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)


@pytest.fixture
def store(tmp_path: Path) -> Path:
    root = tmp_path / "hashsets"
    root.mkdir()
    return root


@pytest.fixture
def imports(tmp_path: Path) -> Path:
    d = tmp_path / "import"
    d.mkdir()
    return d


def _records(path: Path, width: int) -> list[bytes]:
    data = path.read_bytes()
    return [data[i : i + width] for i in range(0, len(data), width)]


def _nsrl(store: Path, imports: Path, name: str = "nsrl", **kw: object) -> object:
    return import_set(store, imports, "/import/rds.db", name, "known_good", "nsrl",
                      isolate=False, now=NOW, **kw)  # type: ignore[arg-type]


def test_nsrl_import_writes_sorted_unique_stores(store: Path, imports: Path) -> None:
    rows = digests(1, 3000)
    make_rdsv3(imports / "rds.db", rows + rows[:500])  # duplicates collapse
    hash_set, stats = import_set(
        store, imports, "/import/rds.db", "nsrl-min", "known_good", "nsrl",
        isolate=False, now=NOW, chunk_records=999,  # many runs
    )
    assert hash_set.algorithms == ["sha256", "sha1", "md5"]
    assert stats.counts == {"sha256": 3000, "sha1": 3000, "md5": 3000}
    for algo, idx in (("sha256", 0), ("sha1", 1), ("md5", 2)):
        records = _records(store / "nsrl-min" / f"{algo}.bin", mf.WIDTH[algo])
        assert records == sorted({bytes.fromhex(r[idx]) for r in rows})
    manifest = mf.load(store)
    assert [s.name for s in manifest.sets] == ["nsrl-min"]
    entry = manifest.sets[0]
    assert entry.tool_version == importer.TOOL_VERSION
    assert entry.source_sha256 == hashlib.sha256((imports / "rds.db").read_bytes()).hexdigest()
    assert verify_store(store) == []
    assert not (store / mf.STAGING_DIR).exists()


def test_nsrl_without_the_distinct_view_reads_file(store: Path, imports: Path) -> None:
    rows = digests(2, 50)
    make_rdsv3(imports / "rds.db", rows, distinct_view=False, upper=False)
    hash_set, stats = _nsrl(store, imports)  # type: ignore[misc]
    assert stats.counts["sha256"] == 50


def test_nsrl_bad_digests_are_counted_and_skipped(store: Path, imports: Path) -> None:
    rows = digests(3, 20)
    bad = [("zz" * 32, "a" * 39, None), ("", "b" * 40, "c" * 31), (b"\x00" * 32, 7, "d" * 32)]
    make_rdsv3(imports / "rds.db", rows, distinct_view=False, extra_rows=bad)
    _, stats = _nsrl(store, imports)  # type: ignore[misc]
    assert stats.counts == {"sha256": 20, "sha1": 21, "md5": 21}
    assert stats.invalid == 5 and stats.missing == 2


@pytest.mark.parametrize(
    "build",
    [
        lambda p: make_rdsv3(p, digests(4, 5), drop_columns=("package_id",)),
        lambda p: p.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100),
        lambda p: p.write_text("not a database"),
    ],
)
def test_nsrl_unknown_layouts_are_refused(store: Path, imports: Path, build: object) -> None:
    build(imports / "rds.db")  # type: ignore[operator]
    with pytest.raises(ImportRefused) as exc:
        _nsrl(store, imports)
    assert exc.value.code in {"nsrl_schema", "nsrl_open_failed", "nsrl_read_failed"}
    assert mf.load(store).sets == []
    assert not (store / "nsrl").exists()


def test_nsrl_other_tables_only_is_refused(store: Path, imports: Path) -> None:
    import sqlite3

    conn = sqlite3.connect(imports / "rds.db")
    conn.execute("CREATE TABLE PKG (package_id INTEGER, name TEXT)")
    conn.commit()
    conn.close()
    with pytest.raises(ImportRefused) as exc:
        _nsrl(store, imports)
    assert exc.value.code == "nsrl_schema"


def test_list_import_md5sum_style(store: Path, imports: Path) -> None:
    rows = digests(5, 200)
    values = [r[2] for r in rows] + ["nothex" * 4, "A" * 33, "#comment"]
    values.append(rows[0][2].upper())  # duplicate, upper case
    make_list(imports / "bad.md5", values)
    hash_set, stats = import_set(
        store, imports, "bad.md5", "lab-bad", "known_bad", "list", "md5", isolate=False, now=NOW
    )
    assert hash_set.kind == "known_bad" and hash_set.algorithms == ["md5"]
    assert stats.counts == {"md5": 200}
    assert stats.invalid == 2
    assert _records(store / "lab-bad" / "md5.bin", 16) == sorted(
        {bytes.fromhex(r[2]) for r in rows}
    )


def test_list_overlong_lines_are_invalid_not_buffered(store: Path, imports: Path) -> None:
    good = digests(6, 3)
    text = good[0][0] + "\n" + "a" * 100_000 + "\n" + good[1][0] + "\n"
    (imports / "x.txt").write_text(text)
    _, stats = import_set(
        store, imports, "x.txt", "x", "notable", "list", "sha256", isolate=False, now=NOW
    )
    assert stats.counts == {"sha256": 2}


@pytest.mark.parametrize("arg", ["../etc/passwd", "/import/../x", "a/b", "", ".", "..",
                                 "/etc/passwd", "sub\\x", "x\x00y"])
def test_input_paths_cannot_escape_the_import_dir(store: Path, imports: Path, arg: str) -> None:
    with pytest.raises(ImportRefused) as exc:
        import_set(store, imports, arg, "x", "notable", "list", "sha256", isolate=False)
    assert exc.value.code in {"bad_import_path", "import_not_found"}


def test_symlinked_and_non_regular_inputs_are_refused(
    store: Path, imports: Path, tmp_path: Path
) -> None:
    target = make_list(tmp_path / "outside.txt", [digests(7, 1)[0][0]])
    try:
        os.symlink(target, imports / "link.txt")
    except OSError:
        pytest.skip("symlinks are not available on this host")
    with pytest.raises(ImportRefused) as exc:
        import_set(store, imports, "link.txt", "x", "notable", "list", "sha256", isolate=False)
    assert exc.value.code == "import_symlink"
    (imports / "dir").mkdir()
    with pytest.raises(ImportRefused) as exc:
        import_set(store, imports, "dir", "x", "notable", "list", "sha256", isolate=False)
    assert exc.value.code == "import_not_regular"


@pytest.mark.parametrize("name", ["UPPER", "-x", ".hidden", "a/b", "manifest.json", "x" * 65, ""])
def test_set_names_are_checked(store: Path, imports: Path, name: str) -> None:
    make_list(imports / "l.txt", [digests(8, 1)[0][0]])
    with pytest.raises(ImportRefused) as exc:
        import_set(store, imports, "l.txt", name, "notable", "list", "sha256", isolate=False)
    assert exc.value.code == "bad_name"


def test_empty_and_duplicate_sets_are_refused(store: Path, imports: Path) -> None:
    make_list(imports / "empty.txt", ["# nothing", "zz"])
    with pytest.raises(ImportRefused) as exc:
        import_set(store, imports, "empty.txt", "e", "notable", "list", "sha256", isolate=False)
    assert exc.value.code == "empty_set"
    assert not (store / "e").exists()
    make_list(imports / "l.txt", [digests(9, 1)[0][0]])
    import_set(store, imports, "l.txt", "dup", "notable", "list", "sha256", isolate=False)
    with pytest.raises(ImportRefused) as exc:
        import_set(store, imports, "l.txt", "dup", "notable", "list", "sha256", isolate=False)
    assert exc.value.code == "set_exists"


def test_an_interrupted_import_leaves_no_partial_set(
    store: Path, imports: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_list(imports / "l.txt", [r[0] for r in digests(10, 100)])
    original = importer.build

    def crash(*args: object, **kwargs: object) -> object:
        original(*args, **kwargs)  # type: ignore[arg-type]
        raise ImportRefused("simulated_crash")

    monkeypatch.setattr(importer, "build", crash)
    with pytest.raises(ImportRefused):
        import_set(store, imports, "l.txt", "half", "notable", "list", "sha256", isolate=False)
    assert mf.load(store).sets == []
    assert not (store / "half").exists()
    assert not (store / mf.STAGING_DIR).exists()
    # A crash after the rename but before the manifest: an orphan dir, never matched, replaced.
    monkeypatch.setattr(importer, "build", original)
    (store / "half").mkdir()
    (store / "half" / "sha256.bin").write_bytes(b"\xff" * 32)
    import_set(store, imports, "l.txt", "half", "notable", "list", "sha256", isolate=False)
    assert mf.load(store).sets[0].files[0].count == 100
    assert verify_store(store) == []


def test_remove_and_verify(store: Path, imports: Path) -> None:
    make_list(imports / "a.txt", [r[0] for r in digests(11, 10)])
    make_list(imports / "b.txt", [r[1] for r in digests(12, 10)])
    import_set(store, imports, "a.txt", "a", "notable", "list", "sha256", isolate=False)
    import_set(store, imports, "b.txt", "b", "known_bad", "list", "sha1", isolate=False)
    assert verify_store(store) == []
    path = store / "b" / "sha1.bin"
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    path.write_bytes(bytes(data))
    problems = verify_store(store)
    assert problems and all(p.startswith("b/sha1.bin") for p in problems)
    remove_set(store, "b")
    assert [s.name for s in mf.load(store).sets] == ["a"]
    assert not (store / "b").exists()
    assert verify_store(store) == []
    with pytest.raises(ImportRefused):
        remove_set(store, "b")


def test_an_invalid_manifest_refuses_writes(store: Path, imports: Path) -> None:
    (store / mf.MANIFEST_NAME).write_text(json.dumps({"version": 1, "sets": "nope"}))
    make_list(imports / "l.txt", [digests(13, 1)[0][0]])
    with pytest.raises(ImportRefused) as exc:
        import_set(store, imports, "l.txt", "x", "notable", "list", "sha256", isolate=False)
    assert exc.value.code == "manifest_invalid"
    assert verify_store(store)


def test_manifest_write_is_atomic_and_canonical(store: Path) -> None:
    mf.write(store, HashSetManifestV1())
    assert json.loads((store / mf.MANIFEST_NAME).read_text()) == {"sets": [], "version": 1}
    assert [p.name for p in store.iterdir()] == [mf.MANIFEST_NAME]


def test_cli(store: Path, imports: Path, capsys: pytest.CaptureFixture[str]) -> None:
    env = {
        "DISK_HASHSETS_DIR": str(store),
        "DISK_HASHSETS_IMPORT_DIR": str(imports),
        "DISK_HASHSETS_IN_PROCESS": "1",
    }
    make_rdsv3(imports / "rds.db", digests(14, 30))
    make_list(imports / "bad.txt", [r[0] for r in digests(15, 5)])
    assert main([], env) == 2
    assert main(["import-list", "--file", "/import/bad.txt", "--name", "x"], env) == 2
    assert main(["import-nsrl", "--file", "/import/rds.db", "--name", "nsrl"], env) == 0
    assert main(["import-list", "--file", "/import/bad.txt", "--name", "lab", "--kind",
                 "known_bad", "--algo", "sha256"], env) == 0
    assert main(["import-list", "--file", "../bad.txt", "--name", "lab2", "--kind",
                 "known_bad", "--algo", "sha256"], env) == 1
    capsys.readouterr()
    assert main(["list"], env) == 0
    listed = capsys.readouterr().out.splitlines()
    assert [line.split("\t")[:2] for line in listed] == [
        ["nsrl", "known_good"],
        ["lab", "known_bad"],
    ]
    assert main(["verify"], env) == 0
    assert main(["remove", "--name", "lab"], env) == 0
    assert main(["remove", "--name", "lab"], env) == 1
    (store / "nsrl" / "md5.bin").write_bytes(b"")
    assert main(["verify"], env) == 1


# --- the forked child (Linux: the disk worker image) ------------------------------------------


def _seccomp_or_skip() -> None:
    if not hasattr(os, "fork"):
        pytest.skip("the import child needs fork (the disk worker image)")
    try:
        from cyberlab_worker import seccomp  # noqa: F401
    except OSError:
        pytest.skip("libseccomp is not available here")


def test_isolated_import_in_a_forked_child(store: Path, imports: Path) -> None:
    _seccomp_or_skip()
    rows = digests(20, 500)
    make_rdsv3(imports / "rds.db", rows)
    hash_set, stats = import_set(
        store, imports, "/import/rds.db", "nsrl", "known_good", "nsrl", isolate=True
    )
    assert stats.rows == 500 and stats.counts == {"sha256": 500, "sha1": 500, "md5": 500}
    assert verify_store(store) == []


def test_the_child_has_no_network_and_a_timeout(tmp_path: Path) -> None:
    _seccomp_or_skip()
    import socket
    import time

    def connect() -> importer.ImportStats:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return importer.ImportStats()

    with pytest.raises(ImportRefused) as exc:
        importer._run_isolated(connect, tmp_path / "r1.json", 30)
    assert exc.value.code == "import_failed"

    def slow() -> importer.ImportStats:
        time.sleep(30)
        return importer.ImportStats()

    with pytest.raises(ImportRefused) as exc:
        importer._run_isolated(slow, tmp_path / "r2.json", 1)
    assert exc.value.code == "import_timeout"

    def refused() -> importer.ImportStats:
        raise ImportRefused("nsrl_schema", "detail")

    with pytest.raises(ImportRefused) as exc:
        importer._run_isolated(refused, tmp_path / "r3.json", 30)
    assert exc.value.code == "nsrl_schema"
