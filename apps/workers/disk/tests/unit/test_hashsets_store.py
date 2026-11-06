"""M9 phase 5: the read-only hash-set store (mmap + binary search, kind precedence, invalid
stores disable matching without failing the job) and the external sort."""

import json
from pathlib import Path

import pytest
from cyberlab_jobs.disk import DiskFileRecord

from disk_worker.hashsets import extsort
from disk_worker.hashsets import manifest as mf
from disk_worker.hashsets.extsort import ExternalSorter
from disk_worker.hashsets.importer import import_set
from disk_worker.hashsets.store import HashSetsCorrupt, HashSetStore
from tests.hashsets_fixtures import digests, make_list, make_rdsv3

GOOD = digests(100, 400)
BAD = digests(101, 50)
NOTABLE = digests(102, 50)
BOTH = GOOD[0]  # listed as good and as bad: bad wins


@pytest.fixture
def store(tmp_path: Path) -> Path:
    root, imports = tmp_path / "hashsets", tmp_path / "import"
    root.mkdir()
    imports.mkdir()
    make_rdsv3(imports / "rds.db", GOOD)
    make_list(imports / "bad.txt", [r[0] for r in BAD] + [BOTH[0]])
    make_list(imports / "notable.md5", [r[2] for r in NOTABLE])
    import_set(root, imports, "rds.db", "nsrl", "known_good", "nsrl", isolate=False)
    import_set(root, imports, "bad.txt", "lab-bad", "known_bad", "list", "sha256", isolate=False)
    import_set(root, imports, "notable.md5", "tools", "notable", "list", "md5", isolate=False)
    return root


def test_matching_per_kind_and_algorithm(store: Path) -> None:
    with HashSetStore(store) as hs:
        assert hs.status == "ok" and hs.error is None
        hit = hs.match(GOOD[5][0], None, None)
        assert hit is not None and (hit.name, hit.kind, hit.algo, hit.known) == (
            "nsrl", "known_good", "sha256", "good"
        )
        hit = hs.match(None, GOOD[6][1], None)
        assert hit is not None and hit.algo == "sha1"
        hit = hs.match(None, None, GOOD[7][2].upper())
        assert hit is not None and hit.algo == "md5"
        hit = hs.match(BAD[3][0], BAD[3][1], BAD[3][2])
        assert hit is not None and (hit.name, hit.known) == ("lab-bad", "bad")
        hit = hs.match(None, None, NOTABLE[9][2])
        assert hit is not None and (hit.name, hit.known) == ("tools", "notable")
        assert hs.match(*digests(999, 1)[0]) is None
        assert hs.match(None, None, None) is None
        assert hs.match("zz" * 32, "short", "") is None


def test_known_bad_outranks_known_good(store: Path) -> None:
    with HashSetStore(store) as hs:
        hit = hs.match(*BOTH)
        assert hit is not None and hit.kind == "known_bad"


def test_every_record_is_found_and_neighbours_are_not(store: Path) -> None:
    with HashSetStore(store) as hs:
        for sha256, sha1, md5 in GOOD:
            assert hs.match(sha256, None, None) is not None
            assert hs.match(None, sha1, None) is not None
            assert hs.match(None, None, md5) is not None
        records = sorted(bytes.fromhex(r[0]) for r in GOOD)
        for r in records[:50]:
            probe = (int.from_bytes(r) + 1).to_bytes(32).hex()
            if bytes.fromhex(probe) not in records and probe not in {b[0] for b in BAD}:
                assert hs.match(probe, None, None) is None


def test_refs_for_the_header(store: Path) -> None:
    with HashSetStore(store) as hs:
        refs = hs.refs()
        assert [(r.name, r.kind, r.count) for r in refs] == [
            ("nsrl", "known_good", 400),
            ("lab-bad", "known_bad", 51),
            ("tools", "notable", 50),
        ]
        assert len({r.manifest_sha256 for r in refs}) == 3
        assert [s.name for s in hs.manifest().sets] == ["nsrl", "lab-bad", "tools"]


def test_annotate(store: Path) -> None:
    record = DiskFileRecord(
        partition_index=0, meta_addr=5, path="/Windows/notepad.exe", name="notepad.exe",
        type="reg", flags=1, size=10, magic="pe", hash_status="hashed",
        sha256=GOOD[1][0], md5=GOOD[1][2],
    )
    with HashSetStore(store) as hs:
        annotated = hs.annotate(record)
        assert (annotated.known, annotated.known_set) == ("good", "nsrl")
        DiskFileRecord.model_validate(annotated.model_dump())
        unhashed = DiskFileRecord(
            partition_index=0, meta_addr=6, path="/x", name="x", type="reg", flags=1,
            hash_status="too_large",
        )
        assert hs.annotate(unhashed) is unhashed


def test_missing_and_empty_stores_are_valid(tmp_path: Path) -> None:
    for root in (tmp_path / "absent", tmp_path):
        with HashSetStore(root) as hs:
            assert hs.status == "empty"
            assert hs.refs() == [] and hs.manifest().sets == []
            assert hs.match(*GOOD[0]) is None


@pytest.mark.parametrize("damage", ["manifest_json", "manifest_schema", "size", "missing_file",
                                    "foreign_path"])
def test_an_invalid_store_disables_matching(store: Path, damage: str) -> None:
    manifest_path = store / mf.MANIFEST_NAME
    if damage == "manifest_json":
        manifest_path.write_text("{not json")
    elif damage == "manifest_schema":
        manifest_path.write_text(json.dumps({"version": 2, "sets": []}))
    elif damage == "size":
        with open(store / "tools" / "md5.bin", "ab") as f:
            f.write(b"\x00")
    elif damage == "missing_file":
        (store / "nsrl" / "sha1.bin").unlink()
    else:
        data = json.loads(manifest_path.read_text())
        data["sets"][0]["files"][0]["path"] = "tools/md5.bin"
        manifest_path.write_text(json.dumps(data))
    hs = HashSetStore(store)  # never raises
    assert hs.status == "invalid" and hs.error
    assert hs.match(*BAD[0]) is None and hs.match(*GOOD[0]) is None
    assert hs.refs() == []
    with pytest.raises(HashSetsCorrupt):
        hs.manifest()
    hs.close()


def test_extsort_many_runs_and_fanin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(extsort, "MAX_FANIN", 3)
    rows = [bytes.fromhex(r[2]) for r in digests(200, 2000)]
    sorter = ExternalSorter(16, tmp_path, chunk_records=97)
    for r in rows + rows[::3]:
        sorter.add(r)
    out = list(sorter.finish())
    assert out == sorted(set(rows))
    assert list(tmp_path.iterdir()) == []
    with pytest.raises(ValueError):
        ExternalSorter(16, tmp_path).add(b"short")


def test_extsort_in_memory_and_empty(tmp_path: Path) -> None:
    sorter = ExternalSorter(4, tmp_path)
    assert list(sorter.finish()) == []
    sorter = ExternalSorter(4, tmp_path)
    for r in (b"bbbb", b"aaaa", b"bbbb"):
        sorter.add(r)
    assert list(sorter.finish()) == [b"aaaa", b"bbbb"]
    with pytest.raises(extsort.SortOrderError):
        list(extsort.unique([b"b", b"a"]))
