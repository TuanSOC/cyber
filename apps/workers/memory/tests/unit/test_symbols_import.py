"""`import` (M8 phase 5): single ISFs and local zips, parsed and schema-validated in a child
process, identity from the metadata, member checks for zips (traversal, symlinks, type,
count, size, duplicates), a pinned `--sha256`, duplicates refused unless `--replace`."""

import hashlib
import json
import lzma
import os
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs.memory import LinuxBanner, WindowsPdb

from memory_worker.symbols import isolate
from memory_worker.symbols.import_isf import (
    ImportRefused,
    ImportResult,
    import_file,
    resolve_import_file,
    volatility_schema_dir,
)
from memory_worker.symbols.manifest import isf_relpath, read_manifest
from memory_worker.symbols.store import SymbolStore
from tests.symbols_helpers import (
    BANNER,
    GUID,
    HOSTILE_BANNER,
    dumps,
    import_dir,
    linux_isf,
    new_store,
    schema_dir,
    windows_isf,
    xz,
    zip_bytes,
)

WIN = WindowsPdb(name="ntkrnlmp.pdb", guid=GUID, age=1)


def _import(tmp_path: Path, name: str, data: bytes, **kwargs: Any) -> ImportResult:
    root = tmp_path / "symbols"
    if not root.exists():
        new_store(tmp_path)
    src = import_dir(tmp_path) / name
    src.write_bytes(data)
    return import_file(root, src, schema_dir=schema_dir(tmp_path), **kwargs)


def test_a_linux_isf_is_imported_and_found_by_banner(tmp_path: Path) -> None:
    result = _import(tmp_path, "kernel.json", dumps(linux_isf()))
    assert result.source == "operator"
    (change,) = result.changes
    assert change.action == "added"
    hit = SymbolStore(tmp_path / "symbols").lookup(LinuxBanner(banner=BANNER))
    assert hit is not None and hit.sha256 == change.sha256
    # Stored re-compressed as xz, content unchanged.
    assert json.loads(lzma.decompress(hit.path.read_bytes())) == linux_isf()


def test_a_windows_json_xz_is_imported_at_its_lookup_path(tmp_path: Path) -> None:
    result = _import(tmp_path, "nt.json.xz", xz(dumps(windows_isf())))
    assert [c.path for c in result.changes] == [isf_relpath(WIN)]
    assert SymbolStore(tmp_path / "symbols").lookup(WIN) is not None


def test_a_hostile_banner_is_stored_as_data_only(tmp_path: Path) -> None:
    result = _import(tmp_path, "evil.json", dumps(linux_isf(HOSTILE_BANNER)))
    (change,) = result.changes
    assert change.path == isf_relpath(LinuxBanner(banner=HOSTILE_BANNER))
    assert HOSTILE_BANNER not in change.path


@pytest.mark.parametrize(
    ("data", "match"),
    [
        (b"not json", "not valid JSON"),
        (b"[1, 2]", "JSON object"),
        (b'{"metadata": {"format": "6.2.0"}, "x": NaN}', "non-finite"),
        (dumps({"metadata": {"format": "../../etc/x"}}), "metadata.format"),
        (dumps({"metadata": {"format": "9.9.9"}}), "no Volatility schema"),
        (dumps({"metadata": {"format": "6.2.0"}}), "schema violation"),
        (dumps({**windows_isf(), "symbols": []}), "schema violation"),
        (b"\xfd7zXZ\x00garbage", "invalid xz"),
        (xz(dumps(windows_isf())) + b"trailing", "after the xz stream"),
        (xz(dumps(windows_isf()))[:-12], "xz"),
    ],
)
def test_invalid_isfs_are_refused(tmp_path: Path, data: bytes, match: str) -> None:
    with pytest.raises(ImportRefused, match=match):
        _import(tmp_path, "bad.json", data)
    assert read_manifest(tmp_path / "symbols").files == []


def test_an_isf_without_a_kernel_identity_is_refused(tmp_path: Path) -> None:
    doc = windows_isf()
    del doc["metadata"]["windows"]
    with pytest.raises(ImportRefused, match="no kernel identity"):
        _import(tmp_path, "types.json", dumps(doc))
    with pytest.raises(ImportRefused, match="no kernel identity"):
        _import(tmp_path, "driver.json", dumps(windows_isf(name="tcpip.pdb")))


@pytest.mark.parametrize(
    "doc",
    [
        windows_isf(guid="../../etc/passwd0000000000000000"),
        windows_isf(age=70_000),
        windows_isf(guid="0123"),
        linux_isf("Linux \x1b[31m red"),
    ],
)
def test_a_malformed_identity_is_refused(tmp_path: Path, doc: dict[str, object]) -> None:
    with pytest.raises(ImportRefused, match="identity|banner"):
        _import(tmp_path, "bad.json", dumps(doc))


def test_an_oversize_isf_is_refused_in_the_child(tmp_path: Path) -> None:
    src = tmp_path / "big.json.xz"
    src.write_bytes(xz(b" " * 200_000 + dumps(windows_isf())))
    with pytest.raises(isolate.ChildFailed, match="more than 100000"):
        isolate.run_child(
            "isf",
            {
                "src": str(src),
                "out": str(tmp_path / "out.json.xz"),
                "schema_dir": str(schema_dir(tmp_path)),
                "max_bytes": 100_000,
            },
            tmp_path / "work",
            timeout_s=60,
        )


def test_a_duplicate_with_different_content_needs_replace(tmp_path: Path) -> None:
    first = _import(tmp_path, "a.json", dumps(windows_isf()))
    doc = windows_isf()
    doc["base_types"]["long"] = {"kind": "int", "size": 8, "signed": True, "endian": "little"}
    with pytest.raises(ImportRefused, match="--replace"):
        _import(tmp_path, "b.json", dumps(doc))
    again = _import(tmp_path, "a.json", dumps(windows_isf()))
    assert [c.action for c in again.changes] == ["unchanged"]
    replaced = _import(tmp_path, "b.json", dumps(doc), replace=True)
    (change,) = replaced.changes
    assert change.action == "replaced" and change.old_sha256 == first.changes[0].sha256


def test_the_import_file_must_be_inside_the_import_dir(tmp_path: Path) -> None:
    root = import_dir(tmp_path)
    (root / "ok.json").write_text("{}")
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    assert resolve_import_file("ok.json", root) == Path(os.path.realpath(root / "ok.json"))
    for name in (str(outside), "../outside.json", str(root), "missing.json"):
        with pytest.raises(ImportRefused):
            resolve_import_file(name, root)
    if os.name == "posix":
        (root / "link.json").symlink_to(outside)
        with pytest.raises(ImportRefused):
            resolve_import_file("link.json", root)


def test_a_wrong_suffix_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ImportRefused, match=".zip"):
        _import(tmp_path, "kernel.tar", b"x")


# --- zips -----------------------------------------------------------------------------------


def _members() -> dict[str, bytes]:
    return {
        "windows/": b"",
        f"windows/ntkrnlmp.pdb/{GUID}-1.json.xz": xz(dumps(windows_isf())),
        "linux/kernel.json": dumps(linux_isf()),
        "windows/tcpip.pdb/00000000000000000000000000000000-1.json": dumps(
            windows_isf(name="tcpip.pdb", guid="0" * 32)
        ),
    }


def test_a_zip_is_imported_with_its_sha256_as_source(tmp_path: Path) -> None:
    data = zip_bytes(_members())
    digest = hashlib.sha256(data).hexdigest()
    result = _import(tmp_path, "pack.zip", data, sha256=digest)
    assert result.source == f"zip:{digest}"
    assert sorted(c.path for c in result.changes) == sorted(
        [isf_relpath(WIN), isf_relpath(LinuxBanner(banner=BANNER))]
    )
    assert [s["reason"] for s in result.skipped] == ["not a kernel ISF"]
    assert {f.source for f in read_manifest(tmp_path / "symbols").files} == {f"zip:{digest}"}


def test_a_wrong_sha256_is_refused_before_opening(tmp_path: Path) -> None:
    with pytest.raises(ImportRefused, match="--sha256"):
        _import(tmp_path, "pack.zip", zip_bytes(_members()), sha256="0" * 64)


@pytest.mark.parametrize(
    ("members", "match"),
    [
        ({"windows/../../etc/cron.d/x.json": b"{}"}, "segment"),
        ({"/windows/x.json": b"{}"}, "member name"),
        ({"windows/a\\..\\b.json": b"{}"}, "member name|segment"),  # zipfile maps \ on Windows
        ({"mac/kernel.json": b"{}"}, "member name"),
        ({"windows/kernel.json.gz": b"{}"}, "member name"),
        ({"README.txt": b"hi"}, "member name"),
        ({"windows//x.json": b"{}"}, "segment"),
        ({"linux/win.json": dumps(windows_isf())}, "identity is not windows"),
        ({"linux/bad.json": b"[]"}, "JSON object"),
    ],
)
def test_bad_zip_members_refuse_the_whole_zip(
    tmp_path: Path, members: dict[str, bytes], match: str
) -> None:
    good = {f"windows/ntkrnlmp.pdb/{GUID}-1.json": dumps(windows_isf())}
    with pytest.raises(ImportRefused, match=match):
        _import(tmp_path, "pack.zip", zip_bytes({**good, **members}))
    assert read_manifest(tmp_path / "symbols").files == []


def test_a_symlink_member_is_refused(tmp_path: Path) -> None:
    data = zip_bytes({}, symlinks={"linux/k.json": "/etc/passwd"})
    with pytest.raises(ImportRefused, match="symlink"):
        _import(tmp_path, "pack.zip", data)


def test_zip_caps_are_enforced_in_the_child(tmp_path: Path) -> None:
    schemas = str(schema_dir(tmp_path))

    def run(data: bytes, **caps: int) -> dict[str, object]:
        src = tmp_path / "pack.zip"
        src.write_bytes(data)
        out = tmp_path / f"out-{os.urandom(3).hex()}"
        out.mkdir()
        params = {"src": str(src), "out_dir": str(out), "schema_dir": schemas, **caps}
        return isolate.run_child("zip", params, out, timeout_s=60)

    big = dumps(windows_isf()) + b" " * 5000
    with pytest.raises(isolate.ChildFailed, match="over 4000"):
        run(zip_bytes({"windows/a.json": big}), max_member_bytes=4000)
    with pytest.raises(isolate.ChildFailed, match="more than 4000"):  # xz bomb in a member
        run(zip_bytes({"windows/a.json.xz": xz(big)}), max_member_bytes=4000)
    two = {"windows/a.json": dumps(windows_isf()), "linux/b.json": dumps(linux_isf())}
    with pytest.raises(isolate.ChildFailed, match="in total"):
        run(zip_bytes(two), max_total_bytes=len(dumps(windows_isf())) + 10)
    with pytest.raises(isolate.ChildFailed, match="more than 1 members"):
        run(zip_bytes(two), max_members=1)
    with pytest.raises(isolate.ChildFailed, match="valid zip"):
        run(b"PK\x03\x04 not really a zip")


def test_a_duplicate_member_name_is_refused(tmp_path: Path) -> None:
    import io
    import warnings
    import zipfile

    buf = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(buf, "w") as zf:
        warnings.simplefilter("ignore")
        zf.writestr("linux/a.json", dumps(linux_isf()))
        zf.writestr("linux/a.json", dumps(linux_isf("Linux version 2")))
    with pytest.raises(ImportRefused, match="duplicate"):
        _import(tmp_path, "pack.zip", buf.getvalue())


def test_two_members_with_one_identity_are_refused(tmp_path: Path) -> None:
    doc = windows_isf()
    doc["enums"] = {"e": {"size": 4, "base": "int", "constants": {}}}
    members = {"windows/a.json": dumps(windows_isf()), "windows/b.json": dumps(doc)}
    with pytest.raises(ImportRefused, match="same identity"):
        _import(tmp_path, "pack.zip", zip_bytes(members))


def test_the_child_refuses_network_and_subprocesses(tmp_path: Path) -> None:
    """The audit hook is installed before any task runs."""
    isolate._deny_hook("open", ())
    for event in ("socket.connect", "subprocess.Popen", "os.system", "urllib.Request"):
        with pytest.raises(PermissionError):
            isolate._deny_hook(event, ())


def test_schema_dir_discovery_needs_volatility() -> None:
    try:
        path = volatility_schema_dir()
    except ImportRefused:
        pytest.skip("volatility3 is not installed on this interpreter (runs in the image)")
    assert path.name == "schemas" and any(path.glob("schema-6.*.json"))


def test_the_real_volatility_schema_refuses_a_broken_isf(tmp_path: Path) -> None:
    try:
        schemas = volatility_schema_dir()
    except ImportRefused:
        pytest.skip("volatility3 is not installed on this interpreter (runs in the image)")
    doc = windows_isf()
    doc["base_types"] = "not an object"
    src = tmp_path / "broken.json"
    src.write_bytes(dumps(doc))
    with pytest.raises(isolate.ChildFailed, match="schema violation|no Volatility schema"):
        isolate.run_child(
            "isf",
            {"src": str(src), "out": str(tmp_path / "o.json.xz"), "schema_dir": str(schemas)},
            tmp_path / "w",
            timeout_s=120,
        )


def test_the_child_may_write_only_in_its_work_dir(tmp_path: Path) -> None:
    """Review fix: the child never has the store writable (its work dir is outside it and
    every other write, change or link is refused)."""
    work, store = tmp_path / "work", tmp_path / "symbols"
    roots = isolate.write_roots({"out": str(work / "isf.json.xz")}, work)
    hook = isolate.write_guard(roots)
    hook("open", (str(work / "isf.json.xz"), "wb", 0))
    hook("open", (str(store / "manifest.json"), "rb", os.O_RDONLY))  # reads are fine
    hook("os.mkdir", (str(work / ".child-cache"), 0o700, -1))
    hook("open", (7, "wb", 0))  # an fd opened (and checked) earlier
    for event, args in (
        ("open", (str(store / "windows" / "x.json.xz"), "wb", 0)),
        ("open", (str(store / "manifest.json"), None, os.O_WRONLY | os.O_TRUNC)),
        ("open", (str(work / ".." / "symbols" / "x"), "ab", 0)),
        ("os.rename", (str(work / "a"), str(store / "a"), -1, -1)),
        ("os.chmod", (str(store), 0o755, -1)),
        ("os.remove", (str(store / "manifest.json"), -1)),
        ("shutil.copyfile", (str(work / "a"), str(store / "a"))),
        ("os.symlink", (str(store), str(work / "link"), -1)),
    ):
        with pytest.raises(PermissionError):
            hook(event, args)


def test_import_stages_through_a_temp_dir_outside_the_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Path] = []
    real = isolate.run_child

    def spy(task: str, params: dict[str, Any], work: Path, **kw: Any) -> dict[str, Any]:
        seen.append(work)
        return real(task, params, work, **kw)

    monkeypatch.setattr(isolate, "run_child", spy)
    result = _import(tmp_path, "kernel.json", dumps(windows_isf()))
    assert result.changes and seen
    store = (tmp_path / "symbols").resolve()
    assert all(store not in w.resolve().parents for w in seen)
