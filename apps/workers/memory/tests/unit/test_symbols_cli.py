"""The `memory-symbols` CLI (M8 phase 5): every phase-1 hostile `WindowsPdb` is refused before
any network code runs; `import`, `list`, `verify`, `reindex` exit codes; JSON-line logs; no
output ever carries a Linux banner outside a JSON value, let alone inside a command (RT12)."""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs.memory import WindowsPdb

from memory_worker.symbols import fetch_windows as fw
from memory_worker.symbols import import_isf
from memory_worker.symbols.__main__ import main
from memory_worker.symbols.manifest import isf_relpath, read_manifest
from tests.symbols_helpers import (
    CONTRACT_FIXTURES,
    GUID,
    HOSTILE_BANNER,
    dumps,
    import_dir,
    linux_isf,
    new_store,
    schema_dir,
    tamper,
    windows_isf,
)


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    root = new_store(tmp_path)
    imports = import_dir(tmp_path)
    schemas = schema_dir(tmp_path)
    monkeypatch.setenv("MEMORY_SYMBOLS_DIR", str(root))
    monkeypatch.setattr(import_isf, "IMPORT_ROOT", imports)
    monkeypatch.setattr(import_isf, "volatility_schema_dir", lambda: schemas)

    def no_network(*_: object, **__: object) -> None:
        raise AssertionError("no test may reach the network code")

    monkeypatch.setattr(fw, "default_transport", no_network)
    monkeypatch.setattr(fw, "fetch_windows", no_network)
    return {"root": root, "import": imports}


def _events(err: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in err.splitlines() if line.startswith("{")]


def _hostile_required() -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for name in ("bad_guid", "non_kernel_pdb"):
        lines = (CONTRACT_FIXTURES / "hostile" / f"{name}.ndjson").read_text().splitlines()
        header = json.loads(lines[0])
        found.append(header["symbols"]["required"])
    return found


HOSTILE = [
    *[(r["name"], r["guid"], str(r["age"])) for r in _hostile_required()],
    ("ntkrnlmp.pdb; rm -rf /", GUID, "1"),
    ("$(id).pdb", GUID, "1"),
    ("../../../etc/passwd", GUID, "1"),
    ("ntkrnlmp.pdb/../../x", GUID, "1"),
    ("NTKRNLMP.PDB", GUID, "1"),
    ("ntkrnlmp.pdb\n", GUID, "1"),
    ("ntkrnlmp.pdb", GUID.lower(), "1"),
    ("ntkrnlmp.pdb", GUID + "0", "1"),
    ("ntkrnlmp.pdb", GUID[:-1] + "G", "1"),
    ("ntkrnlmp.pdb", "%2e%2e%2f" + GUID[9:], "1"),
    ("ntkrnlmp.pdb", GUID, "-1"),
    ("ntkrnlmp.pdb", GUID, "65536"),
    ("ntkrnlmp.pdb", GUID, "0x1A"),
    ("ntkrnlmp.pdb", GUID, "1;id"),
    ("ntkrnlmp.pdb", GUID, " 1"),
    ("ntkrnlmp.pdb", GUID, "١"),  # a non-ASCII digit int() would accept
    ("https://evil.example/x.pdb", GUID, "1"),
    ("ntkrnlmp.pdb", GUID, "1e3"),
]


@pytest.mark.parametrize(("pdb", "guid", "age"), HOSTILE)
def test_hostile_pdb_identities_never_reach_the_network(
    env: dict[str, Path], capsys: pytest.CaptureFixture[str], pdb: str, guid: str, age: str
) -> None:
    code = main(["fetch-windows", "--pdb", pdb, "--guid", guid, "--age", age])
    assert code == 2
    err = capsys.readouterr().err
    for value in (pdb, guid, age):
        if any(ch in value for ch in "$;/%\n") or len(value) > 8:
            assert value not in err  # the refusal never echoes the hostile value


def test_a_refused_redirect_exits_1_and_names_the_host(
    env: dict[str, Path], capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def refused(*_: object, **__: object) -> None:
        raise fw.FetchRefused("redirect to host cdn.new.example ...", "cdn.new.example")

    monkeypatch.setattr(fw, "fetch_windows", refused)
    assert main(["fetch-windows", "--pdb", "ntkrnlmp.pdb", "--guid", GUID, "--age", "1"]) == 1
    events = _events(capsys.readouterr().err)
    assert events[0]["event"] == "command" and events[0]["pdb"]["guid"] == GUID
    assert {"event": "refused", "host": "cdn.new.example"}.items() <= events[-1].items()


def test_import_list_verify(env: dict[str, Path], capsys: pytest.CaptureFixture[str]) -> None:
    (env["import"] / "evil.json").write_bytes(dumps(linux_isf(HOSTILE_BANNER)))
    (env["import"] / "nt.json").write_bytes(dumps(windows_isf()))
    assert main(["import", "--file", "evil.json", "--no-reindex"]) == 0
    assert main(["import", "--file", "/import-is-elsewhere/nt.json", "--no-reindex"]) == 1
    assert main(["import", "--file", str(env["import"] / "nt.json"), "--no-reindex"]) == 0
    assert main(["list"]) == 0
    assert main(["verify"]) == 0
    out, err = capsys.readouterr()
    listed = [json.loads(line) for line in out.splitlines()]
    assert {e["os"] for e in listed} == {"linux", "windows"}
    banners = [e["identity"]["banner"] for e in listed if e["os"] == "linux"]
    assert banners == [HOSTILE_BANNER] and all(e["source"] == "operator" for e in listed)
    # RT12: the banner appears only as an escaped JSON value, never as raw text, and no line
    # that mentions a command carries any part of it.
    assert HOSTILE_BANNER not in out + err
    for line in (out + err).splitlines():
        if "pnpm" in line or "fetch-windows" in line or "--file" in line:
            assert "curl" not in line and "Linux version" not in line
    events = _events(err)
    assert any(e["event"] == "manifest_change" and e["action"] == "added" for e in events)
    verified = {"tool": "memory-symbols", "event": "verified", "files": 2, "mismatches": 0}
    assert events[-1] == verified


def test_verify_finds_tampered_and_unlisted_files(
    env: dict[str, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    (env["import"] / "nt.json").write_bytes(dumps(windows_isf()))
    assert main(["import", "--file", "nt.json", "--no-reindex"]) == 0
    entry = read_manifest(env["root"]).files[0]
    tamper(env["root"] / entry.path)
    planted = env["root"] / "linux" / "planted.json.xz"
    os.chmod(planted.parent, 0o755)
    planted.write_bytes(b"x")
    assert main(["verify"]) == 1
    mismatches = [e for e in _events(capsys.readouterr().err) if e["event"] == "mismatch"]
    assert {m["reason"] for m in mismatches} == {"sha256 differs", "not in the manifest"}


def test_an_import_reindexes_and_reports_a_refusal(
    env: dict[str, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    (env["import"] / "nt.json").write_bytes(dumps(windows_isf()))
    # The temp store is not at /symbols: the change is committed, reindex is refused (RT5).
    assert main(["import", "--file", "nt.json"]) == 1
    assert [f.path for f in read_manifest(env["root"]).files] == [
        isf_relpath(WindowsPdb(name="ntkrnlmp.pdb", guid=GUID, age=1))
    ]
    assert main(["reindex"]) == 1
    messages = [e.get("message", "") for e in _events(capsys.readouterr().err)]
    assert any("/symbols" in m for m in messages)


def test_a_refused_import_exits_1(env: dict[str, Path], capsys: pytest.CaptureFixture[str]) -> None:
    (env["import"] / "bad.json").write_bytes(b'{"metadata": {"format": "6.2.0"}}')
    assert main(["import", "--file", "bad.json"]) == 1
    assert _events(capsys.readouterr().err)[-1]["event"] == "refused"
    assert read_manifest(env["root"]).files == []


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["corpus"],
        ["import-pack", "--url", "https://example.invalid/pack.zip"],
        ["import"],
        ["import", "--file", "x.zip", "--sha256", "ABC"],
        ["fetch-windows", "--pdb", "ntkrnlmp.pdb"],
        ["verify", "--extra"],
    ],
)
def test_usage_errors_exit_2(env: dict[str, Path], argv: list[str]) -> None:
    assert main(argv) == 2


def test_a_broken_manifest_fails_list_and_verify(env: dict[str, Path]) -> None:
    os.chmod(env["root"] / "manifest.json", 0o644)
    (env["root"] / "manifest.json").write_text("{")
    assert main(["list"]) == 1
    assert main(["verify"]) == 1


def test_the_module_entry_point(tmp_path: Path) -> None:
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
    env["MEMORY_SYMBOLS_DIR"] = str(tmp_path)
    proc = subprocess.run(
        [sys.executable, "-m", "memory_worker.symbols", "list"],
        capture_output=True,
        text=True,
        env=env,
        cwd=Path(__file__).resolve().parents[2],
        timeout=60,
        check=False,
    )
    # A never-written store (no manifest yet) lists as empty, not as an error.
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    events = [json.loads(line) for line in proc.stderr.splitlines()]
    assert events[0]["event"] == "start"
    assert events[-1] == {
        "tool": "memory-symbols",
        "event": "listed",
        "files": 0,
        "volatility_version": None,
        "empty": True,
    }


def test_a_dangling_manifest_link_is_still_an_error(env: dict[str, Path]) -> None:
    manifest = env["root"] / "manifest.json"
    os.chmod(env["root"], 0o755)
    manifest.unlink()
    try:
        manifest.symlink_to(env["root"] / "nowhere.json")
    except OSError:
        pytest.skip("symlinks need privileges on this host")
    assert main(["list"]) == 1
