"""The `disk-hashsets` tool end to end (M9 phase 5). Synthetic inputs only; nothing is ever
downloaded.

- `test_cli_*`: the real CLI as a subprocess (`python -I -m disk_worker.hashsets`, the forked
  import child under the kit's seccomp filter) on temp store / import dirs: imports of an
  RDSv3-schema SQLite and md5sum / sha256 lists, `list`, `verify`, `remove`, and the negative
  cases (a symlink, `..`, a bad schema, bad digests, a killed import leaving no set). Runs in
  the disk worker image (fork + libseccomp); skipped elsewhere.
- `test_compose_*`: the compose definition (no network, uid 10008, `/import` read-only) where
  the repo's `docker-compose.yml` is visible, and, with `CYBERLAB_COMPOSE_TESTS=1` on a host
  with Docker, the real `docker compose --profile tools run --rm disk-hashsets-test` with the
  generated files in `./.disk-import`.
"""

import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from disk_worker.hashsets import manifest as mf
from tests.hashsets_fixtures import digests, make_list, make_rdsv3

REPO = Path(__file__).resolve().parents[5]
COMPOSE = REPO / "docker-compose.yml"


def _isolation_available() -> bool:
    if not hasattr(os, "fork"):
        return False
    try:
        from cyberlab_worker import seccomp  # noqa: F401
    except OSError:
        return False
    return True


needs_child = pytest.mark.skipif(
    not _isolation_available(), reason="the import child needs fork + libseccomp (disk image)"
)


@pytest.fixture
def dirs(tmp_path: Path) -> tuple[Path, Path]:
    store, imports = tmp_path / "hashsets", tmp_path / "import"
    store.mkdir()
    imports.mkdir()
    return store, imports


def _tool(store: Path, imports: Path, *args: str, **kw: object) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "DISK_HASHSETS_DIR": str(store),
        "DISK_HASHSETS_IMPORT_DIR": str(imports),
    }
    return subprocess.run(
        [sys.executable, "-I", "-m", "disk_worker.hashsets", *args],
        env=env,
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
        **kw,  # type: ignore[arg-type]
    )


@needs_child
def test_cli_imports_lists_verifies_and_removes(dirs: tuple[Path, Path]) -> None:
    store, imports = dirs
    rows = digests(1, 5000)
    make_rdsv3(imports / "rds.db", rows)
    make_list(imports / "bad.md5", [r[2] for r in digests(2, 100)] + ["zz", "0" * 31])
    make_list(imports / "tools.sha256", [r[0] for r in digests(3, 10)], md5sum_style=False)
    r = _tool(store, imports, "import-nsrl", "--file", "/import/rds.db", "--name", "nsrl-test")
    assert r.returncode == 0, r.stderr
    assert "sha256 5000" in r.stdout
    r = _tool(store, imports, "import-list", "--file", "/import/bad.md5", "--name", "lab-bad",
              "--kind", "known_bad", "--algo", "md5")
    assert r.returncode == 0, r.stderr
    assert "invalid 2" in r.stdout
    r = _tool(store, imports, "import-list", "--file", "tools.sha256", "--name", "tools",
              "--kind", "notable", "--algo", "sha256")
    assert r.returncode == 0, r.stderr
    r = _tool(store, imports, "list")
    assert [line.split("\t")[:2] for line in r.stdout.splitlines()] == [
        ["nsrl-test", "known_good"], ["lab-bad", "known_bad"], ["tools", "notable"]
    ]
    assert _tool(store, imports, "verify").returncode == 0
    assert _tool(store, imports, "remove", "--name", "tools").returncode == 0
    assert not (store / "tools").exists()
    with open(store / "lab-bad" / "md5.bin", "r+b") as f:
        f.write(b"\xff")
    r = _tool(store, imports, "verify")
    assert r.returncode == 1 and "lab-bad/md5.bin" in r.stdout


@needs_child
@pytest.mark.parametrize(
    "case", ["symlink", "dotdot", "absolute", "bad_schema", "not_sqlite", "bad_digests_only"]
)
def test_cli_negative_cases(dirs: tuple[Path, Path], tmp_path: Path, case: str) -> None:
    store, imports = dirs
    outside = make_list(tmp_path / "outside.txt", [digests(4, 1)[0][0]])
    args = ["import-list", "--name", "x", "--kind", "notable", "--algo", "sha256", "--file"]
    if case == "symlink":
        (imports / "link.txt").symlink_to(outside)
        args.append("/import/link.txt")
    elif case == "dotdot":
        args.append("/import/../outside.txt")
    elif case == "absolute":
        args.append(str(outside))
    elif case == "bad_schema":
        make_rdsv3(imports / "rds.db", digests(5, 10), drop_columns=("file_name",))
        args = ["import-nsrl", "--name", "x", "--file", "/import/rds.db"]
    elif case == "not_sqlite":
        (imports / "rds.db").write_bytes(os.urandom(4096))
        args = ["import-nsrl", "--name", "x", "--file", "/import/rds.db"]
    else:
        make_list(imports / "l.txt", ["zz" * 32, "g" * 64, "a" * 63])
        args.append("l.txt")
    r = _tool(store, imports, *args)
    assert r.returncode == 1, (r.stdout, r.stderr)
    assert "refused" in r.stderr
    assert mf.load(store).sets == []
    assert sorted(p.name for p in store.iterdir() if p.name != ".lock") == []


@needs_child
def test_cli_a_killed_import_leaves_no_set(dirs: tuple[Path, Path]) -> None:
    store, imports = dirs
    with open(imports / "big.txt", "w") as f:
        for sha256, _, _ in digests(6, 400_000):
            f.write(sha256 + "\n")
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "DISK_HASHSETS_DIR": str(store),
        "DISK_HASHSETS_IMPORT_DIR": str(imports),
    }
    proc = subprocess.Popen(
        [sys.executable, "-I", "-m", "disk_worker.hashsets", "import-list", "--file", "big.txt",
         "--name", "big", "--kind", "notable", "--algo", "sha256"],
        env=env, cwd=Path(__file__).resolve().parents[2], start_new_session=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 60
    while not (store / mf.STAGING_DIR).exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    os.killpg(proc.pid, signal.SIGKILL)
    proc.wait()
    assert mf.load(store).sets == []
    assert not (store / "big").exists()
    r = _tool(store, imports, "import-list", "--file", "big.txt", "--name", "big",
              "--kind", "notable", "--algo", "sha256")
    assert r.returncode == 0, r.stderr
    assert not (store / mf.STAGING_DIR).exists()
    assert _tool(store, imports, "verify").returncode == 0


# --- compose ---------------------------------------------------------------------------------


def _services() -> dict[str, dict[str, object]]:
    if not COMPOSE.is_file():
        pytest.skip("docker-compose.yml is not visible here")
    yaml = pytest.importorskip("yaml")
    services: dict[str, dict[str, object]] = yaml.safe_load(COMPOSE.read_text())["services"]
    return services


@pytest.mark.parametrize("name", ["disk-hashsets", "disk-hashsets-test", "disk-hashsets-init"])
def test_compose_the_tool_has_no_network(name: str) -> None:
    service = _services()[name]
    assert service.get("network_mode") == "none"
    assert "networks" not in service
    assert "ports" not in service


@pytest.mark.parametrize("name", ["disk-hashsets", "disk-hashsets-test"])
def test_compose_the_tool_runs_as_10008_with_import_read_only(name: str) -> None:
    service = _services()[name]
    assert service["user"] == "10008:10008"
    assert service["cap_drop"] == ["ALL"]
    assert service["read_only"] is True
    volumes = [str(v) for v in service["volumes"]]  # type: ignore[attr-defined]
    assert "./.disk-import:/import:ro" in volumes
    assert service["entrypoint"] == ["python", "-I", "-m", "disk_worker.hashsets"]


@pytest.fixture
def import_dir() -> Iterator[tuple[Path, str]]:
    if os.environ.get("CYBERLAB_COMPOSE_TESTS") != "1" or shutil.which("docker") is None:
        pytest.skip("set CYBERLAB_COMPOSE_TESTS=1 on a host with Docker")
    d = REPO / ".disk-import"
    d.mkdir(exist_ok=True)
    tag = uuid.uuid4().hex[:8]
    yield d, tag
    for p in d.glob(f"*{tag}*"):
        p.unlink()


def _compose(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "--profile", "tools", "run", "--rm", "disk-hashsets-test", *args],
        cwd=REPO,
        env={**os.environ, "MSYS_NO_PATHCONV": "1"},
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )


def test_compose_run_on_the_test_store(import_dir: tuple[Path, str]) -> None:
    d, tag = import_dir
    make_rdsv3(d / f"rds-{tag}.db", digests(7, 2000))
    make_list(d / f"bad-{tag}.txt", [r[0] for r in digests(8, 20)])
    name = f"it-{tag}"
    r = _compose("import-nsrl", "--file", f"/import/rds-{tag}.db", "--name", name)
    assert r.returncode == 0, r.stderr
    try:
        r = _compose("import-list", "--file", f"/import/bad-{tag}.txt", "--name", f"{name}-bad",
                     "--kind", "known_bad", "--algo", "sha256")
        assert r.returncode == 0, r.stderr
        listed = _compose("list").stdout
        assert name in listed and f"{name}-bad" in listed
        assert _compose("verify").returncode == 0
        assert _compose("import-list", "--file", "/import/../etc/passwd", "--name", "x",
                        "--kind", "notable", "--algo", "sha256").returncode == 1
    finally:
        _compose("remove", "--name", f"{name}-bad")
        assert _compose("remove", "--name", name).returncode == 0
    assert name not in _compose("list").stdout
