"""The radare2 run is fixed (RT9; pure Python): the frozen script holds only allow-listed lines
(configuration, analysis without ESIL, the four JSON listings, marker echoes, quit), the argv
is constant apart from root's own paths, and the limits are the planned ones."""

from pathlib import Path, PurePosixPath

from re_worker.engines.r2 import split_time
from re_worker.engines.spec import (
    R2_MAX_OUTPUT_BYTES,
    R2_OUTPUT,
    r2_spec,
    reducer_spec,
)
from re_worker.probe.r2 import MARKER, SECTIONS

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "r2" / "quick.r2"
ALLOWED_COMMANDS = {"aa", "aac", "aar", "aan", "ij", "aflj", "iij", "izj", "q"}
FORBIDDEN = ("!", "#!", ".", "`", "=", "o", "d", "w", "@", "aaaa", "ae", "pd", "r2pipe")


def _commands() -> list[str]:
    return [
        line.strip()
        for line in SCRIPT.read_text(encoding="ascii").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def test_script_lines_are_allow_listed() -> None:
    for command in _commands():
        head = command.split()[0]
        if head == "e":
            assert "=" in command and "@" not in command and "`" not in command, command
            continue
        if head == "?e":
            assert MARKER.match((command[3:] + "\n").encode()), command
            continue
        assert command in ALLOWED_COMMANDS, command
        assert not command.startswith(FORBIDDEN) or command in {"aa", "aac", "aar", "aan"}


def test_script_markers_are_the_reducer_sections_in_order() -> None:
    markers = [c[3:] for c in _commands() if c.startswith("?e ")]
    names = [m.removeprefix("===CYBERLAB:").removesuffix("===") for m in markers]
    assert names == [*SECTIONS, "end"]


def test_argv_is_constant() -> None:
    spec = r2_spec(
        script=Path("/opt/re/r2/quick.r2"),
        sample=PurePosixPath("/work/j/input/sample"),
        timeout_s=280,
    )
    assert spec.argv[1:6] == ("-q", "-NN", "-S", "-2", "-i")
    assert spec.argv[-1] == "/work/j/input/sample"
    assert spec.stdout_name == R2_OUTPUT and spec.limits.fsize_bytes == R2_MAX_OUTPUT_BYTES
    assert spec.limits.as_bytes == 1024**3 and spec.limits.cpu_s == 560
    assert spec.limits.nproc == 64 and spec.env == {}


def test_reducer_runs_as_an_isolated_probe() -> None:
    spec = reducer_spec(
        python="/py", out=PurePosixPath("/work/j/r2-out"), timeout_s=60, caps={"functions": 9}
    )
    assert spec.argv[:7] == ("/py", "-I", "-s", "-B", "-m", "re_worker.probe", "r2")
    assert "/work/j/r2-out/r2.out" in spec.argv and spec.key == "r2_reduce"
    assert spec.argv[spec.argv.index("--max-functions") + 1] == "9"


def test_split_time() -> None:
    assert split_time(300) == (225.0, 75.0)
    assert split_time(1000) == (880.0, 120.0)
    assert split_time(20) == (10.0, 10.0)
