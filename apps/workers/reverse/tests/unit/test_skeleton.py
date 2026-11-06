"""The phase-1 skeleton: the stubs keep their frozen signatures, the fixed radare2 script never
enables execution, the JVM argument helpers agree with our launch.properties."""

import inspect
from pathlib import Path, PurePosixPath

from re_worker import jvm_args, priority
from re_worker.detections import run as detect
from re_worker.engines.r2 import run_quick

ROOT = Path(__file__).resolve().parents[2]
QUICK = ROOT / "r2" / "quick.r2"
LAUNCH = ROOT / "docker" / "launch.properties"
# Command prefixes the quick script must never use: shell / rlang (`!`, `#!`), open or write
# files (`o`, `w`), debugger (`d`), web server (`=`), ESIL (`ae`, `aaaa`), run scripts (`.`).
FORBIDDEN_PREFIXES = ("!", "#!", "o", "d", "w", "=", "aaaa", "ae", ".")


def test_frozen_signatures() -> None:
    assert list(inspect.signature(priority.rank).parameters) == ["view", "job"]
    assert list(inspect.signature(detect).parameters) == ["view", "limits"]
    assert list(inspect.signature(run_quick).parameters) == ["ws", "job", "budget"]


def test_quick_script_never_executes_the_sample() -> None:
    commands = [
        line.strip()
        for line in QUICK.read_text().splitlines()
        if line.strip() and not line.startswith("# ")
    ]
    assert commands[-1] == "q"
    for command in commands:
        head = command.split()[0]
        if head == "e":
            continue  # configuration variables
        assert not head.startswith(FORBIDDEN_PREFIXES), command
    assert {"aflj", "iij", "izj", "ij"} <= set(commands)


def test_launch_properties_match_the_expected_vmargs() -> None:
    parsed = jvm_args.parse_launch_properties(LAUNCH.read_text())
    assert parsed == list(jvm_args.LAUNCH_PROPERTIES_VMARGS)
    assert not any(a.startswith(("-Xmx", "-XX:+Use", "-agent", "-javaagent")) for a in parsed)


def test_stage_args_and_cpu_limit() -> None:
    out = PurePosixPath("/work/job/out")
    args = jvm_args.stage_args(2 * 1024**3, out)
    assert args[0] == "-Xmx2048m" and "-XX:+DisableAttachMechanism" in args
    assert "-XX:ErrorFile=/work/job/out/hs_err.log" in args
    expected = jvm_args.expected_args(1024**3, out)
    assert expected[: len(jvm_args.LAUNCH_PROPERTIES_VMARGS)] == list(
        jvm_args.LAUNCH_PROPERTIES_VMARGS
    )
    assert jvm_args.mismatch(expected, expected) == []
    assert jvm_args.mismatch([*expected, "-javaagent:x.jar"], expected) == ["-javaagent:x.jar"]
    assert jvm_args.cpu_limit_s(1500) == 3060  # RT3
