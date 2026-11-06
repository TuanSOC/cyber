"""The expected JVM arguments of each Ghidra stage (M10 phase 1, FROZEN; RT1 / RT3 / RT4 / RT19).

The probe passes `stage_args(...)`; PyGhidra's launcher prepends the `VMARGS` of our own
`support/launch.properties` (`LAUNCH_PROPERTIES_VMARGS`); root compares the JVM's effective
`RuntimeMXBean.getInputArguments()` (reported in the header's `jvm_args`) with
`expected_args(...)` and fails the stage on any difference. Values are PROVISIONAL until the
phase-2 spike (the parent applies its values in one follow-up commit).

JIT code is RWX on Linux x86-64: no W^X / MDWE control applies to the JVM (RT29, stated).
"""

from collections.abc import Sequence
from pathlib import PurePosixPath
from typing import Literal

Stage = Literal["analyze", "decompile"]

# What docker/launch.properties carries (VMARGS, then VMARGS_LINUX); test_jvm_args pins it.
LAUNCH_PROPERTIES_VMARGS: tuple[str, ...] = (
    "-Djava.system.class.loader=ghidra.GhidraClassLoader",
    "-Dfile.encoding=UTF8",
    "-Duser.country=US",
    "-Duser.language=en",
    "-Duser.variant=",
    "-Dsun.java2d.opengl=false",
    "-Djdk.tls.client.protocols=TLSv1.2,TLSv1.3",
    "-Xshare:off",
    "-Dsun.java2d.xrender=false",
)
# Environment variables the JVM would read options from: absent in every stage (RT19).
FORBIDDEN_ENV: tuple[str, ...] = (
    "JAVA_TOOL_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "_JAVA_OPTIONS",
    "DEBUGINFOD_URLS",
    "CLASSPATH",
)


def _mib(value: int) -> str:
    return f"{value // (1024 * 1024)}m"


def stage_args(heap_bytes: int, out_dir: PurePosixPath) -> list[str]:
    """Our arguments for one stage JVM (same set for `analyze` and `decompile`, only the heap
    differs: RE_JVM_HEAP / RE_DECOMPILE_JVM_HEAP)."""
    return [
        f"-Xmx{_mib(heap_bytes)}",
        "-XX:+UseSerialGC",
        "-XX:ActiveProcessorCount=2",
        "-XX:ReservedCodeCacheSize=128m",
        "-XX:MaxMetaspaceSize=512m",
        "-XX:CompressedClassSpaceSize=256m",
        "-XX:MaxDirectMemorySize=256m",
        "-Xss1m",
        "-XX:-UsePerfData",
        "-XX:+DisableAttachMechanism",
        "-XX:+ExitOnOutOfMemoryError",
        f"-XX:ErrorFile={out_dir / 'hs_err.log'}",
        "-Djava.awt.headless=true",
        f"-Duser.home={out_dir / 'home'}",
        f"-Djava.io.tmpdir={out_dir / 'tmp'}",
    ]


def expected_args(heap_bytes: int, out_dir: PurePosixPath) -> list[str]:
    """The JVM's effective input arguments: launch.properties first, then ours."""
    return [*LAUNCH_PROPERTIES_VMARGS, *stage_args(heap_bytes, out_dir)]


def parse_launch_properties(text: str) -> list[str]:
    """`VMARGS` then `VMARGS_LINUX` values of a launch.properties text, in file order."""
    common: list[str] = []
    linux: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        if key == "VMARGS":
            common.append(value)
        elif key == "VMARGS_LINUX":
            linux.append(value)
    return [*common, *linux]


def cpu_limit_s(stage_timeout_s: int) -> int:
    """RLIMIT_CPU of a JVM stage (RT3): it sums every thread's CPU on 2 CPUs, so the wall
    timeout and the analysis monitor are the real bounds."""
    return 2 * stage_timeout_s + 60


def mismatch(effective: Sequence[str], expected: Sequence[str]) -> list[str]:
    """Arguments in one list and not the other (empty when they are equal, order included)."""
    if list(effective) == list(expected):
        return []
    return sorted(set(effective) ^ set(expected)) or ["<order differs>"]
