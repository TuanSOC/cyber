"""The JVM stages' argv and environment (pure Python; RT1, RT19): only root-chosen values
reach a stage, no JVM option variable ever does, and the expected argument list is ours."""

from pathlib import Path, PurePosixPath

import pytest

from re_worker import jvm_args
from re_worker.engines.spec import (
    JVM_SUBDIRS,
    UnsafeEnvironment,
    analyze_spec,
    assert_clean_env,
    decompile_spec,
    jvm_env,
)

OUT = PurePosixPath("/work/job/analyze-out")
JAVA = Path("/opt/java/openjdk")
GHIDRA = Path("/opt/ghidra")


def _analyze() -> object:
    return analyze_spec(
        python="/opt/venv/bin/python",
        out=OUT,
        sample=PurePosixPath("/work/job/input/sample"),
        loader="pe",
        project=PurePosixPath("/work/job/project"),
        heap=2 * 1024**3,
        as_bytes=5 * 1024**3,
        timeout_s=1800,
        analysis_timeout_s=1500,
        caps={"functions": 20000, "strings": 100},
        java_home=JAVA,
        ghidra_dir=GHIDRA,
    )


def test_analyze_argv_is_the_isolated_probe() -> None:
    spec = _analyze()
    argv = list(spec.argv)  # type: ignore[attr-defined]
    assert argv[:6] == ["/opt/venv/bin/python", "-I", "-s", "-B", "-m", "re_worker.probe"]
    assert argv[6] == "analyze"
    assert argv[argv.index("--loader") + 1] == "pe"
    assert argv[argv.index("--max-functions") + 1] == "20000"
    assert spec.subdirs == JVM_SUBDIRS and spec.heap_bytes == 2 * 1024**3  # type: ignore[attr-defined]
    assert spec.stdout_name == "rows.jsonl"  # type: ignore[attr-defined]


def test_jvm_environment_is_fresh_and_clean() -> None:
    env = jvm_env(OUT, JAVA, GHIDRA)
    assert env == {
        "JAVA_HOME": str(JAVA),
        "GHIDRA_INSTALL_DIR": str(GHIDRA),
        "MALLOC_ARENA_MAX": "2",
        "HOME": "/work/job/analyze-out/home",
        "TMPDIR": "/work/job/analyze-out/tmp",
        "XDG_CONFIG_HOME": "/work/job/analyze-out/xdg/config",
        "XDG_CACHE_HOME": "/work/job/analyze-out/xdg/cache",
    }
    for name in jvm_args.FORBIDDEN_ENV:
        assert name not in env
    assert {"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "DEBUGINFOD_URLS"} <= set(
        jvm_args.FORBIDDEN_ENV
    )


@pytest.mark.parametrize("name", jvm_args.FORBIDDEN_ENV)
def test_forbidden_variables_are_refused(name: str) -> None:
    with pytest.raises(UnsafeEnvironment):
        assert_clean_env({"HOME": "/x", name: "-javaagent:/tmp/a.jar"})


def test_decompile_spec_has_its_own_heap_and_the_list() -> None:
    out = PurePosixPath("/work/job/decompile-out")
    spec = decompile_spec(
        python="/py",
        out=out,
        project=PurePosixPath("/work/job/project"),
        listing=PurePosixPath("/work/job/stage/decompile_list.json"),
        heap=1024**3,
        as_bytes=4 * 1024**3,
        timeout_s=600,
        java_home=JAVA,
        ghidra_dir=GHIDRA,
    )
    argv = list(spec.argv)
    assert argv[argv.index("--heap") + 1] == str(1024**3)
    assert argv[argv.index("--list") + 1] == "/work/job/stage/decompile_list.json"
    assert spec.env["HOME"] == "/work/job/decompile-out/home"
    expected = jvm_args.expected_args(1024**3, out)
    assert "-Xmx1024m" in expected and "-XX:+DisableAttachMechanism" in expected
    assert "-XX:ErrorFile=/work/job/decompile-out/hs_err.log" in expected
