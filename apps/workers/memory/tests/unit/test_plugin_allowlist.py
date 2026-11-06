"""The probe's plugin table is the allow-list (pure Python): exactly the frozen `MemoryPlugin`
set, every profile's plugins covered, no write option ever true, nothing else runnable."""

from pathlib import Path

import pytest
from cyberlab_jobs.memory import PLUGINS_BY_PROFILE, MemoryPlugin

from memory_worker.probe import main as probe_main
from memory_worker.probe.plugins import PLUGINS, WRITE_OPTIONS, UnknownPlugin, max_rows, spec_for
from tests.replay_helpers import LIMITS

NEVER = [
    "windows.handles",
    "windows.registry.hashdump.Hashdump",
    "windows.registry.hashdump",
    "windows.registry.lsadump",
    "windows.registry.cachedump",
    "windows.envars",
    "windows.dumpfiles",
    "windows.memmap",
    "windows.registry.printkey",
    "windows.vadyarascan",
    "yarascan.YaraScan",
    "linux.vmayarascan",
    "linux.pagecache.RecoverFs",
    "linux.pagecache.Files",
    "windows.malfind",  # the deprecated shim, never the allow-listed name
    "windows.pslist.PsList",
    "",
    "../windows.pslist",
]


def test_the_table_is_exactly_the_frozen_allow_list() -> None:
    assert set(PLUGINS) == set(MemoryPlugin)
    for plugins in PLUGINS_BY_PROFILE.values():
        assert set(plugins) <= set(PLUGINS)
    for plugin, spec in PLUGINS.items():
        assert spec.plugin is plugin
        # The class path names the plugin's own module (current names, not shims).
        assert spec.class_path.rsplit(".", 1)[0] == plugin.value


def test_no_write_option_is_ever_set() -> None:
    for spec in PLUGINS.values():
        for name, value in spec.options.items():
            if name in WRITE_OPTIONS:
                assert value is False, (spec.plugin, name)
    dumps = {p for p, s in PLUGINS.items() if "dump" in s.options}
    assert MemoryPlugin.WINDOWS_PSLIST in dumps and MemoryPlugin.LINUX_HIDDEN_MODULES in dumps
    assert PLUGINS[MemoryPlugin.LINUX_MALFIND].options["dump-regions"] is False
    assert PLUGINS[MemoryPlugin.WINDOWS_PSSCAN].options["physical"] is False


@pytest.mark.parametrize("name", NEVER)
def test_nothing_outside_the_table_is_runnable(name: str) -> None:
    with pytest.raises(UnknownPlugin):
        spec_for(name)


@pytest.mark.parametrize("name", ["windows.handles", "windows.registry.hashdump", "x; rm -rf /"])
def test_the_probe_refuses_before_importing_volatility(name: str, tmp_path: Path) -> None:
    out = tmp_path.resolve()
    argv = ["run", name, "--max-rows", "10", "--image", str(out / "i"), "--symbols", str(out)]
    assert probe_main.main([*argv, "--out", str(out)]) == probe_main.EXIT_USAGE
    assert not (out / "status.json").exists()


def test_the_probe_refuses_relative_paths_and_absurd_caps(tmp_path: Path) -> None:
    out = str(tmp_path.resolve())
    rel = ["run", "windows.pslist", "--max-rows", "10", "--image", "image"]
    assert probe_main.main([*rel, "--symbols", out, "--out", out]) == probe_main.EXIT_USAGE
    big = ["run", "windows.pslist", "--max-rows", str(10**9), "--image", out + "/i"]
    assert probe_main.main([*big, "--symbols", out, "--out", out]) == probe_main.EXIT_USAGE


def test_row_caps_follow_the_job_limits() -> None:
    assert max_rows(PLUGINS[MemoryPlugin.WINDOWS_PSLIST], LIMITS) == LIMITS.max_processes
    assert max_rows(PLUGINS[MemoryPlugin.WINDOWS_NETSCAN], LIMITS) == LIMITS.max_connections
    assert max_rows(PLUGINS[MemoryPlugin.LINUX_MALFIND], LIMITS) == LIMITS.max_injections
    assert max_rows(PLUGINS[MemoryPlugin.LINUX_LSOF], LIMITS) == LIMITS.max_artifacts
