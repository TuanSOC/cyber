"""Start the JVM through PyGhidra in library mode (M10 phase 2; RT1). Tool uid only.

PyGhidra's launcher is not side-effect free (RT1, `pyghidra/launcher.py`): `start()` may run
`LaunchSupport` through `subprocess.check_output(..., shell=True)` and `java -version` to find
the JDK, merges the `VMARGS` of `support/launch.properties` into the JVM arguments, and may
install Python plugins of Ghidra extensions (a lock file in `tempfile.gettempdir()`). Hence:
- the pinned JDK home is set on the launcher before `start()`, so the discovery subprocess
  is skipped where the launcher honours it [I: the spike records whether 3.2 does; if not,
  the two root-controlled helper runs happen before the audit hook and are recorded];
- the image ships our reviewed `support/launch.properties` (root-owned), so the merged list
  is exactly `jvm_args.LAUNCH_PROPERTIES_VMARGS` + our `stage_args`;
- plugin installation finds nothing (trimmed `Extensions/`, no `pyghidra*` entry point,
  read-only site-packages: asserted by `docker/finalize_image.py`);
- the audit hook is installed by the caller **after** this returns;
- the JVM's effective `RuntimeMXBean.getInputArguments()` is returned for `status.json`;
  root compares it with `jvm_args.expected_args` (mismatch: `jvm_start_failed`).
"""

from pathlib import Path
from typing import Any

GHIDRA_DIR = Path("/opt/ghidra")
JAVA_HOME = Path("/opt/java/openjdk")
DECOMPILER = GHIDRA_DIR / "Ghidra/Features/Decompiler/os/linux_x86_64/decompile"
SPAWN_HELPER = JAVA_HOME / "lib/jspawnhelper"
MAX_ARGS = 64


def _pin_java_home(launcher: Any, java_home: Path) -> None:
    for attribute in ("java_home", "_java_home"):
        if hasattr(launcher, attribute):
            try:
                setattr(launcher, attribute, java_home)
                return
            except AttributeError:  # a read-only property in this PyGhidra version
                continue


def start(
    vmargs: list[str], *, install_dir: Path = GHIDRA_DIR, java_home: Path = JAVA_HOME
) -> list[str]:
    """Start the JVM with `vmargs` appended to launch.properties; return the effective JVM
    input arguments (at most `MAX_ARGS`, each cut at 512 characters)."""
    from pyghidra.launcher import HeadlessPyGhidraLauncher

    launcher = HeadlessPyGhidraLauncher(install_dir=install_dir, verbose=False)
    _pin_java_home(launcher, java_home)
    launcher.add_vmargs(*vmargs)
    launcher.start()

    from java.lang.management import ManagementFactory

    arguments = ManagementFactory.getRuntimeMXBean().getInputArguments()
    return [str(a)[:512] for a in list(arguments)[:MAX_ARGS]]


__all__ = ["DECOMPILER", "GHIDRA_DIR", "JAVA_HOME", "SPAWN_HELPER", "start"]
