"""Build-time only: assert the pinned engines, lock the install trees, keep the license texts
and write /etc/cyberlab/versions.json (M10 phase 1; the trim list is provisional until the
phase-2 spike).

- Ghidra is exactly 12.2 (`Ghidra/application.properties`), trimmed: no `server/`,
  `Ghidra/Features/Jython`, `Ghidra/Debug`, no processor but x86 and DATA, no bundled
  extension; its `support/launch.properties` is byte-identical to our reviewed copy (RT1).
- The JDK is 25 (`/opt/java/openjdk/release`); PyGhidra is 3.2.x (the wheel bundled in the
  verified zip) and no Python entry point of a `pyghidra*` group is installed (RT1: the
  launcher must find no plugin to install); JPype1 is present; `r2pipe` is absent (RT9).
- radare2 is 6.2.6 (`dpkg-query`).
- `/opt/ghidra`, `/opt/java`, `/opt/re` and site-packages are root-owned and writable by root
  only (a tool process can never plant a class, a plugin or a .pth file).
- The dev target also has the compilers of the phase-4 samples; the prod target has none.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import stat
import subprocess  # noqa: S404 - build time only, fixed argv
import sys
from importlib.metadata import PackageNotFoundError, entry_points, version
from pathlib import Path

GHIDRA = Path("/opt/ghidra")
JAVA = Path("/opt/java/openjdk")
GHIDRA_VERSION = "12.2"
JDK_MAJOR = "25"
PYGHIDRA_PREFIX = "3.2"
RADARE2_VERSION = "6.2.6"
KEPT_PROCESSORS = {"x86", "DATA"}
ABSENT = ("server", "Ghidra/Features/Jython", "Ghidra/Debug", "docs", "Extensions/Ghidra")
FORBIDDEN_MODULES = ("r2pipe", "jython")
OUR_LAUNCH_PROPERTIES = Path("/usr/local/lib/cyberlab/launch.properties")
DECOMPILER = GHIDRA / "Ghidra/Features/Decompiler/os/linux_x86_64/decompile"
QUICK_SCRIPT = Path("/opt/re/r2/quick.r2")
ARTIFACTS = Path("/usr/local/lib/cyberlab/artifacts.json")
DOC = Path("/usr/share/doc/cyberlab-re")
VERSIONS = Path("/etc/cyberlab/versions.json")
DEV_TOOLS = ("gcc", "x86_64-w64-mingw32-gcc", "i686-w64-mingw32-gcc", "nm", "strip")


def fail(message: str) -> None:
    raise SystemExit(f"finalize_image: {message}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ghidra_version() -> str:
    text = (GHIDRA / "Ghidra/application.properties").read_text(encoding="utf-8")
    match = re.search(r"^application\.version=(\S+)$", text, re.MULTILINE)
    if match is None or match.group(1) != GHIDRA_VERSION:
        fail(f"Ghidra must be {GHIDRA_VERSION}, found {match.group(1) if match else None}")
    return match.group(1)


def assert_trimmed() -> None:
    present = [name for name in ABSENT if (GHIDRA / name).exists()]
    if present:
        fail(f"trimmed parts are present: {present}")
    processors = {p.name for p in (GHIDRA / "Ghidra/Processors").iterdir()}
    if processors != KEPT_PROCESSORS:
        fail(f"processors must be {sorted(KEPT_PROCESSORS)}, found {sorted(processors)}")
    if not os.access(DECOMPILER, os.X_OK):
        fail("the decompiler binary is missing")
    ours = OUR_LAUNCH_PROPERTIES.read_bytes()
    if (GHIDRA / "support/launch.properties").read_bytes() != ours:
        fail("support/launch.properties is not our reviewed copy (RT1)")


def jdk_version() -> str:
    text = (JAVA / "release").read_text(encoding="utf-8")
    match = re.search(r'^JAVA_VERSION="([^"]+)"$', text, re.MULTILINE)
    if match is None or match.group(1).split(".")[0] != JDK_MAJOR:
        fail(f"the JDK must be {JDK_MAJOR}, found {match.group(1) if match else None}")
    return match.group(1)


def python_engines() -> dict[str, str]:
    found = {}
    for dist in ("pyghidra", "JPype1"):
        try:
            found[dist] = version(dist)
        except PackageNotFoundError:
            fail(f"{dist} is not installed")
    if not found["pyghidra"].startswith(PYGHIDRA_PREFIX):
        fail(f"PyGhidra must be {PYGHIDRA_PREFIX}.x, found {found['pyghidra']}")
    present = [m for m in FORBIDDEN_MODULES if importlib.util.find_spec(m) is not None]
    if present:
        fail(f"forbidden modules are importable: {present}")
    plugin_groups = sorted({ep.group for ep in entry_points() if ep.group.startswith("pyghidra")})
    if plugin_groups:
        fail(f"PyGhidra plugin entry points are installed: {plugin_groups} (RT1)")
    return found


def radare2_version() -> str:
    out = subprocess.run(  # noqa: S603 - fixed argv
        ["/usr/bin/dpkg-query", "-W", "-f=${Version}", "radare2"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not out.startswith(RADARE2_VERSION):
        fail(f"radare2 must be {RADARE2_VERSION}, found {out}")
    if stat.S_IMODE(QUICK_SCRIPT.stat().st_mode) != 0o444 or QUICK_SCRIPT.stat().st_uid != 0:
        fail("the quick script must be root-owned 0444 (RT9)")
    return out


def assert_tools(target: str) -> None:
    present = [tool for tool in DEV_TOOLS if shutil.which(tool)]
    if target == "dev" and len(present) != len(DEV_TOOLS):
        fail(f"the dev target needs {DEV_TOOLS}, found {present}")
    if target == "prod" and {"gcc", "x86_64-w64-mingw32-gcc", "i686-w64-mingw32-gcc"} & set(
        present
    ):
        fail(f"no compiler in the prod target, found {present}")


def lock_tree(root: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(root):
        os.chown(dirpath, 0, 0)
        Path(dirpath).chmod(0o755)
        for name in [*dirnames, *filenames]:
            path = Path(dirpath) / name
            if path.is_symlink() or path.is_dir():
                continue
            os.chown(path, 0, 0)
            mode = stat.S_IMODE(path.stat().st_mode)
            path.chmod(mode & ~(stat.S_IWGRP | stat.S_IWOTH))


def keep_licenses() -> None:
    DOC.mkdir(parents=True, exist_ok=True)
    for name in ("LICENSE", "LICENSE.txt", "NOTICE"):
        for root in (GHIDRA, JAVA):
            source = root / name
            if source.is_file():
                shutil.copyfile(source, DOC / f"{root.name}-{name}")
    jdk_legal = JAVA / "legal"
    if jdk_legal.is_dir():
        shutil.copytree(jdk_legal, DOC / "jdk-legal", dirs_exist_ok=True)
    r2_copyright = Path("/usr/share/doc/radare2/copyright")
    if r2_copyright.is_file():
        shutil.copyfile(r2_copyright, DOC / "radare2-copyright")
    if not (DOC / "licenses").is_dir():
        fail("the Ghidra license texts were not staged by trim-ghidra.sh")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=("dev", "prod"), required=True)
    target = parser.parse_args().target
    ghidra = ghidra_version()
    assert_trimmed()
    jdk = jdk_version()
    engines = python_engines()
    radare2 = radare2_version()
    assert_tools(target)
    keep_licenses()
    for root in (GHIDRA, JAVA, QUICK_SCRIPT.parent):
        lock_tree(root)
    for root in sorted({p for p in sys.path if p.endswith("site-packages")}):
        lock_tree(Path(root))
    artifacts = json.loads(ARTIFACTS.read_text(encoding="utf-8"))
    versions = {
        "python": platform.python_version(),
        "ghidra": ghidra,
        "jdk": jdk,
        "pyghidra": engines["pyghidra"],
        "jpype": engines["JPype1"],
        "radare2": radare2,
        "ghidra_zip_sha256": artifacts["ghidra_zip_sha256"],
        "radare2_deb_sha256": artifacts["radare2_deb_sha256"],
        "jdk_image": artifacts["jdk_image"],
        "launch_properties_sha256": sha256(OUR_LAUNCH_PROPERTIES),
        "quick_script_sha256": sha256(QUICK_SCRIPT),
        "target": target,
    }
    VERSIONS.parent.mkdir(parents=True, exist_ok=True)
    VERSIONS.write_text(json.dumps(versions, sort_keys=True) + "\n")
    print(VERSIONS.read_text())


if __name__ == "__main__":
    main()
