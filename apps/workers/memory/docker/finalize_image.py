"""Build-time only: assert the dependency set, lock site-packages, keep the VSL license text
and write /etc/cyberlab/versions.json (M8 phase 1).

- The forbidden modules are NOT importable: `leechcorepyc` (GPLv3, live acquisition),
  `Crypto` (pycryptodome: only the credential dumpers need it), `PIL` (pillow), `smb` (pysmb,
  Volatility's smb:// handler), `yara` / `yara_x` (M8 runs no YARA, RT8).
- `volatility3` is exactly 2.28.2 and unmodified (nothing is removed or patched: VSL).
- site-packages is root-owned and writable by root only (a tool process can never plant a
  plugin, a symbol table or a .pth file).
- The wheel's LICENSE.txt is copied to /usr/share/doc/volatility3/ (VSL redistribution).
"""

from __future__ import annotations

import importlib.util
import json
import os
import platform
import shutil
import stat
import sys
from importlib.metadata import PackageNotFoundError, distribution, version
from pathlib import Path

VOLATILITY_VERSION = "2.28.2"
FORBIDDEN_MODULES = ("leechcorepyc", "Crypto", "PIL", "smb", "yara", "yara_x")
FORBIDDEN_DISTS = ("leechcorepyc", "pycryptodome", "pillow", "pysmb", "yara-python", "yara-x")
LICENSE_DIR = Path("/usr/share/doc/volatility3")
VERSIONS = Path("/etc/cyberlab/versions.json")


def assert_forbidden_absent() -> None:
    present = [m for m in FORBIDDEN_MODULES if importlib.util.find_spec(m) is not None]
    for name in FORBIDDEN_DISTS:
        try:
            distribution(name)
        except PackageNotFoundError:
            continue
        present.append(name)
    if present:
        raise SystemExit(f"forbidden dependencies in the image: {sorted(set(present))}")


def assert_volatility() -> None:
    import volatility3

    found = getattr(volatility3, "__version__", None) or version("volatility3")
    if found != VOLATILITY_VERSION or version("volatility3") != VOLATILITY_VERSION:
        raise SystemExit(f"volatility3 must be {VOLATILITY_VERSION}, found {found}")


def keep_license() -> None:
    files = [
        f
        for f in distribution("volatility3").files or []
        if Path(str(f)).name.upper() in {"LICENSE.TXT", "LICENSE"}
    ]
    if not files:
        raise SystemExit("the volatility3 wheel ships no LICENSE.txt: refusing to redistribute it")
    LICENSE_DIR.mkdir(parents=True, exist_ok=True)
    target = LICENSE_DIR / "LICENSE.txt"
    shutil.copyfile(Path(str(files[0].locate())), target)
    target.chmod(0o444)


def lock_site_packages() -> None:
    for root in sorted({p for p in sys.path if p.endswith("site-packages")}):
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


def main() -> None:
    assert_forbidden_absent()
    assert_volatility()
    keep_license()
    lock_site_packages()
    versions = {
        "python": platform.python_version(),
        "volatility3": version("volatility3"),
        "pefile": version("pefile"),
        "capstone": version("capstone"),
        "jsonschema": version("jsonschema"),
    }
    VERSIONS.parent.mkdir(parents=True, exist_ok=True)
    VERSIONS.write_text(json.dumps(versions, sort_keys=True) + "\n")
    print(VERSIONS.read_text())


if __name__ == "__main__":
    main()
