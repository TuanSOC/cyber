"""Build-time only (M9 phase 1): assert the pins and the forbidden set, lock site-packages, ship
the license texts and NOTICE, and write /etc/cyberlab/versions.json.

- Pins: `pytsk3` 20260715 (bundles TSK 4.15.0), `libewf-python` (`pyewf`) 20260924, `plaso`
  20261027 in /opt/plaso, `yara-python` 4.x (the M3 pin).
- Forbidden in every target: the Debian `sleuthkit` and `python3-tsk` packages and their
  binaries (`fls`, `icat`, `mmls`, ...), TSK's GPL `srch_strings`.
- Forbidden in the prod target only (the dev target installs them for the phase-4 image
  generator): `ewf-tools` (`ewfacquirestream`, `ewfverify`), `mkfs.*`, `mtools`, `ntfs-3g`,
  `sfdisk`, and any compiler (`cc`, `gcc`; the Plaso builder stage stays behind, RT11).
- The M3 baseline rule source baked into /opt/rules/image/ hashes to `BASELINE_SHA256` (RT8).
- site-packages (the worker venv and /opt/plaso) is root-owned and not writable by others.
- Every installed distribution's license file is copied to /usr/share/doc/cyberlab-disk/
  licenses/, and NOTICE (TSK IBM-PL / CPL, libyal LGPL-3.0+ with source links, Apache-2.0
  components) is written beside them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
from importlib.metadata import PackageNotFoundError, distributions, version
from pathlib import Path

PYTSK3 = "20260715"
LIBEWF = "20260924"
PLASO = "20261027"
YARA_MAJOR = "4."
PLASO_PYTHON = Path("/opt/plaso/bin/python")
RULES = Path("/opt/rules/image/cyberlab_baseline.yar")
DOC = Path("/usr/share/doc/cyberlab-disk")
VERSIONS = Path("/etc/cyberlab/versions.json")
FORBIDDEN_DEBIAN = ("sleuthkit", "python3-tsk", "libtsk19", "libtsk-dev")
PROD_ONLY_DEBIAN = ("ewf-tools", "mtools", "ntfs-3g", "dosfstools", "e2fsprogs-l10n")
FORBIDDEN_BINARIES = ("fls", "icat", "mmls", "fsstat", "tsk_recover", "srch_strings")
PROD_ONLY_FORBIDDEN = (
    "ewfverify",
    "mkfs.fat",
    "mkfs.ext4",
    "mke2fs",
    "mkfs.exfat",
    "mkntfs",
    "mcopy",
    "mtools",
    "ntfs-3g",
    "ntfscp",
    "sfdisk",
    "ewfacquirestream",
    "cc",
    "gcc",
    "c++",
)


def _dpkg_installed(package: str) -> bool:
    result = subprocess.run(  # noqa: S603 - fixed argv
        ["/usr/bin/dpkg-query", "-W", "-f=${Status}", package],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0 and "install ok installed" in result.stdout


def assert_forbidden_absent(target: str) -> None:
    packages = FORBIDDEN_DEBIAN + (PROD_ONLY_DEBIAN if target == "prod" else ())
    present = [p for p in packages if _dpkg_installed(p)]
    binaries = list(FORBIDDEN_BINARIES)
    if target == "prod":
        binaries += PROD_ONLY_FORBIDDEN
    present += [b for b in binaries if shutil.which(b) is not None]
    if present:
        raise SystemExit(f"forbidden in the {target} image: {sorted(set(present))}")


def assert_pins() -> dict[str, str]:
    import pyewf  # type: ignore[import-not-found]
    import pytsk3  # type: ignore[import-not-found]
    import yara  # type: ignore[import-not-found]

    found = {
        "pytsk3": version("pytsk3"),
        "libewf-python": version("libewf-python"),
        "yara-python": version("yara-python"),
    }
    if found["pytsk3"] != PYTSK3 or found["libewf-python"] != LIBEWF:
        raise SystemExit(f"pins: pytsk3 {PYTSK3}, libewf-python {LIBEWF}; found {found}")
    if not found["yara-python"].startswith(YARA_MAJOR):
        raise SystemExit(f"yara-python must be 4.x, found {found['yara-python']}")
    plaso = subprocess.run(  # noqa: S603 - fixed argv
        [str(PLASO_PYTHON), "-I", "-c", "import plaso; print(plaso.__version__)"],
        capture_output=True,
        text=True,
        check=False,
    )
    if plaso.returncode != 0 or plaso.stdout.strip() != PLASO:
        raise SystemExit(f"/opt/plaso must hold plaso {PLASO}: {plaso.stdout} {plaso.stderr}")
    launch = subprocess.run(  # noqa: S603 - fixed argv
        [str(PLASO_PYTHON), "-I", "-c", "import cyberlab_plaso_launch, cyberlab_plaso_export"],
        capture_output=True,
        check=False,
    )
    if launch.returncode != 0:
        raise SystemExit("cyberlab_plaso_launch / _export are not importable under -I (RT24)")
    return {
        **found,
        "tsk": str(getattr(pytsk3, "TSK_VERSION_STR", "unknown")),
        "pyewf": str(getattr(pyewf, "get_version", lambda: "unknown")()),
        "yara": str(getattr(yara, "YARA_VERSION", "unknown")),
        "plaso": PLASO,
    }


def assert_rules() -> str:
    from cyberlab_worker.yara_rules import BASELINE_SHA256

    digest = hashlib.sha256(RULES.read_bytes()).hexdigest()
    if digest != BASELINE_SHA256:
        raise SystemExit(f"{RULES} hashes to {digest}, not BASELINE_SHA256 (RT8)")
    return digest


def _site_packages(python: str) -> list[str]:
    out = subprocess.run(  # noqa: S603 - fixed argv
        [python, "-I", "-c", "import site, json; print(json.dumps(site.getsitepackages()))"],
        capture_output=True,
        text=True,
        check=True,
    )
    return [str(p) for p in json.loads(out.stdout)]


def lock_site_packages() -> None:
    roots = {p for p in sys.path if p.endswith("site-packages")}
    roots |= set(_site_packages(str(PLASO_PYTHON)))
    for root in sorted(roots):
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


def keep_licenses() -> list[str]:
    """Each worker-venv distribution's license files (the /opt/plaso ones are copied by the
    same loop run with the Plaso interpreter, phase 3 extends it)."""
    target = DOC / "licenses"
    target.mkdir(parents=True, exist_ok=True)
    kept = []
    for dist in distributions():
        name = dist.metadata["Name"] or "unknown"
        for f in dist.files or []:
            base = Path(str(f)).name.upper()
            if base.startswith(("LICENSE", "COPYING", "NOTICE")):
                dest = target / f"{name}-{Path(str(f)).name}"
                try:
                    shutil.copyfile(Path(str(f.locate())), dest)
                except OSError:
                    continue
                dest.chmod(0o444)
                kept.append(name)
    for required in ("pytsk3", "libewf-python", "yara-python"):
        if required not in kept:
            raise SystemExit(f"the {required} wheel ships no license file: refusing to ship it")
    return sorted(set(kept))


def write_notice() -> None:
    notice = (DOC / "NOTICE.md").read_text(encoding="utf-8")
    (DOC / "NOTICE").write_text(notice, encoding="utf-8")
    (DOC / "NOTICE").chmod(0o444)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=("dev", "prod"), required=True)
    target = parser.parse_args().target
    assert_forbidden_absent(target)
    pins = assert_pins()
    rules_sha256 = assert_rules()
    keep_licenses()
    write_notice()
    lock_site_packages()
    try:
        artifacts = subprocess.run(  # noqa: S603 - fixed argv
            [str(PLASO_PYTHON), "-I", "-c", "import artifacts; print(artifacts.__version__)"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, PackageNotFoundError):
        artifacts = "unknown"
    versions = {
        "python": platform.python_version(),
        **pins,
        "artifacts": artifacts,
        "rules_sha256": rules_sha256,
        "target": target,
    }
    VERSIONS.parent.mkdir(parents=True, exist_ok=True)
    VERSIONS.write_text(json.dumps(versions, sort_keys=True) + "\n")
    print(VERSIONS.read_text())


if __name__ == "__main__":
    main()
