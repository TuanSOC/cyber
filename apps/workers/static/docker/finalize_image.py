"""Build-time only: precompute the capa rule cache and write /etc/cyberlab/versions.json.

The runtime rootfs is read-only, so capa must find a ready cache: capa uses
$XDG_CACHE_HOME itself (not $XDG_CACHE_HOME/capa) as its cache directory on Linux,
and the image sets XDG_CACHE_HOME=/opt/capa/cache. The cache file name is derived from
the capa version and the sha256 of every rule file, so it only hits for exactly the
rules baked under /opt/capa/rules and the installed capa.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

CAPA_ROOT = Path("/opt/capa")
CLAMAV_DB = Path("/var/lib/clamav")


def build_capa_cache() -> None:
    import capa.rules.cache

    cache_dir = Path(os.environ["XDG_CACHE_HOME"])
    if not capa.rules.cache.generate_rule_cache(CAPA_ROOT / "rules", cache_dir):
        raise SystemExit("capa rule cache generation failed")
    for path in cache_dir.iterdir():
        path.chmod(0o444)
    cache_dir.chmod(0o555)


def cvd_header(path: Path) -> list[str]:
    # CVD/CLD header: 512 bytes "ClamAV-VDB:<build time>:<version>:<sigs>:<flevel>:<md5>:<dsig>:<builder>:<stime>"
    with path.open("rb") as fh:
        return fh.read(512).decode("ascii", "replace").rstrip("\x00 ").split(":")


def clamav_db_info() -> tuple[str, str | None]:
    for name in ("daily.cld", "daily.cvd"):
        path = CLAMAV_DB / name
        if path.is_file():
            header = cvd_header(path)
            if header[0] == "ClamAV-VDB" and len(header) >= 9:
                stime = datetime.fromtimestamp(int(header[8]), tz=UTC)
                return header[2], stime.isoformat().replace("+00:00", "Z")
    return "unavailable", None


def clamav_version() -> str:
    out = subprocess.run(  # noqa: S603 (fixed argv)
        ["/usr/bin/clamscan", "--version"], check=True, capture_output=True, text=True
    ).stdout
    # "ClamAV 1.4.3" or "ClamAV 1.4.3/27800/<date>" when a DB is present
    return out.split()[1].split("/")[0]


def main() -> None:
    import yara

    build_capa_cache()
    db_version, db_date = clamav_db_info()
    versions = {
        "python": platform.python_version(),
        "pefile": version("pefile"),
        "pyelftools": version("pyelftools"),
        # yara-python bundles libyara of the same version (no yara CLI in the image)
        "yara": yara.__version__,
        "capa": version("flare-capa"),
        "capa_rules": (CAPA_ROOT / "rules.version").read_text().strip(),
        "floss": version("flare-floss"),
        "clamav": clamav_version(),
        "clamav_db": db_version,
        "clamav_db_date": db_date,
        "ppdeep": version("ppdeep"),
    }
    out = Path("/etc/cyberlab/versions.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(versions, sort_keys=True) + "\n")
    print(out.read_text())


if __name__ == "__main__":
    main()
