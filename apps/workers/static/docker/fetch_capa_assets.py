"""Build-time only: fetch the capa rules and FLIRT signatures, verifying pinned sha256 digests.

Runs in the `capa-assets` build stage (network available); the analysis network has no egress.
Any digest mismatch fails the build.
"""

from __future__ import annotations

import hashlib
import io
import shutil
import sys
import tarfile
import urllib.request
from pathlib import Path

CAPA_TAG = "v10.0.0"

# capa-rules release tarball (GitHub source archive). sha256 computed once on 2026-11-04.
# Licence: Apache-2.0 (https://github.com/mandiant/capa-rules).
RULES_URL = f"https://github.com/mandiant/capa-rules/archive/refs/tags/{CAPA_TAG}.tar.gz"
RULES_SHA256 = "3d14dbdaf5b71731e42395ed5fa4d287418e6a2e5d6b0a348c7fd9fbe1699611"

# FLIRT signatures from the capa repository `sigs/` at the same tag (raw files are
# content-addressed by digest, unlike the 20 MB source archive). Licence: Apache-2.0.
SIGS_BASE = f"https://raw.githubusercontent.com/mandiant/capa/{CAPA_TAG}/sigs/"
SIGS_SHA256 = {
    "1_flare_msvc_rtf_32_64.sig": "e0042918fa80d432a1914680816996ac397afc30b05d3161192f29de63e66e79",
    "2_flare_msvc_atlmfc_32_64.sig": "c6f6084f1553f3a4a515bcefe7a72fe2b3564c8338c01fa9add1166276bf09f1",
    "3_flare_common_libs.sig": "6fa7dda3ffb523d2f555348db47c67b9820a40153bfacd543c9ea02a1ecd83a8",
}

DEST = Path("/opt/capa")


def fetch(url: str, sha256: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310 (fixed https URLs)
        data: bytes = resp.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != sha256:
        sys.exit(f"sha256 mismatch for {url}: got {digest}, pinned {sha256}")
    return data


def main() -> None:
    rules_dir = DEST / "rules"
    sigs_dir = DEST / "sigs"
    rules_dir.mkdir(parents=True)
    sigs_dir.mkdir(parents=True)

    with tarfile.open(fileobj=io.BytesIO(fetch(RULES_URL, RULES_SHA256)), mode="r:gz") as tar:
        tar.extractall(DEST / "_src", filter="data")
    (src,) = (DEST / "_src").iterdir()
    for entry in src.iterdir():
        if entry.name.startswith("."):
            continue  # .github etc. are not rules
        shutil.move(str(entry), rules_dir / entry.name)
    shutil.rmtree(DEST / "_src")

    for name, digest in SIGS_SHA256.items():
        (sigs_dir / name).write_bytes(fetch(SIGS_BASE + name, digest))

    (DEST / "rules.version").write_text(CAPA_TAG + "\n")
    count = sum(1 for _ in rules_dir.rglob("*.yml"))
    print(f"capa rules {CAPA_TAG}: {count} rule files; {len(SIGS_SHA256)} FLIRT sigs")


if __name__ == "__main__":
    main()
