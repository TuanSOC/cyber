#!/usr/bin/env python3
"""Build the committed Enterprise ATT&CK index from a pinned attack-stix-data bundle.

Stdlib only. Run by a maintainer on the host (never in CI or a `backend` container, which have
no egress), then commit the output:

    python scripts/build_attack_index.py --version 20.0 --sha256 <hex>

It downloads the pinned bundle, aborts unless its sha256 matches, and writes
`apps/api/app/modules/attack/data/attack_enterprise_v<version>.json`. The same input always
gives byte-identical output. `--input` builds from an already downloaded bundle instead.

Since ATT&CK v19, Defense Evasion is split into "Stealth" and "Defense Impairment"; tactics are
taken from the bundle only (see app/modules/attack/build.py).

To bump: pick the newest Enterprise entry in
https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json, download it,
record its sha256 below, rebuild, delete the old index file and update `INDEX_VERSION` in
app/modules/attack/index.py.
"""

import argparse
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
API_ROOT = REPO_ROOT / "apps" / "api"
sys.path.insert(0, str(API_ROOT))

from app.modules.attack.build import BuildError, build_from_bytes, output_name  # noqa: E402

# Pinned: Enterprise ATT&CK v20.0 (collection modified 2026-10-13T17:53:10.145Z).
DEFAULT_VERSION = "20.0"
DEFAULT_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-{version}.json"
)
DEFAULT_SHA256 = "81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352"
OUTPUT_DIR = API_ROOT / "app" / "modules" / "attack" / "data"
MAX_BUNDLE_BYTES = 256 * 1024 * 1024
TIMEOUT_S = 120


def download(url: str) -> bytes:
    if not url.startswith("https://"):
        raise BuildError("source URL must be https")
    request = urllib.request.Request(url, headers={"User-Agent": "cyberlab-attack-index"})  # noqa: S310
    with urllib.request.urlopen(request, timeout=TIMEOUT_S) as response:  # noqa: S310
        data: bytes = response.read(MAX_BUNDLE_BYTES + 1)
    if len(data) > MAX_BUNDLE_BYTES:
        raise BuildError(f"bundle larger than {MAX_BUNDLE_BYTES} bytes")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", default=DEFAULT_VERSION, help="ATT&CK version, e.g. 20.0")
    parser.add_argument("--url", help="bundle URL (default: the attack-stix-data raw URL)")
    parser.add_argument("--sha256", default=DEFAULT_SHA256, help="expected bundle sha256")
    parser.add_argument("--input", type=Path, help="build from a local bundle file instead")
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    args = parser.parse_args(argv)

    url = args.url or DEFAULT_URL.format(version=args.version)
    try:
        name = output_name(args.version)
        data = args.input.read_bytes() if args.input else download(url)
        index = build_from_bytes(
            data, version=args.version, source_url=url, expected_sha256=args.sha256
        )
    except (BuildError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    args.output_dir.mkdir(parents=True, exist_ok=True)
    out = args.output_dir / name
    out.write_bytes(index)
    print(f"wrote {out} ({len(index)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
