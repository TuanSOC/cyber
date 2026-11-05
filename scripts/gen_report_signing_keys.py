#!/usr/bin/env python3
"""Generate a report signing key pair (Ed25519) for the API (M6).

The private half goes to a JSON file only the api service mounts (a compose secret); the
public half goes to `.env`, is published at `GET /api/v1/report-signing-keys` and is listed in
docs/DEPLOYMENT.md, so a recipient can verify a report offline (scripts/verify_report.py).
Needs `cryptography`, so run it with the api image from the repo root:

  docker run --rm -v "$PWD:/repo" -w /repo cyberlab/api:dev python scripts/gen_report_signing_keys.py

Options:
  --kid KID      key id (default prod-report-YYYYMMDD); `dev-` ids are refused in prod
  --out PATH     private key file (default .secrets/report_signing_private.json)
  --add          add the kid to an existing file instead of refusing to overwrite it
                 (rotation: keep the old public key published while old reports circulate)

The file is written with mode 0400. Compose (non-swarm) secrets are bind mounts that keep
the file's owner and mode, so it must belong to the prod image user (uid 10001): run as root
(the docker invocation above) the script chowns it; otherwise it prints the chown command.
"""

import argparse
import base64
import datetime as dt
import json
import os
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

KID = re.compile(r"[A-Za-z0-9._-]{1,64}")
IMAGE_UID = 10001  # the `cyberlab` user of the api image


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--kid", default=f"prod-report-{dt.datetime.now(dt.UTC):%Y%m%d}")
    parser.add_argument("--out", default=".secrets/report_signing_private.json")
    parser.add_argument("--add", action="store_true")
    args = parser.parse_args()

    if not KID.fullmatch(args.kid):
        parser.error("--kid must match [A-Za-z0-9._-]{1,64}")
    out = Path(args.out)
    existing: dict[str, str] = {}
    if out.exists():
        if not args.add:
            parser.error(f"{out} exists: pass --add to add a key for rotation")
        existing = json.loads(out.read_text(encoding="utf-8"))
        if args.kid in existing:
            parser.error(f"kid {args.kid!r} already exists in {out}")

    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    raw_public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    keys = {**existing, args.kid: base64.b64encode(raw_private).decode()}

    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.chmod(0o600)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(keys, handle, indent=2)
        handle.write("\n")
    out.chmod(0o400)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(out, IMAGE_UID, IMAGE_UID)
        print(f"Wrote {out} (mode 0400, owner {IMAGE_UID}).")
    else:
        print(f"Wrote {out} (mode 0400). For the prod image user: chown 10001:10001 {out}")

    public = json.dumps({args.kid: base64.b64encode(raw_public).decode()}, separators=(",", ":"))
    print("Add to .env (merge the public key JSON with every key that signed reports still in use):")
    print(f"REPORT_PROD_SIGNING_ACTIVE_KID={args.kid}")
    print(f"REPORT_PROD_SIGNING_PUBLIC_KEYS='{public}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
