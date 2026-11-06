"""`python -m samples.memgen`: write one synthetic image (and optionally its ISF).

python -m samples.memgen --scenario linux_benign --format raw --out /work/benign.raw
python -m samples.memgen --isf-out /work/cyberlab-synthetic-6.1.0.json.xz
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from samples.memgen import FORMATS, SCENARIOS, image_bytes, isf_xz, scenario
from samples.memgen.kernel import windows_identity_isf_xz


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="memgen")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="linux_benign")
    parser.add_argument("--format", choices=FORMATS, default="raw")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--isf-out", type=Path, help="write the ISF matching the image banner")
    parser.add_argument(
        "--windows-isf-out",
        type=Path,
        help="write the identity-only ISF of the replay fixtures' Windows kernel PDB",
    )
    args = parser.parse_args(argv)
    if args.out is None and args.isf_out is None and args.windows_isf_out is None:
        parser.error("nothing to write: give --out, --isf-out and/or --windows-isf-out")
    if args.out is not None:
        data = image_bytes(args.scenario, args.format)
        args.out.write_bytes(data)
        print(f"{args.out}: {args.scenario} {args.format} {len(data)} bytes")
    if args.isf_out is not None:
        args.isf_out.write_bytes(isf_xz(scenario(args.scenario).banner))
        print(f"{args.isf_out}: ISF for {args.scenario}")
    if args.windows_isf_out is not None:
        args.windows_isf_out.write_bytes(windows_identity_isf_xz())
        print(f"{args.windows_isf_out}: identity-only ISF of the replay Windows fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
