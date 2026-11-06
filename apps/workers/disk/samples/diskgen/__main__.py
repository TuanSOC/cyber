"""`python -m samples.diskgen --out DIR [--only ID,...] [--hostile N --seed S]` (`pnpm disk:gen`).

Writes `<DIR>/<id>/` per image (segments + `ground_truth.json`) and, with `--hostile`,
`<DIR>/hostile/<nn>_<mutation>/` (segments + `mutation.json`), then `<DIR>/index.json`. An id
whose tools are missing fails the run unless `--skip-missing` is given (then it is listed as
skipped in the index, never faked). Output belongs in a temp / tmpfs directory: never commit it.
"""

import argparse
import json
import sys
import time
from pathlib import Path

from samples.diskgen import NOTE, images, mutate, tools

DEFAULT_OUT = "/work/diskgen"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m samples.diskgen")
    parser.add_argument("--out", default=DEFAULT_OUT, help=f"output directory ({DEFAULT_OUT})")
    parser.add_argument("--only", default="", help="comma-separated image ids (default: all)")
    parser.add_argument("--hostile", type=int, default=0, metavar="N", help="hostile cases")
    parser.add_argument("--seed", type=int, default=0, help="hostile mode seed")
    parser.add_argument("--ntfs-route", choices=images.NTFS_ROUTES, default="auto")
    parser.add_argument("--skip-missing", action="store_true", help="skip ids missing a tool")
    parser.add_argument("--list", action="store_true", help="print the image ids and exit")
    args = parser.parse_args(argv)

    if args.list:
        for image_id in images.BUILDERS:
            needs = images.NEEDS.get(image_id, ())
            print(f"{image_id}\t{' '.join(needs) or '(pure Python)'}")
        return 0
    wanted = [i for i in args.only.split(",") if i] or list(images.BUILDERS)
    unknown = [i for i in wanted if i not in images.BUILDERS]
    if unknown:
        parser.error(f"unknown image ids: {', '.join(unknown)}")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    gen = images.Generator(out, args.ntfs_route)
    started = time.monotonic()
    built: dict[str, str] = {}
    skipped: dict[str, str] = {}
    for image_id in wanted:
        try:
            b = gen.build(image_id)
        except tools.ToolMissing as exc:
            if not args.skip_missing:
                print(f"{image_id}: {exc}", file=sys.stderr)
                return 1
            skipped[image_id] = str(exc)
            continue
        built[image_id] = b.truth.get("determinism", "byte_exact")
        print(f"{image_id}: {', '.join(p.name for p in b.segments)}")
    hostile_done: list[str] = []
    hostile_skipped: list[str] = []
    if args.hostile:
        cases, hostile_skipped = mutate.hostile(gen, args.hostile, args.seed)
        hostile_done = [c.directory.name for c in cases]
        for line in hostile_skipped:
            if not args.skip_missing:
                print(f"hostile {line}", file=sys.stderr)
                return 1
        print(f"hostile: {len(hostile_done)} cases, {len(hostile_skipped)} skipped")
    index = {
        "note": NOTE,
        "images": built,
        "skipped": skipped,
        "hostile": hostile_done,
        "hostile_skipped": hostile_skipped,
        "seconds": round(time.monotonic() - started, 1),
    }
    (out / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    print(f"{len(built)} images in {index['seconds']} s -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
