"""`/opt/plaso/bin/python -I -m cyberlab_plaso_export <storage> <out.jsonl>` (M9 phase 1
placeholder; phase 3 owns the body, RT11 / RT24).

The single-process event exporter used instead of `psort.py -o json_line` if the phase-3a spike
sees psort start a process or a zmq TCP queue under the filter: Plaso's storage reader plus its
`shared_json` serializer, the same JSONL shape, the same sandbox. Until then it refuses to run.
"""

import sys


def main(argv: list[str]) -> int:
    print("cyberlab_plaso_export: not implemented (M9 phase 3)", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
