"""Probe command line (tool uid only).

The analyzer starts every probe with cwd = the root-owned, read-only input dir
(`run_tool(cwd=...)`), so nothing resolved relative to the cwd (by us or a library) can be a
file another tool planted; `-I` already keeps the cwd off sys.path. Paths are absolute.
"""

import argparse
from pathlib import Path

MODES = ["archive", "facts", "pe", "elf", "strings", "yara", "capa", "floss"]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="static_worker.probe")
    parser.add_argument("mode", choices=MODES)
    # The sample; for `capa` / `floss` the tool's JSON document to reduce.
    parser.add_argument("sample", type=Path)
    parser.add_argument("--max-sections", type=int, default=1000)
    parser.add_argument("--max-imports", type=int, default=10_000)
    parser.add_argument("--max-exports", type=int, default=10_000)
    parser.add_argument("--max-resources", type=int, default=10_000)
    parser.add_argument("--max-strings", type=int, default=10_000)
    parser.add_argument("--min-length", type=int, default=6)
    parser.add_argument("--max-matches", type=int, default=1000)
    parser.add_argument("--max-records", type=int, default=1000)
    parser.add_argument("--ssdeep-max-bytes", type=int, default=64 * 1024**2)
    parser.add_argument("--rules", type=Path, action="append", default=[])
    parser.add_argument("--timeout", type=int, default=60)
    return parser


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    sample: Path = args.sample
    if args.mode == "archive":
        from static_worker.probe import archive

        archive.run(sample)
    elif args.mode == "facts":
        from static_worker.probe import facts

        facts.run(sample, ssdeep_max_bytes=args.ssdeep_max_bytes)
    elif args.mode == "pe":
        from static_worker.probe import pe

        pe.run(
            sample,
            max_sections=args.max_sections,
            max_imports=args.max_imports,
            max_exports=args.max_exports,
            max_resources=args.max_resources,
        )
    elif args.mode == "elf":
        from static_worker.probe import elf

        elf.run(
            sample,
            max_sections=args.max_sections,
            max_imports=args.max_imports,
            max_exports=args.max_exports,
        )
    elif args.mode == "strings":
        from static_worker.probe import strings

        strings.run(sample, max_strings=args.max_strings, min_length=args.min_length)
    elif args.mode == "yara":
        from static_worker.probe import yarascan

        yarascan.run(sample, args.rules, timeout=args.timeout, max_matches=args.max_matches)
    else:
        from static_worker.probe import reduce

        reduce.run(args.mode, sample, max_records=args.max_records)
    return 0
