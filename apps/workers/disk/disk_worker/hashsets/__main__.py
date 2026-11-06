"""`python -I -m disk_worker.hashsets <command> ...`: the trusted `disk-hashsets` tool (M9 phase 5).

Commands:
- `import-nsrl --file /import/<f> --name <n> [--kind known_good]` (NSRL RDSv3 SQLite);
- `import-list --file /import/<f> --name <n> --kind known_good|known_bad|notable
  --algo sha256|sha1|md5` (one digest per line, md5sum-style suffixes, `#` comments);
- `list`; `verify` (re-hash every file against the manifest; exit 1 on a mismatch);
  `remove --name <n>` (manifest first, then files).

Offline only: the compose service has `network_mode: none` and the import children run under
the kit's seccomp network filter; nothing is ever downloaded. The store is
`$DISK_HASHSETS_DIR` (`/hashsets`), the import dir `$DISK_HASHSETS_IMPORT_DIR` (`/import`,
mounted read-only). Exit codes: 0 done, 1 refused / mismatch, 2 usage.
"""

import argparse
import os
import sys
from pathlib import Path
from typing import NoReturn

from disk_worker.hashsets import manifest as mf
from disk_worker.hashsets.importer import (
    ImportRefused,
    import_set,
    remove_set,
    verify_store,
)

COMMANDS = ("import-nsrl", "import-list", "list", "verify", "remove")
KINDS = ("known_good", "known_bad", "notable")
ALGOS = ("sha256", "sha1", "md5")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        print(f"disk-hashsets: {message}", file=sys.stderr)
        raise SystemExit(2)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="disk-hashsets", description="Offline known-file hash-set store.")
    sub = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    nsrl = sub.add_parser("import-nsrl", help="import an NSRL RDSv3 SQLite database")
    nsrl.add_argument("--file", required=True)
    nsrl.add_argument("--name", required=True)
    nsrl.add_argument("--kind", choices=KINDS, default="known_good")
    lst = sub.add_parser("import-list", help="import a plain hash list")
    lst.add_argument("--file", required=True)
    lst.add_argument("--name", required=True)
    lst.add_argument("--kind", choices=KINDS, required=True)
    lst.add_argument("--algo", choices=ALGOS, required=True)
    sub.add_parser("list", help="list the sets")
    sub.add_parser("verify", help="re-hash every set file against the manifest")
    rm = sub.add_parser("remove", help="remove a set")
    rm.add_argument("--name", required=True)
    return parser


def _list(root: Path) -> int:
    try:
        manifest = mf.load(root)
    except mf.ManifestInvalid as exc:
        print(f"disk-hashsets: invalid manifest: {exc}", file=sys.stderr)
        return 1
    for s in manifest.sets:
        counts = ",".join(f"{f.algo}={f.count}" for f in s.files)
        print(f"{s.name}\t{s.kind}\t{counts}\t{s.imported_at.isoformat()}")
    if not manifest.sets:
        print("(no hash sets)")
    return 0


def main(argv: list[str], env: dict[str, str] | None = None) -> int:
    env = dict(os.environ) if env is None else env
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:  # usage errors and --help
        return exc.code if isinstance(exc.code, int) else 2
    root = Path(env.get("DISK_HASHSETS_DIR", "/hashsets"))
    import_dir = Path(env.get("DISK_HASHSETS_IMPORT_DIR", "/import"))
    # The fork isolates every parse; only the host unit tests (no fork) run in-process.
    isolate = hasattr(os, "fork") and env.get("DISK_HASHSETS_IN_PROCESS") != "1"
    try:
        if args.command in ("import-nsrl", "import-list"):
            hash_set, stats = import_set(
                root,
                import_dir,
                args.file,
                args.name,
                args.kind,
                "nsrl" if args.command == "import-nsrl" else "list",
                getattr(args, "algo", None),
                isolate=isolate,
            )
            counts = ", ".join(f"{a} {c}" for a, c in stats.counts.items())
            print(
                f"imported {hash_set.name} ({hash_set.kind}): {counts}; rows {stats.rows}, "
                f"invalid {stats.invalid}, missing {stats.missing}"
            )
            return 0
        if args.command == "remove":
            remove_set(root, args.name)
            print(f"removed {args.name}")
            return 0
        if args.command == "verify":
            problems = verify_store(root)
            for problem in problems:
                print(f"MISMATCH {problem}")
            print("verify: ok" if not problems else f"verify: {len(problems)} problem(s)")
            return 1 if problems else 0
        return _list(root)
    except ImportRefused as exc:
        print(f"disk-hashsets: refused: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
