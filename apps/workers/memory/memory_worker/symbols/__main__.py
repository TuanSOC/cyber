"""`python -I -m memory_worker.symbols <command>`: the trusted operator tool `memory-symbols`
(M8 phase 5). Run through `pnpm memory:symbols -- [--store test] <command>`; compose runs it as
uid 10005 on its own `symbols_egress` network only, `mem_limit 2g`, read-only rootfs, the
target store always mounted at `/symbols` (RT5, RT17).

Commands (frozen names):
- `fetch-windows --pdb <kernel pdb> --guid <32 hex> --age <n> [--replace] [--no-reindex]`
  (operator only; never run by a test, gate or worker);
- `import --file <path in /import> [--sha256 <hex>] [--replace] [--no-reindex]`;
- `reindex`, `verify` (exit 1 on any mismatch), `list` (JSON lines, no file contents).

Exit codes: 0 done, 1 refused / failed / mismatch, 2 invalid usage or input. Every run logs its
command, the URLs it fetched and the manifest changes as JSON lines on stderr. No output ever
suggests a command containing a Linux banner (attacker-chosen text, RT12): identities are
printed as JSON values only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, NoReturn

from cyberlab_jobs.memory import WindowsPdb
from pydantic import ValidationError

from memory_worker.symbols import fetch_windows as fetch_mod
from memory_worker.symbols import import_isf, reindex
from memory_worker.symbols.isolate import safe_text
from memory_worker.symbols.manifest import (
    MANIFEST,
    TOOL_VERSION,
    ManifestInvalid,
    StoreError,
    iter_store_files,
    read_manifest,
    sha256_file,
)

COMMANDS = ("fetch-windows", "import", "reindex", "verify", "list")
_AGE_RE = re.compile(r"^[0-9]{1,5}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class UsageError(Exception):
    pass


def log(event: str, **fields: Any) -> None:
    """One JSON line on stderr (ASCII-escaped: no terminal control from any value)."""
    record = {"tool": "memory-symbols", "event": event, **fields}
    print(json.dumps(record, ensure_ascii=True, default=str), file=sys.stderr, flush=True)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # argparse would echo the offending value; values here may come from a hostile image.
        raise UsageError(message.split(":", 1)[0][:120])


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="memory-symbols", add_help=True)
    sub = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    fetch = sub.add_parser("fetch-windows", help="fetch one Windows kernel PDB (operator only)")
    fetch.add_argument("--pdb", required=True)
    fetch.add_argument("--guid", required=True)
    fetch.add_argument("--age", required=True)
    fetch.add_argument("--replace", action="store_true")
    fetch.add_argument("--no-reindex", action="store_true")
    imp = sub.add_parser("import", help="import an ISF or a local zip of ISFs from /import")
    imp.add_argument("--file", required=True)
    imp.add_argument("--sha256")
    imp.add_argument("--replace", action="store_true")
    imp.add_argument("--no-reindex", action="store_true")
    sub.add_parser("reindex", help="rebuild the identifier cache (store at /symbols only)")
    sub.add_parser("verify", help="re-hash every file against the manifest")
    sub.add_parser("list", help="identities, sources and import dates")
    return parser


def store_root() -> Path:
    return Path(os.environ.get("MEMORY_SYMBOLS_DIR", "/symbols"))


def import_root() -> Path:
    return import_isf.IMPORT_ROOT


def parse_pdb(name: str, guid: str, age: str) -> WindowsPdb:
    """The frozen model, nothing else: no normalization of what the image claimed."""
    if not _AGE_RE.fullmatch(age):
        raise UsageError("--age must be a decimal integer 0..65535")
    try:
        return WindowsPdb(name=name, guid=guid, age=int(age))
    except ValidationError as exc:
        fields = sorted({str(err["loc"][0]) for err in exc.errors() if err["loc"]})
        raise UsageError(
            "invalid Windows kernel PDB identity ("
            + ", ".join(fields)
            + "): the name must be a kernel PDB, the GUID 32 upper-case hex"
        ) from exc


def _reindex_after(no_reindex: bool) -> int:
    if no_reindex:
        log("reindex_skipped", reason="--no-reindex: run `reindex` before the worker uses it")
        return 0
    try:
        reindex.reindex(store_root(), log=log)
    except reindex.ReindexRefused as exc:
        log("error", command="reindex", message=str(exc))
        log("note", message="the manifest changes are committed; run `reindex` again")
        return 1
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    pdb = parse_pdb(args.pdb, args.guid, args.age)
    log("command", command="fetch-windows", pdb=pdb.model_dump(), replace=args.replace)
    try:
        change = fetch_mod.fetch_windows(store_root(), pdb, replace=args.replace, log=log)
    except fetch_mod.FetchRefused as exc:
        log("refused", message=str(exc), host=exc.host)
        return 1
    except (fetch_mod.FetchFailed, import_isf.ImportRefused) as exc:
        log("error", message=str(exc))
        return 1
    if change.action == "unchanged":
        return 0
    return _reindex_after(args.no_reindex)


def cmd_import(args: argparse.Namespace) -> int:
    if args.sha256 is not None and not _SHA_RE.fullmatch(args.sha256):
        raise UsageError("--sha256 must be 64 lower-case hex characters")
    log("command", command="import", file=safe_text(args.file, 255), replace=args.replace)
    try:
        path = import_isf.resolve_import_file(args.file, import_root())
        result = import_isf.import_file(
            store_root(), path, sha256=args.sha256, replace=args.replace, log=log
        )
    except import_isf.ImportRefused as exc:
        log("refused", message=str(exc))
        return 1
    changed = [c for c in result.changes if c.action != "unchanged"]
    log(
        "imported",
        source=result.source,
        changed=len(changed),
        unchanged=len(result.changes) - len(changed),
        skipped=len(result.skipped),
    )
    if not changed:
        return 0
    return _reindex_after(args.no_reindex)


def cmd_reindex(_args: argparse.Namespace) -> int:
    log("command", command="reindex")
    return _reindex_after(False)


def cmd_verify(_args: argparse.Namespace) -> int:
    root = store_root()
    log("command", command="verify")
    try:
        manifest = read_manifest(root)
    except ManifestInvalid as exc:
        log("mismatch", message=str(exc))
        return 1
    problems = 0
    listed: set[str] = set()
    for entry in manifest.files:
        listed.add(entry.path)
        try:
            ok = sha256_file(root / entry.path) == entry.sha256
            reason = "sha256 differs"
        except FileNotFoundError:
            ok, reason = False, "missing"
        except Exception as exc:  # noqa: BLE001 - any unreadable file is a mismatch
            ok, reason = False, type(exc).__name__
        if not ok:
            problems += 1
            log("mismatch", path=entry.path, reason=reason)
    for rel in iter_store_files(root):
        if rel not in listed:
            problems += 1
            log("mismatch", path=safe_text(rel, 255), reason="not in the manifest")
    cache = root / ".cache/volatility3/identifier.cache"
    if not cache.is_file():
        log("warning", message="no identifier cache: run `reindex`")
    elif manifest.identifier_cache_sha256 is None:
        log("warning", message="the manifest records no cache hash (not seeded): run `reindex`")
    else:
        try:
            cache_ok = sha256_file(cache) == manifest.identifier_cache_sha256
        except Exception:  # noqa: BLE001 - an unreadable cache is a mismatch
            cache_ok = False
        if not cache_ok:
            problems += 1
            log("mismatch", path=".cache/volatility3/identifier.cache", reason="sha256 differs")
    log("verified", files=len(manifest.files), mismatches=problems)
    return 1 if problems else 0


def cmd_list(_args: argparse.Namespace) -> int:
    root = store_root()
    if not os.path.lexists(root / MANIFEST):
        # A store nothing has written to yet (a fresh volume): empty, not an error. Anything
        # at the manifest path (a symlink, a broken file) still goes through read_manifest.
        log("listed", files=0, volatility_version=None, empty=True)
        return 0
    try:
        manifest = read_manifest(root)
    except ManifestInvalid as exc:
        log("error", message=str(exc))
        return 1
    for entry in manifest.files:
        line = {
            "os": entry.os,
            "identity": entry.identity.model_dump(),
            "source": entry.source,
            "imported_at": entry.imported_at,
            "path": entry.path,
        }
        print(json.dumps(line, ensure_ascii=True, default=str))
    log("listed", files=len(manifest.files), volatility_version=manifest.volatility_version)
    return 0


HANDLERS = {
    "fetch-windows": cmd_fetch,
    "import": cmd_import,
    "reindex": cmd_reindex,
    "verify": cmd_verify,
    "list": cmd_list,
}


def main(argv: Sequence[str]) -> int:
    try:
        args = _parser().parse_args(list(argv))
        return HANDLERS[args.command](args)
    except UsageError as exc:
        print(f"memory-symbols: {exc}", file=sys.stderr)
        print(f"usage: memory-symbols {{{','.join(COMMANDS)}}} ...", file=sys.stderr)
        return 2
    except (StoreError, ManifestInvalid) as exc:
        log("error", message=str(exc))
        return 1
    except SystemExit as exc:  # --help
        return int(exc.code or 0)


if __name__ == "__main__":
    log("start", version=TOOL_VERSION)
    raise SystemExit(main(sys.argv[1:]))
