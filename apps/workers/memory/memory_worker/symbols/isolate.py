"""Child-process parsing for the trusted `memory-symbols` tool (M8 phase 5, RT17).

Every parse or conversion of operator- or network-supplied bytes (JSON, `jsonschema`, xz,
zip, Volatility's `pdbconv`, Volatility's identifier indexer) runs in a fresh child
interpreter:

- `python -I` (no env, user site or cwd on `sys.path`), started from a fixed argv: the only
  inputs are paths the parent created and a params JSON file the parent wrote; no shell, no
  operator or image text is ever interpolated into a command;
- `RLIMIT_AS` 2 GiB, `RLIMIT_FSIZE`, no core dumps, a wall-clock timeout (the child is killed);
- a PEP 578 audit hook refuses sockets, subprocesses and `exec` inside the child;
- outputs land in the parent's temp dir only (`result.json` + produced files); the parent
  re-hashes and validates everything before an atomic move into the store.

This module is stdlib-only at import time (the child imports it first); `jsonschema` and
Volatility are imported inside the tasks that need them.
"""

from __future__ import annotations

import base64
import hashlib
import json
import lzma
import os
import re
import stat
import subprocess
import sys
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import IO, Any

RLIMIT_AS = 2 * 1024**3
RLIMIT_FSIZE = 1024**3  # no single file a child writes may exceed 1 GiB
MAX_ISF_BYTES = 256 * 1024**2  # decompressed, per ISF
MAX_ZIP_MEMBERS = 50_000
MAX_ZIP_TOTAL_BYTES = 4 * 1024**3  # decompressed, all members together
XZ_MEMLIMIT = 128 * 1024**2  # xz decoder memory (preset 9 needs ~65 MiB)
XZ_PRESET = 6
MAX_RESULT_BYTES = 64 * 1024**2
MAX_BANNER = 512

# The package parent dir (`apps/workers/memory` or `/srv/workers/memory`): put on the child's
# sys.path explicitly, since `-I` ignores PYTHONPATH and the cwd.
PKG_PARENT = Path(__file__).resolve().parents[2]
_BOOTSTRAP = (
    "import sys; sys.path.insert(0, sys.argv[1]); "
    "from memory_worker.symbols.isolate import child_main; "
    "raise SystemExit(child_main(sys.argv[2:]))"
)

MEMBER_RE = re.compile(r"^(windows|linux)/[A-Za-z0-9._/-]+\.json(\.xz)?$")
MEMBER_DIR_RE = re.compile(r"^(windows|linux)(/[A-Za-z0-9._-]+)*/$")
FORMAT_RE = re.compile(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")
_PRINTABLE = frozenset(chr(c) for c in range(0x20, 0x7F))
_XZ_MAGIC = b"\xfd7zXZ\x00"


class ChildFailed(RuntimeError):
    """The child refused the input, crashed, ran out of memory or timed out."""


class Refused(ValueError):
    """Raised inside the child: the input is invalid (the message is ASCII, bounded)."""


# --- shared helpers (pure, also used by the worker side) ------------------------------------


def normalize_banner(raw: bytes) -> str | None:
    """The `LinuxBanner.banner` form of a raw kernel banner, as the identify probe reads it
    (phase 2, `probe/vol.py::_banner_at`): cut at the first NUL, surrounding ASCII whitespace
    stripped (the kernel's `linux_banner` ends with a newline and a NUL), printable ASCII
    only, at most 512 characters. None when it cannot be a valid banner."""
    end = raw.find(b"\x00")
    text = (raw if end < 0 else raw[:end]).strip()
    try:
        banner = text.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not banner or len(banner) > MAX_BANNER or any(ch not in _PRINTABLE for ch in banner):
        return None
    return banner


def safe_text(value: object, limit: int = 200) -> str:
    """Attacker-influenced text made inert for a log line or an error (ASCII, escaped)."""
    return ascii(str(value)[:limit])


# --- parent side ------------------------------------------------------------------------------


def _limit_child(rlimit_as: int) -> None:  # pragma: no cover - forked child, POSIX only
    import resource

    resource.setrlimit(resource.RLIMIT_AS, (rlimit_as, rlimit_as))
    resource.setrlimit(resource.RLIMIT_FSIZE, (RLIMIT_FSIZE, RLIMIT_FSIZE))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _child_env(work: Path) -> dict[str, str]:
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/nonexistent",
        "XDG_CONFIG_HOME": "/nonexistent",
        "XDG_CACHE_HOME": str(work / ".child-cache"),
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if os.name == "nt":  # host test runs only: the interpreter needs these to start
        for key in ("SYSTEMROOT", "PATH", "TEMP", "TMP"):
            if key in os.environ:
                env[key] = os.environ[key]
    return env


def run_child(
    task: str,
    params: dict[str, Any],
    work: Path,
    *,
    timeout_s: float,
    rlimit_as: int = RLIMIT_AS,
) -> dict[str, Any]:
    """Run one child task over files in `work` (a parent-owned temp dir) and return its
    `result.json`. Raises `ChildFailed` on refusal, crash, OOM or timeout."""
    if task not in TASKS:
        raise ValueError(f"unknown child task {task!r}")
    work.mkdir(parents=True, exist_ok=True)
    token = os.urandom(6).hex()
    params_path = work / f"params-{token}.json"
    result_path = work / f"result-{token}.json"
    params_path.write_text(json.dumps(params))
    cmd = [sys.executable, "-I", "-c", _BOOTSTRAP, str(PKG_PARENT), task]
    cmd += [str(params_path), str(result_path)]
    limit = (lambda: _limit_child(rlimit_as)) if os.name == "posix" else None
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, parent-made paths only, no shell
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout_s,
            env=_child_env(work),
            cwd=str(work),
            close_fds=True,
            preexec_fn=limit,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ChildFailed(f"{task}: timed out after {timeout_s:.0f}s") from exc
    finally:
        params_path.unlink(missing_ok=True)
    try:
        if proc.returncode != 0:
            tail = proc.stderr.decode("ascii", "replace").strip().splitlines()[-1:]
            reason = "".join(c if c in _PRINTABLE else "?" for c in tail[0][:300]) if tail else ""
            reason = reason or f"exit {proc.returncode}"
            if proc.returncode < 0 or "MemoryError" in reason:
                reason = f"killed or out of memory ({reason})"
            raise ChildFailed(f"{task}: {reason}")
        size = result_path.stat().st_size
        if size > MAX_RESULT_BYTES:
            raise ChildFailed(f"{task}: result too large")
        result: dict[str, Any] = json.loads(result_path.read_bytes())
        return result
    except (OSError, ValueError) as exc:
        raise ChildFailed(f"{task}: no usable result ({type(exc).__name__})") from exc
    finally:
        result_path.unlink(missing_ok=True)


# --- child side -------------------------------------------------------------------------------


_DENIED_EVENTS = (
    "socket.",
    "subprocess.",
    "os.system",
    "os.exec",
    "os.posix_spawn",
    "os.spawn",
    "os.fork",
    "os.forkpty",
    "urllib.Request",
    "http.client.connect",
    "ftplib.",
    "smtplib.",
    "webbrowser.",
)


def _deny_hook(event: str, _args: tuple[object, ...]) -> None:
    if event.startswith(_DENIED_EVENTS):
        raise PermissionError(f"memory-symbols child: {event} is not allowed")


def _iter_chunks(fh: IO[bytes], size: int = 1024 * 1024) -> Iterator[bytes]:
    while chunk := fh.read(size):
        yield chunk


def xz_decompress(chunks: Iterator[bytes], cap: int) -> bytes:
    """Stream-decompress one xz stream with a decoder memory limit and an output cap."""
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=XZ_MEMLIMIT)
    out = bytearray()
    try:
        for chunk in chunks:
            data = chunk
            while not dec.eof:
                out += dec.decompress(data, max_length=cap + 1 - len(out))
                if len(out) > cap:
                    raise Refused(f"decompresses to more than {cap} bytes")
                data = b""
                if dec.needs_input:
                    break
            if dec.eof:
                if dec.unused_data or any(_iter_chunks_rest(chunks)):
                    raise Refused("data after the xz stream")
                break
    except lzma.LZMAError as exc:
        raise Refused(f"invalid xz data ({safe_text(exc, 80)})") from exc
    if not dec.eof:
        raise Refused("truncated xz stream")
    return bytes(out)


def _iter_chunks_rest(chunks: Iterator[bytes]) -> Iterator[bytes]:
    for chunk in chunks:
        if chunk:
            yield chunk


def _refuse_constant(name: str) -> None:
    raise Refused(f"non-finite number {name} in JSON")


def parse_isf(data: bytes) -> dict[str, Any]:
    try:
        doc = json.loads(data, parse_constant=_refuse_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Refused(f"not valid JSON ({type(exc).__name__})") from exc
    if not isinstance(doc, dict):
        raise Refused("an ISF is a JSON object")
    return doc


def load_schema(schema_dir: Path, doc: dict[str, Any]) -> dict[str, Any]:
    """Volatility's own rule (`volatility3/schemas/__init__.py`): the schema file is
    `schema-<metadata.format>.json`; the format is checked before it becomes a file name."""
    meta = doc.get("metadata")
    fmt = meta.get("format") if isinstance(meta, dict) else None
    if not isinstance(fmt, str) or not FORMAT_RE.fullmatch(fmt):
        raise Refused("missing or invalid metadata.format")
    path = schema_dir / f"schema-{fmt}.json"
    if not path.is_file():
        raise Refused(f"no Volatility schema for ISF format {fmt}")
    schema: dict[str, Any] = json.loads(path.read_text())
    return schema


def validate_isf(doc: dict[str, Any], schema_dir: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:  # never skip validation silently (research §7)
        raise Refused("jsonschema is not installed: refusing to import unvalidated ISF") from exc
    schema = load_schema(schema_dir, doc)
    validator_cls = jsonschema.validators.validator_for(schema)
    # The first error only: a hostile document may hold millions of them.
    error = next(iter(validator_cls(schema).iter_errors(doc)), None)
    if error is not None:
        where = "/".join(str(p) for p in list(error.absolute_path)[:8])
        raise Refused(f"ISF schema violation at {safe_text(where, 120)}")


def identity_of(doc: dict[str, Any]) -> dict[str, Any] | None:
    """The kernel identity in an ISF's metadata, as Volatility's identifiers read it:
    Windows `metadata.windows.pdb` {database, GUID, age}; Linux the base64
    `symbols.linux_banner.constant_data`. None when the ISF carries neither (e.g. a
    Volatility built-in type table). The parent validates it with the frozen models."""
    meta = doc.get("metadata")
    windows = meta.get("windows") if isinstance(meta, dict) else None
    pdb = windows.get("pdb") if isinstance(windows, dict) else None
    symbols = doc.get("symbols")
    lb = symbols.get("linux_banner") if isinstance(symbols, dict) else None
    constant = lb.get("constant_data") if isinstance(lb, dict) else None
    if pdb is not None and constant is not None:
        raise Refused("an ISF with both a Windows PDB and a Linux banner")
    if pdb is not None:
        if not isinstance(pdb, dict):
            raise Refused("metadata.windows.pdb is not an object")
        name, guid, age = pdb.get("database"), pdb.get("GUID"), pdb.get("age")
        if not isinstance(name, str) or not isinstance(guid, str):
            raise Refused("metadata.windows.pdb lacks database / GUID")
        if not isinstance(age, int) or isinstance(age, bool):
            raise Refused("metadata.windows.pdb.age is not an integer")
        return {"os": "windows", "name": name[:64], "guid": guid.upper()[:64], "age": age}
    if constant is not None:
        if not isinstance(constant, str) or len(constant) > 4 * MAX_BANNER:
            raise Refused("symbols.linux_banner.constant_data is not a short string")
        try:
            raw = base64.b64decode(constant, validate=True)
        except ValueError as exc:
            raise Refused("symbols.linux_banner.constant_data is not base64") from exc
        banner = normalize_banner(raw)
        if banner is None:
            raise Refused("the Linux banner is not printable ASCII of at most 512 characters")
        return {"os": "linux", "banner": banner}
    return None


def _write_xz(data: bytes, out: Path) -> str:
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as raw, lzma.open(raw, "wb", preset=XZ_PRESET) as fh:
        fh.write(data)
    digest = hashlib.sha256()
    with out.open("rb") as fh:
        for chunk in _iter_chunks(fh):
            digest.update(chunk)
    return digest.hexdigest()


def _isf_bytes(raw_chunks: Iterator[bytes], first: bytes, cap: int) -> bytes:
    """Plain JSON or xz (sniffed by magic), decompressed with the cap."""

    def chain() -> Iterator[bytes]:
        yield first
        yield from raw_chunks

    if first.startswith(_XZ_MAGIC):
        return xz_decompress(chain(), cap)
    out = bytearray()
    for chunk in chain():
        out += chunk
        if len(out) > cap:
            raise Refused(f"larger than {cap} bytes")
    return bytes(out)


def _process(data: bytes, schema_dir: Path, out: Path) -> dict[str, Any]:
    doc = parse_isf(data)
    validate_isf(doc, schema_dir)
    identity = identity_of(doc)
    del doc
    entry: dict[str, Any] = {"identity": identity}
    if identity is not None:
        entry["file"] = out.name
        entry["sha256"] = _write_xz(data, out)
    return entry


def task_isf(params: dict[str, Any]) -> dict[str, Any]:
    """One `.json` / `.json.xz` ISF -> validated, identified, re-compressed `out`."""
    src, out = Path(params["src"]), Path(params["out"])
    cap = int(params.get("max_bytes", MAX_ISF_BYTES))
    with src.open("rb") as fh:
        first = fh.read(64)
        data = _isf_bytes(_iter_chunks(fh), first, cap)
    return _process(data, Path(params["schema_dir"]), out)


def _member_problem(info: zipfile.ZipInfo) -> str | None:
    name = info.filename
    mode = info.external_attr >> 16
    kind = stat.S_IFMT(mode)
    if kind == stat.S_IFLNK:
        return "a symlink member"
    if info.flag_bits & 0x1:
        return "an encrypted member"
    if info.is_dir():
        if kind not in (0, stat.S_IFDIR) or not MEMBER_DIR_RE.fullmatch(name):
            return "an unexpected directory member"
        return None
    if kind not in (0, stat.S_IFREG):
        return "a member that is not a regular file"
    if not MEMBER_RE.fullmatch(name):
        return "a member name outside (windows|linux)/....json[.xz]"
    if name.startswith("/") or any(seg in ("", ".", "..") for seg in name.split("/")):
        return "a member path with an empty, . or .. segment"
    return None


def task_zip(params: dict[str, Any]) -> dict[str, Any]:
    """A local zip of ISFs: every member checked before any is parsed (traversal, symlinks,
    type, count, duplicate names), then each parsed and validated with per-member and total
    decompression caps. Produced files are `out_dir/<index>.json.xz`."""
    src, out_dir = Path(params["src"]), Path(params["out_dir"])
    schema_dir = Path(params["schema_dir"])
    member_cap = int(params.get("max_member_bytes", MAX_ISF_BYTES))
    total_cap = int(params.get("max_total_bytes", MAX_ZIP_TOTAL_BYTES))
    max_members = int(params.get("max_members", MAX_ZIP_MEMBERS))
    members: list[dict[str, Any]] = []
    total = 0
    try:
        with zipfile.ZipFile(src) as zf:
            infos = zf.infolist()
            if len(infos) > max_members:
                raise Refused(f"more than {max_members} members")
            seen: set[str] = set()
            for info in infos:
                problem = _member_problem(info)
                if problem:
                    raise Refused(f"{problem}: {safe_text(info.filename, 120)}")
                if info.filename in seen:
                    raise Refused(f"duplicate member {safe_text(info.filename, 120)}")
                seen.add(info.filename)
            for index, info in enumerate(i for i in infos if not i.is_dir()):
                if info.file_size > member_cap:
                    raise Refused(f"member over {member_cap} bytes: {safe_text(info.filename)}")
                with zf.open(info) as fh:
                    first = fh.read(64)
                    try:
                        data = _isf_bytes(_iter_chunks(fh), first, member_cap)
                    except Refused as exc:
                        raise Refused(f"{safe_text(info.filename)}: {exc}") from exc
                total += len(data)
                if total > total_cap:
                    raise Refused(f"members decompress to more than {total_cap} bytes in total")
                try:
                    entry = _process(data, schema_dir, out_dir / f"{index:05d}.json.xz")
                except Refused as exc:
                    raise Refused(f"{safe_text(info.filename)}: {exc}") from exc
                identity = entry["identity"]
                if identity is not None and identity["os"] != info.filename.split("/", 1)[0]:
                    raise Refused(f"{safe_text(info.filename)}: identity is not {identity['os']}")
                members.append({"name": info.filename, **entry})
    except zipfile.BadZipFile as exc:
        raise Refused(f"not a valid zip ({safe_text(exc, 80)})") from exc
    return {"members": members}


def _volatility_offline() -> Any:
    from volatility3.framework import constants

    constants.OFFLINE = True
    constants.REMOTE_ISF_URL = None
    return constants


def task_pdbconv(params: dict[str, Any]) -> dict[str, Any]:
    """Convert a downloaded PDB with Volatility's own `pdbconv` (`-f`, a local file only:
    never its `-p` downloader), then validate and identify the produced ISF."""
    import runpy

    pdb, out = Path(params["pdb"]), Path(params["out"])
    converted = out.parent / "pdbconv-output.json"
    _volatility_offline()
    argv = sys.argv
    sys.argv = ["pdbconv", "-f", str(pdb), "-o", str(converted)]
    try:
        runpy.run_module(
            "volatility3.framework.symbols.windows.pdbconv", run_name="__main__", alter_sys=True
        )
    except SystemExit as exc:
        if exc.code not in (0, None):
            raise Refused(f"pdbconv failed (exit {safe_text(exc.code, 20)})") from exc
    finally:
        sys.argv = argv
    if not converted.is_file():  # an output name of pdbconv's own choosing, in the work dir
        produced = [
            p
            for p in sorted(out.parent.glob("*.json*"))
            if p not in (out, pdb) and not p.name.startswith(("params-", "result-"))
        ]
        if len(produced) != 1:
            raise Refused("pdbconv produced no single ISF file")
        converted = produced[0]
    cap = int(params.get("max_bytes", MAX_ISF_BYTES))
    with converted.open("rb") as fh:
        first = fh.read(64)
        data = _isf_bytes(_iter_chunks(fh), first, cap)
    converted.unlink()
    return _process(data, Path(params["schema_dir"]), out)


def task_reindex(params: dict[str, Any]) -> dict[str, Any]:
    """Build Volatility's identifier cache for `root` only, offline, into `cache`."""
    root, cache = str(params["root"]), str(params["cache"])
    constants = _volatility_offline()
    constants.SYMBOL_BASEPATHS = [root]
    constants.CACHE_PATH = str(Path(cache).parent)
    import volatility3.symbols
    from volatility3.framework.automagic import symbol_cache

    volatility3.symbols.__path__ = [root]
    symbol_cache.SqliteCache(cache).update()
    return {"cache": cache}


TASKS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "isf": task_isf,
    "zip": task_zip,
    "pdbconv": task_pdbconv,
    "reindex": task_reindex,
}


def child_main(argv: list[str]) -> int:
    """Entry point inside the child: `<task> <params.json> <result.json>`."""
    task, params_path, result_path = argv
    params = json.loads(Path(params_path).read_text())
    sys.addaudithook(_deny_hook)
    try:
        result = TASKS[task](params)
    except Refused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 3
    Path(result_path).write_text(json.dumps(result))
    return 0

