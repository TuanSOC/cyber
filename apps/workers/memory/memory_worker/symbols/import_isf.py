"""`memory-symbols import --file <path>`: operator-supplied ISFs into the store (M8 phase 5).

Input is a file in the operator import dir (`/import`, mounted read-only): a single `.json` /
`.json.xz` ISF (e.g. dwarf2json >= 0.9.0 output for a Linux kernel, or a Windows ISF converted
elsewhere; `source: operator`) or a local `.zip` of ISFs such as a downloaded symbol pack
(`source: zip:<sha256>`, an optional `--sha256` pin checked before anything is opened). The
URL-based `import-pack` is cut (RT22): this tool never downloads a pack.

Parsing, decompression and `jsonschema` validation (Volatility's own schemas) run in a child
process (`isolate.py`); the identity comes from the ISF metadata and is validated with the
frozen models; the produced `.json.xz` goes through the store writer's verified atomic move.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cyberlab_jobs.memory import KERNEL_PDB_NAMES, KernelIdentity, LinuxBanner, WindowsPdb
from pydantic import ValidationError

from memory_worker.symbols import isolate
from memory_worker.symbols.manifest import Change, Logger, StoreError, StoreWriter, no_log

IMPORT_ROOT = Path("/import")
MAX_INPUT_BYTES = 8 * 1024**3  # a zip pack on disk (members are capped separately)
ISF_TIMEOUT_S = 900.0
ZIP_TIMEOUT_S = 6 * 3600.0
ISF_SUFFIXES = (".json", ".json.xz")


class ImportRefused(ValueError):
    pass


@dataclass
class ImportResult:
    source: str
    changes: list[Change] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)


def volatility_schema_dir() -> Path:
    """`volatility3/schemas/` of the installed Volatility (found without importing it)."""
    spec = importlib.util.find_spec("volatility3")
    if spec is None or not spec.submodule_search_locations:
        raise ImportRefused("volatility3 is not installed: no ISF schema to validate against")
    path = Path(next(iter(spec.submodule_search_locations))) / "schemas"
    if not any(path.glob("schema-*.json")):
        raise ImportRefused("the installed volatility3 ships no ISF schemas")
    return path


def resolve_import_file(name: str, import_root: Path = IMPORT_ROOT) -> Path:
    """A regular file inside the import dir (after resolving symlinks), nothing else."""
    root = Path(os.path.realpath(import_root))
    candidate = Path(name)
    if not candidate.is_absolute():
        candidate = root / candidate
    real = Path(os.path.realpath(candidate))
    if real == root or root not in real.parents:
        raise ImportRefused(f"--file must name a file inside {import_root}")
    try:
        info = os.stat(real)
    except OSError as exc:
        raise ImportRefused(f"--file: cannot open ({exc.strerror})") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ImportRefused("--file is not a regular file")
    if info.st_size > MAX_INPUT_BYTES:
        raise ImportRefused("--file is larger than 8 GiB")
    return real


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def to_identity(raw: dict[str, Any] | None) -> KernelIdentity | None:
    """The child's raw identity through the frozen models; None for a non-kernel ISF.
    Raises ValidationError for an identity that is malformed (not merely non-kernel)."""
    if raw is None:
        return None
    if raw.get("os") == "linux":
        return LinuxBanner(banner=raw["banner"])
    name, guid, age = raw.get("name"), raw.get("guid"), raw.get("age")
    if name not in KERNEL_PDB_NAMES:
        # A well-formed PDB identity of something other than a kernel (a driver's PDB in a
        # pack): not for this store. A malformed GUID / age still refuses the input.
        WindowsPdb(name="ntkrnlmp.pdb", guid=guid, age=age)
        return None
    return WindowsPdb(name=name, guid=guid, age=age)


def import_file(
    root: Path,
    file: Path,
    *,
    sha256: str | None = None,
    replace: bool = False,
    schema_dir: Path | None = None,
    log: Logger = no_log,
) -> ImportResult:
    """Import one checked input file (`resolve_import_file`) into the store at `root`."""
    name = file.name.lower()
    is_zip = name.endswith(".zip")
    if not is_zip and not name.endswith(ISF_SUFFIXES):
        raise ImportRefused("--file must be a .json, .json.xz or .zip file")
    digest = file_sha256(file)
    if sha256 is not None and digest != sha256:
        raise ImportRefused("--sha256 does not match the file")
    schemas = schema_dir or volatility_schema_dir()
    source = f"zip:{digest}" if is_zip else "operator"
    result = ImportResult(source=source)
    log("import_input", file=file.name, sha256=digest, kind="zip" if is_zip else "isf")
    # The child works in a temp dir outside the store (review fix); `adopt` copies what it
    # produced into the store's staging dir, `stage` re-hashes it.
    with (
        StoreWriter(root, log=log) as writer,
        tempfile.TemporaryDirectory(prefix="memory-symbols-") as tmp,
    ):
        work = Path(tmp)
        try:
            if is_zip:
                out = isolate.run_child(
                    "zip",
                    {"src": str(file), "out_dir": str(work), "schema_dir": str(schemas)},
                    work,
                    timeout_s=ZIP_TIMEOUT_S,
                )
                members = out["members"]
            else:
                produced = work / "isf.json.xz"
                out = isolate.run_child(
                    "isf",
                    {"src": str(file), "out": str(produced), "schema_dir": str(schemas)},
                    work,
                    timeout_s=ISF_TIMEOUT_S,
                )
                members = [{"name": file.name, **out}]
        except isolate.ChildFailed as exc:
            raise ImportRefused(str(exc)) from exc
        for member in members:
            label = isolate.safe_text(member.get("name", ""), 160)
            try:
                identity = to_identity(member.get("identity"))
            except (ValidationError, KeyError, TypeError) as exc:
                raise ImportRefused(f"{label}: invalid kernel identity in the ISF") from exc
            if identity is None:
                if not is_zip:
                    raise ImportRefused(
                        "the ISF names no kernel identity (a Windows kernel PDB or a Linux "
                        "banner): nothing the worker could look up"
                    )
                result.skipped.append({"member": label, "reason": "not a kernel ISF"})
                continue
            try:
                staged = writer.adopt(work / str(member["file"]), work, "import")
                writer.stage(staged, identity, member["sha256"], source, replace=replace)
            except StoreError as exc:
                hint = "" if replace else " (re-run with --replace to replace it)"
                raise ImportRefused(f"{exc}{hint}") from exc
        result.changes = writer.commit()
    for skipped in result.skipped:
        log("skipped", **skipped)
    return result
