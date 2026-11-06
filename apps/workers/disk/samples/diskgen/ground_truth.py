"""`ground_truth.json`: what a correct reader must find in a generated image, computed from the
generator's input model (the tree, the layout and the writer's placement), never by reading
the image back. Phase 2's engine test (`tests/engine/test_tsk_images.py`) reads `format`,
`partitions`, `files` and `never_collect_meta`; the other keys serve phases 3, 6 and 13.
"""

import hashlib
import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from samples.diskgen import GENERATOR, NOTE, fs_fat
from samples.diskgen.trees import Node, Tree

# Detection methods (disk_worker/detections/base.py, checked by tests/unit/test_diskgen.py).
M_EXEC = "heuristic:disk_exec_user_writable@1"
M_DOUBLE = "heuristic:disk_double_extension@1"
M_MISMATCH = "heuristic:disk_extension_mismatch@1"
M_ADS = "heuristic:disk_ads_executable@1"
M_PERSISTENCE = "heuristic:disk_persistence@1"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_files(paths: Iterable[Path]) -> str:
    h = hashlib.sha256()
    for p in paths:
        with p.open("rb") as f:
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
    return h.hexdigest()


def partition(
    index: int,
    start: int,
    sectors: int,
    fs_type: str | None,
    *,
    fs_status: str = "ok",
    reason: str | None = None,
    os: str = "none",
    os_name: str | None = None,
) -> dict[str, Any]:
    return {
        "index": index,
        "start_sector": start,
        "length_sectors": sectors,
        "fs_type": fs_type,
        "fs_status": fs_status,
        "reason": reason,
        "os": os,
        "os_name": os_name,
    }


def os_of(tree: Tree) -> tuple[str, str | None]:
    """The OS markers phase 2's layout looks for (`probe/layout.py`)."""
    if "/Windows/System32/config/SYSTEM" in tree.nodes:
        return "windows", None
    if "/etc/os-release" in tree.nodes or "/etc/debian_version" in tree.nodes:
        release = tree.nodes.get("/etc/os-release")
        for line in (release.data if release else b"").splitlines():
            if line.startswith(b"PRETTY_NAME="):
                return "linux", line.split(b"=", 1)[1].strip(b"\"'").decode()
        return "linux", None
    return "none", None


def _times(node: Node, family: str) -> dict[str, int | None]:
    if family == "fat":
        return fs_fat.quantize(node)
    if family in ("ext2", "ext3"):
        return {"mtime": node.mtime, "atime": node.atime, "ctime": node.ctime, "crtime": None}
    if family == "ext4":
        return {
            "mtime": node.mtime,
            "atime": node.atime,
            "ctime": node.ctime,
            "crtime": node.crtime,
        }
    return {}  # NTFS: the tools' clock (determinism exception), not asserted


def files(
    tree: Tree,
    partition_index: int,
    family: str,
    placed: Mapping[str, fs_fat.Placed] | None = None,
) -> list[dict[str, Any]]:
    """One entry per name (and per NTFS named stream). `family`: fat, ext2/3/4 or ntfs."""
    linked = {n.link_to for n in tree.walk() if n.link_to} | {
        n.path for n in tree.walk() if n.link_to
    }
    out: list[dict[str, Any]] = []
    for node in tree.walk():
        path = node.path
        if node.deleted and placed is not None:
            path = f"{node.parent.rstrip('/')}/{placed[node.path].display}"
        entry: dict[str, Any] = {
            "partition_index": partition_index,
            "path": path,
            "type": "dir" if node.is_dir else "reg",
            "deleted": node.deleted,
        }
        if not node.is_dir:
            entry["size"] = len(node.data)
            if not node.deleted:  # recovery of a freed chain is reader-specific
                entry["sha256"] = sha256(node.data)
        if family != "fat" and node.path in linked:
            entry["hard_linked"] = True
        if node.never_collect:
            entry["never_collect"] = node.never_collect
        entry["times"] = _times(node, family)
        out.append(entry)
        for stream, data in node.streams.items():
            out.append(
                {
                    "partition_index": partition_index,
                    "path": path,
                    "stream": stream,
                    "type": "reg",
                    "size": len(data),
                    "sha256": sha256(data),
                }
            )
    return out


def never_collect_meta(tree: Tree, partition_index: int) -> list[dict[str, Any]]:
    """The second names of never-collected files (hard links outside every pattern, RT7)."""
    return [
        {"partition_index": partition_index, "path": n.path, "link_to": n.link_to}
        for n in tree.walk()
        if n.link_to is not None and n.never_collect
    ]


def document(
    image_id: str,
    fmt: str,
    segments: list[Path],
    volume_system: str,
    partitions: list[dict[str, Any]],
    file_entries: list[dict[str, Any]],
    **extra: Any,
) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "generator": GENERATOR,
        "note": NOTE,
        "id": image_id,
        "format": fmt,
        "segments": [p.name for p in segments],
        "volume_system": volume_system,
        "partitions": partitions,
        "files": file_entries,
        "never_collect_meta": [],
        "gaps": [],
        "determinism": "byte_exact",
    }
    if fmt != "ewf":
        doc["media_bytes"] = sum(p.stat().st_size for p in segments)
        doc["media_sha256"] = sha256_files(segments)
    doc.update(extra)
    return doc


def write(directory: Path, doc: Mapping[str, Any]) -> Path:
    path = directory / "ground_truth.json"
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path
