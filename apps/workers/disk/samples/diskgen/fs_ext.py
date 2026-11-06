"""ext2 / ext3 / ext4 through e2fsprogs in userspace: `mke2fs -d` copies a staged directory
into a new image file (no mount), then `debugfs -w -f` sets every inode's times and owner
from the tree model. Hard links are staged as hard links (mke2fs keeps them: one inode,
`links_count` 2; RT7).

Determinism: a fixed file system UUID (`-U`), directory hash seed (`-E hash_seed`) and clock
(`E2FSPROGS_FAKE_TIME`, `tools.env`); every inode time is then set explicitly.
"""

import os
import tempfile
import uuid
from pathlib import Path

from samples.diskgen import MIB, tools
from samples.diskgen.trees import Node, Tree

KINDS = ("ext2", "ext3", "ext4")


def stage(tree: Tree, root: Path) -> None:
    """Write the tree under `root` (regular files, directories, hard links; no deleted nodes:
    ext deletion is not modelled)."""
    root.mkdir(parents=True, exist_ok=True)
    for node in tree.walk():
        if node.deleted:
            raise ValueError(f"deleted nodes are not supported on ext: {node.path}")
        target = root / node.path.lstrip("/")
        if node.is_dir:
            target.mkdir(parents=True, exist_ok=True)
        elif node.link_to is not None:
            os.link(root / node.link_to.lstrip("/"), target)
        else:
            target.write_bytes(node.data)
    # Modes and mtimes last (writing a child changes its directory's mtime).
    for node in reversed(list(tree.walk())):
        target = root / node.path.lstrip("/")
        if node.link_to is None:
            os.chmod(target, node.mode)
            os.utime(target, (node.atime, node.mtime))


def _quote(path: str) -> str:
    if any(c in path for c in '"\\\n'):
        raise ValueError(f"debugfs cannot address {path!r}")
    return f'"{path}"'


def owner(node: Node) -> tuple[int, int]:
    return (1000, 1000) if node.path.startswith("/home/alice") else (0, 0)


def debugfs_script(tree: Tree, *, crtime: bool) -> str:
    """`set_inode_field` lines for every inode (hard-link names share their target's inode)."""
    lines: list[str] = []
    for node in tree.walk():
        if node.link_to is not None:
            continue
        p = _quote(node.path)
        uid, gid = owner(node)
        lines += [f"set_inode_field {p} uid {uid}", f"set_inode_field {p} gid {gid}"]
        fields = [("mtime", node.mtime), ("atime", node.atime), ("ctime", node.ctime)]
        if crtime:
            fields.append(("crtime", node.crtime))
        lines += [f"set_inode_field {p} {name} @{value}" for name, value in fields]
    return "\n".join(lines) + "\n"


def mke2fs_argv(
    kind: str,
    out: Path,
    size: int,
    staging: Path,
    fs_uuid: uuid.UUID,
    label: str,
    inodes: int | None = None,
    inode_size: int = 256,
    extra: list[str] | None = None,
) -> list[str]:
    if kind not in KINDS:
        raise ValueError(kind)
    hash_seed = uuid.uuid5(fs_uuid, "hash_seed")
    argv = [
        "mke2fs", "-q", "-F", "-t", kind, "-b", "4096", "-I", str(inode_size),
        "-L", label, "-U", str(fs_uuid),
        "-E", f"hash_seed={hash_seed},root_owner=0:0,lazy_itable_init=0",
        "-d", str(staging),
    ]  # fmt: skip
    if inodes is not None:
        argv += ["-N", str(inodes)]
    argv += extra or []
    return [*argv, str(out), f"{size // 1024}k"]


def build(
    tree: Tree,
    out: Path,
    kind: str,
    size: int,
    *,
    fs_uuid: uuid.UUID,
    label: str,
    extra_debugfs: list[str] | None = None,
    inodes: int | None = None,
    inode_size: int = 256,
) -> None:
    tools.require("mke2fs", "debugfs")
    if size > 64 * MIB:
        raise ValueError("images stay <= 64 MiB")
    with tempfile.TemporaryDirectory(prefix="diskgen-ext-", dir=out.parent) as tmp:
        staging = Path(tmp) / "root"
        stage(tree, staging)
        out.unlink(missing_ok=True)
        tools.run(mke2fs_argv(kind, out, size, staging, fs_uuid, label, inodes, inode_size))
        script = Path(tmp) / "times.debugfs"
        body = debugfs_script(tree, crtime=kind == "ext4")
        script.write_text(body + "".join(f"{line}\n" for line in extra_debugfs or []))
        run_debugfs(out, script)


def run_debugfs(image: Path, script: Path) -> None:
    """debugfs exits 0 even when a command fails: any stderr line but its banner is an error."""
    _, err = tools.run_full(["debugfs", "-w", "-f", str(script), str(image)])
    errors = [line for line in err.splitlines() if line and not line.startswith("debugfs ")]
    if errors:
        raise tools.ToolFailed("debugfs: " + "; ".join(errors[:5]))
