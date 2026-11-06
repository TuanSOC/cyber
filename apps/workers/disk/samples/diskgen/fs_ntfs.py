"""NTFS without any mount (parent decision, RT26): `mkntfs` on an image file, files and named
streams through `ntfscp`, and directories / hard links through libntfs-3g used as a library.

`ntfscp` cannot create directories (research §7). The routes, in the plan's order:

1. `libntfs`: ctypes over `libntfs-3g.so` (opaque pointers only): `ntfs_mount(<image file>, 0)`
   opens the volume in userspace, `ntfs_pathname_to_inode` finds a parent, `ntfs_mbstoucs`
   converts a name, `ntfs_create(parent, 0, name, len, S_IFDIR)` makes a directory and
   `ntfs_link` a second name; `ntfs_inode_close` / `ntfs_umount` flush. It always runs in a
   child process (`python -m samples.diskgen.fs_ntfs`), so a library fault costs the route,
   never the generator. Verified with `ntfsinfo -F` on every leaf directory.
2. our own MFT directory writer: not attempted (riskier than 3, plan risk table);
3. `fat32`: the Windows-shaped tree on FAT32 plus a flat NTFS image (`ntfs_flat`, files in the
   root directory only) for the NTFS-only features (named streams, `$OrphanFiles`).

`auto` tries 1 and falls back to 3; the route taken is recorded in the ground truth. NTFS
times are the tools' "now" (a determinism exception): the ground truth has no NTFS times.
"""

import ctypes
import json
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from samples.diskgen import tools
from samples.diskgen.trees import Tree

S_IFDIR = 0o040000
LIBS = ("libntfs-3g.so.89", "libntfs-3g.so")


def mkntfs(out: Path, size: int, *, label: str, hidden_sectors: int) -> None:
    tools.require("mkntfs")
    with out.open("wb") as f:
        f.truncate(size)
    tools.run(
        [
            "mkntfs", "-F", "-Q", "-q", "-T", "-s", "512", "-c", "4096",
            "-p", str(hidden_sectors), "-H", "255", "-S", "63", "-L", label, str(out),
        ]
    )  # fmt: skip


def ntfscp(image: Path, source: Path, dest: str, stream: str | None = None) -> None:
    argv = ["ntfscp", "-f", "-q"]
    if stream is not None:
        argv += ["-N", stream]
    tools.run([*argv, str(image), str(source), dest])


def copy_files(image: Path, tree: Tree, *, flat: bool = False) -> None:
    """Every regular file (and its named streams) of `tree`; with `flat`, into the root."""
    with tempfile.TemporaryDirectory(prefix="diskgen-ntfs-") as tmp:
        for n, node in enumerate(tree.walk()):
            if node.is_dir or node.link_to is not None:
                continue
            src = Path(tmp) / f"f{n}"
            src.write_bytes(node.data)
            dest = "/" + node.name if flat else node.path
            ntfscp(image, src, dest)
            for i, (stream, data) in enumerate(node.streams.items()):
                ssrc = Path(tmp) / f"f{n}s{i}"
                ssrc.write_bytes(data)
                ntfscp(image, ssrc, dest, stream)


# --- route 1: libntfs-3g as a library (child process only) ------------------------------------


def _load() -> Any:
    last: OSError | None = None
    for name in LIBS:
        try:
            lib = ctypes.CDLL(name)
        except OSError as exc:
            last = exc
            continue
        vp = ctypes.c_void_p
        lib.ntfs_mount.restype = vp
        lib.ntfs_mount.argtypes = [ctypes.c_char_p, ctypes.c_ulong]
        lib.ntfs_umount.restype = ctypes.c_int
        lib.ntfs_umount.argtypes = [vp, ctypes.c_int]
        lib.ntfs_pathname_to_inode.restype = vp
        lib.ntfs_pathname_to_inode.argtypes = [vp, vp, ctypes.c_char_p]
        lib.ntfs_mbstoucs.restype = ctypes.c_int
        lib.ntfs_mbstoucs.argtypes = [ctypes.c_char_p, ctypes.POINTER(vp)]
        lib.ntfs_create.restype = vp
        lib.ntfs_create.argtypes = [vp, ctypes.c_uint32, vp, ctypes.c_uint8, ctypes.c_uint32]
        lib.ntfs_link.restype = ctypes.c_int
        lib.ntfs_link.argtypes = [vp, vp, vp, ctypes.c_uint8]
        lib.ntfs_inode_close.restype = ctypes.c_int
        lib.ntfs_inode_close.argtypes = [vp]
        return lib
    raise OSError(f"libntfs-3g not loadable: {last}")


def _ucs(lib: Any, name: str) -> tuple[ctypes.c_void_p, int]:
    out = ctypes.c_void_p()
    length = lib.ntfs_mbstoucs(name.encode("utf-8"), ctypes.byref(out))
    if length <= 0 or not out.value:
        raise OSError(f"ntfs_mbstoucs failed for {name!r}")
    return out, length


def _child(op: str, image: str, items: list[Any]) -> None:
    """mkdirs: items = ["/a", "/a/b", ...] (parents first); link: items = [[target, new], ...]."""
    lib = _load()
    libc = ctypes.CDLL(None)
    vol = lib.ntfs_mount(image.encode(), 0)
    if not vol:
        raise OSError("ntfs_mount failed")
    try:
        for item in items:
            path, target = (item, None) if op == "mkdirs" else (item[1], item[0])
            parent_path, _, name = path.rpartition("/")
            parent = lib.ntfs_pathname_to_inode(vol, None, (parent_path or "/").encode())
            if not parent:
                raise OSError(f"no parent for {path}")
            ucs, length = _ucs(lib, name)
            try:
                if op == "mkdirs":
                    ni = lib.ntfs_create(parent, 0, ucs, length, S_IFDIR)
                    if not ni:
                        raise OSError(f"ntfs_create failed for {path}")
                    lib.ntfs_inode_close(ni)
                else:
                    ni = lib.ntfs_pathname_to_inode(vol, None, str(target).encode())
                    if not ni:
                        raise OSError(f"no link target {target}")
                    rc = lib.ntfs_link(ni, parent, ucs, length)
                    lib.ntfs_inode_close(ni)
                    if rc != 0:
                        raise OSError(f"ntfs_link failed for {path}")
            finally:
                libc.free(ucs)
                lib.ntfs_inode_close(parent)
    finally:
        if lib.ntfs_umount(vol, 0) != 0:
            raise OSError("ntfs_umount failed")


def libntfs(op: str, image: Path, items: Sequence[Any]) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "samples.diskgen.fs_ntfs", op, str(image), json.dumps(list(items))],
        capture_output=True,
        env=tools.env({"PYTHONPATH": str(Path(__file__).resolve().parents[2])}),
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        raise tools.ToolFailed(f"libntfs {op}: {result.stderr.decode('utf-8', 'replace')[-800:]}")


def verify_dirs(image: Path, dirs: Sequence[str]) -> None:
    leaves = [d for d in dirs if not any(o.startswith(d + "/") for o in dirs)]
    for d in leaves:
        tools.run(["ntfsinfo", "-F", d, str(image)])


def build_tree(image: Path, tree: Tree) -> None:
    """Route 1 on a fresh `mkntfs` image: directories, files and streams, then hard links."""
    dirs = [n.path for n in tree.walk() if n.is_dir]
    libntfs("mkdirs", image, dirs)
    verify_dirs(image, dirs)
    copy_files(image, tree)
    links = [[n.link_to, n.path] for n in tree.walk() if n.link_to is not None]
    if links:
        libntfs("link", image, links)


if __name__ == "__main__":
    _child(sys.argv[1], sys.argv[2], json.loads(sys.argv[3]))
