"""Synthetic disk image generator (M9 phase 4): small images with known ground truth.

Built only from our own content, at test time, without any mount, loop device, FUSE or
privileged container (parent decision, RT26). Two kinds of writers:

- pure Python (`fs_fat`, `layouts`, `hives`, `mutate`, the EWF patcher in `ewf`): FAT12 / 16 /
  32 file systems, MBR / GPT tables, split raw sets, regf base hives and the hostile mutations,
  written byte by byte. They run anywhere (the host unit tests cover them);
- userspace tools that write images directly (`fs_ext`: `mke2fs -d` + `debugfs -w`;
  `fs_exfat`: `mkfs.exfat`; `fs_ntfs`: `mkntfs` + `ntfscp`; `ewf`: `ewfacquirestream`), only in
  the disk worker's dev / test target (`docker/diskgen-packages.txt`), never in prod.

Every image is ≤ 64 MiB, deterministic from fixed seeds and explicit times (the exceptions are
listed in the phase-4 spike notes), written to a temp / tmpfs directory and never committed.
Nothing here is real malware: the "executables" are inert PE / ELF headers built below.

    python -m samples.diskgen --out DIR [--only ID,...] [--hostile N --seed S]
"""

from datetime import UTC, datetime

MIB = 1024 * 1024
SECTOR = 512
SEED = 9064
MAX_IMAGE_BYTES = 64 * MIB
# Every timestamp of every tree is BASE_TIME + an explicit offset (seconds since the epoch).
BASE_TIME = int(datetime(2026, 3, 14, 9, 0, 0, tzinfo=UTC).timestamp())
GENERATOR = "cyberlab-diskgen/1"
NOTE = "synthetic generated image (our own content, not a real disk, not real analysis)"
