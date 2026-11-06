---
phase: 4
title: "Synthetic disk image generator"
status: pending
priority: P2
effort: "14h"
dependencies: []
---

# Phase 4: Synthetic disk image generator (A′, parallel with phase 1; merged before group B)

## Overview
A deterministic generator of small disk images with known ground truth, built only from our own content, at test time, with standard Linux tools. It is the real-engine test data for TSK, libewf and Plaso (plan "Testing and data"). No real disk image, test corpus or third-party artifact is ever downloaded or committed.

The generator runs inside the dev / test target of the disk image, whose extra packages it owns (`docker/diskgen-packages.txt`). Before that image exists, it is developed in a one-off `debian:trixie-slim` container with the same package list (A′; no compose service, no slot, one container at a time beside phase 1).

**Parent decision (red team RT26): no privileged loop-mount container, ever.** No `--privileged`, no loop device, no FUSE mount, no `mount` of any kind, in development, tests or the gate. Every image is built from regular files by tools that write images directly, and nothing binary is committed.

**Owns:**
- `apps/workers/disk/samples/diskgen/**` (`__main__.py`, `layouts.py`, `fs_fat.py`, `fs_exfat.py`, `fs_ext.py`, `fs_ntfs.py`, `ewf.py`, `trees.py`, `hives.py`, `mutate.py`, `ground_truth.py`);
- `apps/workers/disk/docker/diskgen-packages.txt`;
- `samples/hives/**` (hivex `.reg` inputs, if the hive spike succeeds);
- `tests/unit/test_diskgen.py`, `tests/engine/test_diskgen_images.py`.

## Requirements
- **Packages** (`diskgen-packages.txt`, dev / test target only; never prod, asserted by phase 1's `finalize_image.py`): `dosfstools`, `mtools`, `exfatprogs`, `e2fsprogs`, `ntfs-3g` (with `libntfs-3g89t64`, used as a library), `fdisk` (sfdisk), `ewf-tools`, `util-linux` (`utmpdump`), `libhivex-bin` (if used), `coreutils`. GPL licenses are fine for test-time tools (research §7).
- **Images** (each ≤ 64 MiB; fixed seeds; every timestamp set explicitly; output in the test tmpfs or a temp dir, never committed):

  | Id | Layout | Content |
  |---|---|---|
  | `fat_basic` | no table, FAT32 | dirs via `mmd`, files via `mcopy -m` (fixed mtimes), a deleted file via `mdel` (`0xE5` entry), long names, a 2-second timestamp |
  | `fat12`, `fat16` | MBR, one partition each | small trees |
  | `exfat_basic` | MBR, exFAT | a tree (populated through the documented tooling the spike finds; fallback: empty file system, listing only) |
  | `ext4_linux` | GPT, ext4 | a Linux system tree (`mke2fs -d`): `etc/os-release`, `etc/timezone`, `etc/passwd`, a dummy `etc/shadow`, `var/log/{syslog,auth.log,wtmp,dpkg.log}`, `var/log/auth.log.2.gz` (for `full`), a gzip-compressed file named `var/log/messages` (dropped by the compressed-content rule, RT11), `root/.bash_history`, `etc/cron.d/*`, a systemd unit, an ELF in `/tmp`, `authorized_keys`, never-collected dummies of each Linux class (`.aws/credentials`, `.ssh/id_ed25519`, `krb5.keytab`…), **a hard link `var/log/old.log` → the `etc/shadow` inode** (`debugfs -w ln` + `set_inode_field links_count`; RT7); times via `debugfs -w set_inode_field` |
  | `ext2`, `ext3` | MBR | small trees |
  | `ntfs_windows` | MBR, NTFS | a Windows-shaped tree: `Windows/System32/config/{SYSTEM,SOFTWARE}` (hivex-built or placeholder bytes), `Users/alice/NTUSER.DAT`, `Users/alice/AppData/Local/Temp/tool.exe` (a tiny benign PE built by our own script, the M3 sample generator pattern), `invoice.pdf.exe`, a PE behind `.jpg`, a named stream with PE magic, `Zone.Identifier` streams, a Startup-folder file, an `Amcache.hve`, the never-collected names (one small dummy per class: `SAM`, `SECURITY`, `RegBack/SAM`, `Login Data`, `Local State`, `logins.json`, `key4.db`, `NTDS.dit`, `unattend.xml`, `pagefile.sys`, `x.pfx`), **a second name for the `SAM` file** (an NTFS hard link where the chosen NTFS route can make one, else on the FAT32 fallback tree a documented gap; RT7), a non-ASCII user folder `Users/José` (RT31) |
  | `multi_gpt` | GPT: ext4 + FAT + an unsupported partition (an HFS+ superblock signature only) + a LUKS header signature | mixed |
  | `split_raw` | `ntfs_windows` split into 8 MiB parts | — |
  | `ewf_single`, `ewf_multi` | `ewfacquirestream -f encase6` of `ntfs_windows` (multi: `-S` small segments) with case number / examiner set | — |
  | `ewf_bad_hash` | `ewf_single` with its stored MD5 changed in the hash section (our own patcher, CRC fixed) | — |

- **NTFS trees** (`ntfscp` cannot create directories; research §7). No mount of any kind (parent decision, RT26). The spike (≤ 4 h of the 14 h) decides in order:
  1. **libntfs-3g as a library** (`fs_ntfs.py`, ctypes over `libntfs-3g.so`, opaque pointers only): `ntfs_mount(<image file>, 0)` opens the volume without the kernel, `ntfs_pathname_to_inode` finds the parent, `ntfs_mbstoucs` converts the name, `ntfs_create(parent, 0, name, len, S_IFDIR)` makes each directory (`ntfs_link` for the hard link), `ntfs_inode_close` / `ntfs_umount` flush; files and named streams then via `ntfscp` (`-N` / `--attr-name` for an ADS). Verified by `ntfsinfo` and later by TSK. NTFS times the tools set to "now" are read back with `ntfsinfo` into the ground truth (a different reader than TSK), recorded as a determinism exception;
  2. else a minimal directory creator of our own (a new MFT record with an `$INDEX_ROOT` entry in the parent, update sequence fixed), verified by `ntfsinfo`;
  3. else the **Windows-shaped tree on FAT32** (`mmd` / `mcopy`: OS detection, the catalog, collect and Plaso preprocessing are path-based and work on any file system) plus a **flat NTFS image** (files in the root directory only) for the NTFS-only features (named streams, `$OrphanFiles`, deleted MFT entries); the gap is recorded for TESTING.

  The decision is recorded at the end of this file. No image is committed in any branch of the decision.
- **Registry hives** (stretch, inside the 14 h): `hivexregedit --merge` of our `.reg` inputs into a minimal base hive, giving a Run key, a service with an `ImagePath` in `Temp`, and a UserAssist entry. The base hive is written by our own `hives.py` (a regf header with its checksum, one hbin, a root `nk` cell); hivex's own test hives are third-party data and never used. If hivex cannot merge into it, the hive files are placeholder bytes and registry events stay replay-only.
- **Ground truth** (`ground_truth.json` per image):
  - partitions (start, length, type, `fs_status`);
  - every file (path, flags, size, the four times, stream names, sha256 of content);
  - expected OS markers;
  - expected collect plan entries;
  - for the Linux tree, the expected Plaso events by data type;
  - expected findings by method.
- **Hostile mode** (`mutate.py`, used by phases 2 and 13):
  - a 64-level deep tree of 255-character names (path > 4 096 bytes; RT13);
  - an NTFS or ext image whose metadata claims a very large MFT / inode table (sparse; RT30);
  - an E01 whose header claims a media size above `DISK_MAX_MEDIA_BYTES` (RT6);
  - truncation at random offsets;
  - corrupted boot sector / superblock / MFT records (seeded byte flips in metadata regions only);
  - a directory cycle (an ext4 directory entry pointing at an ancestor inode via `debugfs`);
  - a 300 000-entry directory (ext4, generated sparse names);
  - names with `|`, newline, RTLO, 255-byte UTF-8, invalid UTF-8 (FAT / ext raw bytes);
  - overlapping and beyond-media partitions;
  - an EWF with a lying segment count;
  - compressed / archive / VMDK / QCOW / VHD magic files.

  Each mutation is deterministic from (image id, seed).
- **CLI:** `python -m samples.diskgen --out <dir> [--only <ids>] [--hostile N --seed S]`; `pnpm disk:gen` wraps it (phase 1). Generation of the full set takes < 2 min and < 1 GiB of disk.

## Implementation Steps
1. Package list; the one-off container command recorded in this file.
2. FAT / exFAT / ext generators with explicit timestamps; ground truth from our own model of the tree (never by reading back with TSK).
3. Partition layouts (`sfdisk` on a file + `dd conv=notrunc`); split raw; EWF; the hash patcher.
4. NTFS spike and generator; hive stretch.
5. Hostile mode.
6. `test_diskgen.py` (determinism: the same seed gives the same sha256 for every image except EWF timestamps, which are fixed through the tool options or patched); `test_diskgen_images.py` checks images with the generating tools' own readers (`fsck.*` / `ntfsinfo` / `ewfinfo`), not with TSK (phase 2 does that).

## Success Criteria
- [ ] `pnpm disk:gen` produces every image in the table deterministically, with ground truth, in < 2 min.
- [ ] Images pass their own tools' checks (`fsck.fat -n`, `e2fsck -fn`, `ntfsfix -n`, `ewfverify`; the bad-hash image fails `ewfverify` as intended).
- [ ] The NTFS directory decision and the hive outcome are recorded; no step used a mount or a privileged container, and no image is committed; any coverage gap is listed in TESTING by phase 12.
- [ ] Hostile mode produces every listed mutation reproducibly.

## Risk Assessment
- **NTFS without mount:** libntfs-3g's library API is not a documented public interface (ctypes over opaque pointers, the ntfs-3g 2022.10.3 symbols); a custom MFT writer is riskier; the FAT32 fallback keeps every path-based test, and the gap is documented, not hidden.
- **Tool timestamp non-determinism** (`mkfs` UUIDs, EWF acquiry dates): fixed through options (`-U`, `-i` volume ids, `-C`), else patched after generation and recorded.
- **Ground truth computed from the same assumptions as the code under test:** ground truth comes from the generator's input model, and phase 2 compares TSK output against it, not against itself.

## Spike notes
<!-- Filled by the phase-4 agent: NTFS directory approach, hive outcome, exFAT population method, determinism exceptions. -->
