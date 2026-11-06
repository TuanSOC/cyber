# Research: The Sleuth Kit, Plaso and libewf for an offline disk worker (M9)

Date: 2026-11-06 (research run for the M9 plan dated 261107). Method: GitHub releases API, PyPI JSON, Debian package pages and `debian/copyright`, upstream docs and source files. **[V]** means verified at the cited source. **[I]** means inferred, anecdotal or not verified. This is not legal advice.

## 1. The Sleuth Kit (TSK)
- **Latest release:** `sleuthkit-4.15.0` (2026-04-15) [V https://api.github.com/repos/sleuthkit/sleuthkit/releases?per_page=5]. Its notes mention many added memory bounds checks and NTFS overflow fixes. Before it: 4.14.0 (2025-04-15; BitLocker on Windows only; the experimental btrfs / xfs work reverted) and 4.13.0 (2025-03-11).
- **Licenses** [V https://raw.githubusercontent.com/sleuthkit/sleuthkit/develop/licenses/README.md]:
  - core `tsk/`: **IBM Public License 1.0** (the original TCT code) and **CPL-1.0**;
  - `srchtools/srch_strings.c`: **GPL-2.0**, the only GPL tool;
  - Java bindings, case-uco and rejistry++: Apache-2.0; `fiwalk`: public domain; `lzvn.c`: BSD-3; bundled sqlite / crc / sha1: public domain; `md5c.c`: the RSA-MD5 license.
  - libtsk itself is **not GPL**.
  - Debian's `debian/copyright` agrees: CPL-1.0 by default, IBM-PL-1.0 for `tsk/fs/` and `tools/fstools/`, GPL-2+ for `srch_strings.c` [V https://sources.debian.org/src/sleuthkit/4.12.1+dfsg-3/debian/copyright/].
  - **Implication [I]:** CPL / IPL are weak-copyleft. Redistributing the unmodified library in an image needs the license text and an offer of its source; our own code that links it is not covered. Nothing like the VSL "wrapper" clause of M8 applies.
- **Debian trixie** ships `sleuthkit` **4.12.1+dfsg-3**, which predates 4.15.0 and is **probably exposed to the 2026 CVEs** below unless patched [V https://packages.debian.org/trixie/sleuthkit; exposure I]. → **Do not install the Debian package.**
- **Supported formats** [V https://www.sleuthkit.org/sleuthkit/desc.php]:
  - file systems: NTFS, FAT, exFAT, ext2/3/4, APFS (encryption support "not complete"), HFS, ISO 9660, UFS1/2, YAFFS2;
  - volume systems: DOS / MBR, GPT, BSD, Mac, Sun VTOC, LVM (non-Windows, since 4.12.0);
  - images: raw / dd, split raw, E01 (through libewf), VHD, VMDK, AFF (when built with those libraries).
- **CLI:** `fls`, `icat`, `mmls`, `fsstat`, `istat`, `img_stat`, `tsk_recover`, `mactime`, `hfind` and others are all in the package [V https://packages.debian.org/trixie/amd64/sleuthkit/filelist].
  - **There is no JSON output.** `fls -m` writes body files [V https://manpages.debian.org/trixie/sleuthkit/fls.1.en.html].
  - **Body file 3.x** is 11 pipe-separated fields: `MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime`, with Unix-epoch times; `#` lines are comments [V https://github.com/sleuthkit/sleuthkit/wiki/Body_file]. The wiki's example line does not match its own header.
  - File names are attacker-chosen and may contain `|` or newlines [I], so parsing CLI text output of a hostile image is fragile.
- **Parser CVEs** (examples) [V via https://vulnerability.circl.lu/vuln/fkie_cve-2026-40025, https://stack.watch/vuln/CVE-2026-40026, https://vulert.com/vuln-db/debian-10-sleuthkit-134528]:
  - CVE-2026-40025: an APFS keybag heap out-of-bounds read (≤ 4.14.0);
  - CVE-2026-40026: an ISO 9660 SUSP out-of-bounds read plus an infinite loop (≤ 4.14.0);
  - CVE-2020-10233: an NTFS `ntfs_dinode_lookup` heap over-read;
  - CVE-2020-10232: a YAFFS stack overflow;
  - CVE-2019-1010065 and CVE-2018-19497: HFS integer overflow and catalog traversal bugs;
  - CVE-2022-45639: `fls -m` "command injection" (4.11.1; widely regarded as disputed [I]).
  - The pytsk README itself warns that "libtsk is known to have many defects" and recommends a sandbox for untrusted data [V https://github.com/py4n6/pytsk].
- **Decision input:**
  - parse hostile images **only in a sandboxed tool process**;
  - use **explicit file-system and volume-system types** (try NTFS, FAT, exFAT, ext in turn) instead of autodetection. This keeps the APFS, ISO 9660, HFS, UFS and YAFFS2 parsers, where most CVEs sit, out of reach.

## 2. pytsk3 (library mode)
- **Version and license:** PyPI **`pytsk3==20260715`** (2026-07-15), Apache-2.0, Python ≥ 3.10 [V https://pypi.org/pypi/pytsk3/json].
- **Wheels:** cp310–cp314 manylinux x86_64 / aarch64 (so **cp312 manylinux exists**), musllinux, macOS, Windows [V].
- **Bundled TSK:** it **bundles TSK source** (a `sleuthkit` submodule, targeting 4.15.0) [V https://github.com/py4n6/pytsk]. The wheel embeds libtsk statically [I], so a TSK fix means a pytsk3 upgrade, not an OS package upgrade.
- **Maintenance:** active (last push 2026-10-30, not archived) [V https://api.github.com/repos/py4n6/pytsk].
- **Debian:** `python3-tsk` 20231007 in trixie is built for Python 3.13 only, which is unusable on `python:3.12` [V https://packages.debian.org/trixie/python3-tsk].
- **API [I, the well-known recipe]:**
  - `Img_Info` can be subclassed in Python (`read(offset, size)`, `get_size()`), which gives split raw (concatenation) and E01 (a pyewf handle);
  - `Volume_Info(img, type)` lists partitions;
  - `FS_Info(img, offset, type)` opens a file system;
  - directory iteration gives `info.name` / `info.meta`;
  - `File.read_random(offset, size, attr_type, attr_id)` reads content, including NTFS named streams.
  - Phase 2 verifies the exact 20260715 API.
- **Decision input:** pytsk3 in a sandboxed probe process instead of the CLI. It gives structured access, no text parsing of hostile names, and one pinned TSK version.

## 3. libewf / pyewf (E01)
- **Upstream:** only "experimental" prereleases: **libewf-experimental-20260924** (2026-09-25), LGPL-3.0 [V https://api.github.com/repos/libyal/libewf/releases?per_page=5].
- **PyPI:** **`libewf-python==20260924`**, LGPL-3.0-or-later, cp310–cp315 manylinux2014 / musllinux wheels [V https://pypi.org/pypi/libewf-python/json].
- **Debian trixie:** `ewf-tools` / `libewf2` **20140816** (the legacy tree) [V https://packages.debian.org/trixie/ewf-tools]. It provides `ewfacquire`, `ewfacquirestream`, `ewfinfo`, `ewfverify` and others [I]. Use it **only to create synthetic E01 test images**; it is never in the runtime image.
- **LGPL-3.0 obligations [I]:** ship the license text and a source offer, and keep the library replaceable. A Python extension module loaded dynamically from the venv satisfies replaceability. Record it in the NOTICE.
- **What E01 gives the worker [I]:**
  - the stored MD5 / SHA-1 of the acquired media (`pyewf` hash values), so it can verify the media hash with a full read;
  - acquisition header values (case number, examiner, notes, acquiry date). These are attacker- or acquirer-chosen text, to be shown as quoted, inert text;
  - segments named `.E01`, `.E02`…; `pyewf.glob()` resolves the set from the first name.

## 4. Plaso / log2timeline
- **Version and license:** latest **20261027** (2026-10-27), Apache-2.0, Python ≥ 3.10; PyPI `plaso==20261027` [V https://api.github.com/repos/log2timeline/plaso/releases?per_page=5, https://pypi.org/pypi/plaso/json].
- **Dependencies:** **53 direct dependencies** on PyPI [V]:
  - dfvfs, dfwinreg, dtfabric, artifacts, acstore;
  - about 35 libyal bindings (libevtx-, libregf-, libesedb-, liblnk-, libfsntfs-, libfsext-, libvshadow-, libqcow-, libbde-, libluksde- … `-python`), LGPL-3.0+ [I except libewf, which is V];
  - pytsk3, yara-python, **opensearch-py, redis, pyzmq, requests**, psutil, XlsxWriter.
  - Whether every one of them has a cp312 manylinux wheel is **unverified** [I]. → a packaging spike (phase 3a).
- **Debian / Docker:**
  - Debian trixie `plaso` is **20241006**, two years old [V https://packages.debian.org/trixie/plaso].
  - The official Docker image `log2timeline/plaso` (about 152 MB compressed) is `FROM ubuntu:resolute` with the GIFT PPA [V https://raw.githubusercontent.com/log2timeline/plaso/main/config/docker/Dockerfile]: a different base and Python from our workers.
- **CLI** [V https://plaso.readthedocs.io/en/latest/sources/user/Using-log2timeline.html and the cited source files]:
  - `log2timeline.py --storage-file`, `--single-process`, `--no-dependencies-check`;
  - `--status-view none` (`status_view.py`);
  - `--partitions` / `--volumes` / `--vss-stores` (`all`, ranges, `none` for VSS; `storage_media_tool.py`);
  - `--parsers` (comma list, `parser/plugin`, `!` negation; presets `linux`, `win7`, `win7_slow`, `win_gen`, `webhist` …);
  - documented: `--artifact-filters`, `-f/--filter-file`, `--hashers`, `--workers`, `--worker-memory-limit` (default 2 GiB), `--temporary-directory`, `--unattended`, `--timezone`.
  - Session storage is **SQLite only** [V `plaso/lib/definitions.py`].
- **psort outputs** [V https://plaso.readthedocs.io/en/latest/sources/user/Output-and-formatting.html]: dynamic, json, **json_line**, l2tcsv, l2ttln, tln, xlsx, kml, rawpy, null, **opensearch**, opensearch_ts.
  - `json_line` writes one JSON object per event: its attributes, `timestamp`, `timestamp_desc`, `parser`, `data_type`, `display_name`, `filename`, `inode`, `message` and a nested `pathspec` [I; phase 3 records a real sample].
- **Network** [V plugin list https://plaso.readthedocs.io/en/latest/sources/user/Analysis-plugins.html]:
  - The analysis plugins are bloom (local file), browser_search, chrome_extension, nsrlsvr, sessionize, tagging, unique_domains_visited and virustotal.
  - **virustotal** (HTTP) and **nsrlsvr** (TCP) are network clients; chrome_extension may fetch from the Web Store [I].
  - The opensearch outputs and redis task storage are network sinks [I].
  - Extraction itself does no network I/O [I].
  - The multi-process engine coordinates workers through IPC (pyzmq) [I]. **`--single-process`** avoids it, which matters under an AF_UNIX-only seccomp filter [I; verified by the spike].
- **Runtime [I, anecdotal]** (https://groups.google.com/g/log2timeline-discuss/c/4yzRmERDtFc and an issue mirror):
  - a full extraction of 100 GB takes hours on 8 cores; one user reported more than 20 h for 500 GB;
  - about 2 GiB RAM per worker; the storage file can reach gigabytes.
  - → Full-image Plaso is out of reach for a 3 GiB, 2-CPU worker on a dev host. **Targeted collection** (KAPE-style) bounds it.
- **Decision input:** run Plaso **on a bounded set of artifact files the TSK stage extracts into a directory tree that mirrors the original layout**, never on the image. Plaso then:
  - never parses image, volume or file-system formats, so the dfVFS / libfs* stack is not exposed to the raw image;
  - its preprocessors still find `Windows/System32/config`, `/etc` and so on;
  - runs in `--single-process` mode with an explicit parser list, `--hashers none`, no analysis plugins and output `json_line` only.

## 5. dfVFS (context)
- **Formats** [V https://dfvfs.readthedocs.io/en/latest/sources/Supported-formats.html]:
  - images: EWF, raw / split, QCOW, VHD / VHDX, VMDK, Parallels, UDIF;
  - volumes: APM, APFS, BitLocker, BSD, FileVault2, GPT, LVM, LUKS, MBR, VSS;
  - file systems: APFS, ext, FAT, exFAT, HFS+, ISO 9660, NTFS, UFS, XFS;
  - archives: cpio, tar, zip.
- That is a much wider attack surface than M9 needs. With the extraction-first design, dfVFS only reads a plain OS directory (it may still open archives and compound files found among the artifacts; parser allow-list).

## 6. Autopsy
- **Version and license:** latest **4.23.1** (2026-05-07); 4.23.0 (2026-04-15) added an "MCP over STDIO server (Windows only)" [V https://api.github.com/repos/sleuthkit/autopsy/releases?per_page=3]. Apache-2.0 per its README [V].
- **Platforms:** "fully functional and fully tested only on Windows". On Linux it installs through a script (Java 17) or a snap, and some modules do not work there [V https://raw.githubusercontent.com/sleuthkit/autopsy/develop/Running_Linux_OSX.md].
- **Command Line Ingest:** exists (`--createCase`, `--addDataSource`, `--runIngest`, `--generateReports`). The examples are `autopsy64.exe`, it adds one data source per invocation, and ingest profiles must be created in the GUI [V https://sleuthkit.org/autopsy/docs/user-docs/4.23.0/command_line_ingest_page.html]. It still starts the NetBeans platform [I].
- **Multi-user:** needs Solr, PostgreSQL and ActiveMQ; there is no REST API [I].
- **Conclusion:** not feasible as an untrusted, network-less Linux server worker. M9 documents Autopsy as an **analyst-side tool**:
  - download the original segments (audited);
  - import CyberLab's exports: a TSK body file (mactime-compatible), the timeline CSV, and an md5sum-style hash list of flagged files (Autopsy imports md5sum / EnCase / HashKeeper hash sets [I]);
  - server-side Autopsy is "Later / not planned".

## 7. Synthetic test images (test time only; tools never in the prod image)
- **ext4:** `mke2fs -d <dir>` (e2fsprogs 1.47.2 in trixie) fills a new file system from a directory without root or mount [V https://manpages.debian.org/trixie/e2fsprogs/mke2fs.8.en.html]. Timestamps can be set with `debugfs -w -R "set_inode_field <path> mtime <v>"` [I].
- **NTFS:** ntfs-3g 2022.10.3 provides `mkntfs -F` (works on a regular file) and `ntfscp`, which **writes into an unmounted image** and creates files whose parent directory exists, but **cannot create directories** [V https://manpages.debian.org/trixie/ntfs-3g/mkntfs.8.en.html, https://raw.githubusercontent.com/tuxera/ntfs-3g/edge/ntfsprogs/ntfscp.c]. Deep NTFS trees therefore need another route (the phase-4 spike decides: a committed tiny generated NTFS image, or a minimal MFT writer of our own).
- **FAT:** `mkfs.fat -C` plus `mcopy` / `mmd` / `mdel -i img@@offset` fills FAT images without mounting; `mdel` leaves `0xE5` deleted entries that TSK lists [I].
- **Partition tables:** `sfdisk` writes dos and gpt labels to a regular file [V https://manpages.debian.org/trixie/fdisk/sfdisk.8.en.html]; the file-system images are then placed with `dd conv=notrunc` [I].
- **E01:** `ewfacquirestream -t <target> -f encase6 -S <segment size> -C <case> -e <examiner>` reads raw data from stdin [V https://manpages.debian.org/trixie/ewf-tools/ewfacquirestream.1.en.html]. A small `-S` yields multi-segment sets.
- **Licenses:** dosfstools and mtools are GPL-3, e2fsprogs and ntfs-3g GPL-2 [I]. They are used only to create test data in the dev / test target and are never shipped in the prod image.
- **Windows artifacts:**
  - **No Linux tool writes EVTX** [I], so EVTX parsing is covered by psort-shaped row fixtures and a test-only replay engine (the M8 "replay-tested" pattern).
  - Registry hives can be built from `.reg` text with hivex (`hivexregedit --merge`, LGPL) on a minimal base hive [I; the phase-4 spike decides].
  - Linux artifacts are easy: syslog / auth.log text, `utmpdump -r` for wtmp, bash history, cron and systemd units.

## 8. Known-file hash sets (NSRL)
- **Current release:** RDS **2026.09.1** (a delta); the last full release is 2026.03.1 [V https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/nsrl-download/current-rds].
  - Only **RDSv3 SQLite** is published now; the 2.x text format has ended.
  - Sets: Modern PC, Legacy PC, Android, iOS (full and delta).
  - "**Minimal**" versions contain only distinct file records [V https://www.nist.gov/node/800681].
- **Sizes [I]:** full Modern is tens of GB zipped; modern_minimal is a few GB.
- **License:** a US government work, generally treated as public domain [I].
- **hfind:** handles NSRL legacy text, md5sum, HashKeeper and EnCase after building an `.idx` [V https://manpages.debian.org/trixie/sleuthkit/hfind.1.en.html]. It does **not** read RDSv3 SQLite [I].
- **Decision input:**
  - an operator-run, network-less `disk-hashsets` tool imports a local RDSv3 SQLite file (or md5sum / sha256 lists) into a compact sorted binary set on a read-only volume (the M8 symbol-store pattern);
  - the worker binary-searches it through `mmap`;
  - nothing is downloaded by any tool, test or gate;
  - the column names of the RDSv3 `FILE` table are verified in phase 5 against NIST's schema documentation [I].
- **Alternatives [I]:** CIRCL hashlookup (online; refused: lookups leak hashes), Plaso's `bloom` plugin, a self-hosted `nsrlsvr` (a network service; refused for the worker).

## 9. Sizing and platform fit (analysis)
- **Platform limits today:**
  - `MAX_EVIDENCE_BYTES` 2 GiB; M8 adds `MEMORY_MAX_BYTES` (8 GiB default, ≤ 16 GiB) bounded by Caddy's `read_body 30m` (16 GiB needs ≥ 9.2 MB/s);
  - default org quota 20 GiB;
  - objects above 5 GiB work through multipart `fput_object`.
- **Disk images** are 10s–100s of GB. A single request cannot carry them. Two options fit the platform without new trusted services:
  1. **Segment sets.** Analysts already split images: E01 segments (common defaults 640 MB / 1.5 GB / 2 GB [I]) and split raw `.001…`. A job takes an ordered set of up to 64 evidence items, each within the per-request limit. The total is bounded by a setting and the org quota.
  2. **Ingest by reference** (an operator-mounted intake directory read by a trusted importer) removes the per-request bound, but needs a new trusted service with evidence-bucket write and a host path shared by tenants. → "Later", with the design sketch in the plan.
- **Worker disk:**
  - the image is downloaded to the work volume (TSK, libewf and Plaso need random access; HTTP range reads through a block cache are a later optimisation);
  - footprint at analysis time: MinIO copy + `/work` copy + the artifact tree + the Plaso storage file (≈ 2 × image + 3 × artifact budget).
- **Time:**
  - TSK metadata walks are fast (minutes for 500 k entries [I]);
  - hashing reads file contents, so it is budgeted by bytes;
  - Plaso on a bounded artifact set of ≤ 2 GiB should take minutes to tens of minutes in single-process mode [I; the spike measures].

## 10. Open items for the phases (unverified)
1. Whether every Plaso dependency has a cp312 manylinux wheel, and which packages Plaso imports lazily (opensearch-py, redis, pyzmq, requests): the phase-3a spike.
2. Whether `psort.py` opens any socket or forks workers in single-process mode with no analysis plugins: the spike runs it under the kit's AF_UNIX-only seccomp filter.
3. The exact pytsk3 20260715 API for named NTFS streams, `$OrphanFiles` and `TSK_FS_META_FLAG_*` values: phase 2.
4. The RDSv3 schema column names: phase 5.
5. NTFS directory trees for test images (`ntfscp` cannot create directories): the phase-4 spike.
6. Plaso preprocessing on a mirrored directory tree (time zone, users, host name) compared with an image source: the phase-3a spike.
