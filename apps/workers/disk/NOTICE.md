# CyberLab disk forensics analyzer: third-party notices

This image redistributes, **unmodified**, the following components (license texts of every
installed distribution: `/usr/share/doc/cyberlab-disk/licenses/`; this notice:
`/usr/share/doc/cyberlab-disk/NOTICE`). Not legal advice.

| Component | Version | License | Source |
|---|---|---|---|
| The Sleuth Kit (statically embedded in the pytsk3 wheel) | 4.15.0 (the release pytsk3 20260715 bundles) | IBM Public License 1.0 / Common Public License 1.0 (weak copyleft for the library itself) | https://github.com/sleuthkit/sleuthkit/releases/tag/sleuthkit-4.15.0 |
| pytsk3 | 20260715 | Apache-2.0 | https://github.com/py4n6/pytsk (release 20260715); https://pypi.org/project/pytsk3/20260715/ |
| libewf-python (pyewf, libewf) | 20260924 | LGPL-3.0-or-later | https://github.com/libyal/libewf (release 20260924); https://pypi.org/project/libewf-python/20260924/ |
| libyal bindings used by Plaso (libevtx, libregf, libfsntfs, libfsext, libfsfat, libbde, libfsapfs, libvsgpt, ...) | as pinned in `plaso.lock` (installed in /opt/plaso) | LGPL-3.0-or-later | https://github.com/libyal (one repository per library; the release matching the pinned version) |
| Plaso, dfVFS, dfWinReg, dfDateTime, artifacts | plaso 20261027; the others as pinned in `plaso.lock` | Apache-2.0 | https://github.com/log2timeline |
| yara-python (YARA) | 4.x (the M3 pin) | Apache-2.0 (YARA: BSD-3-Clause) | https://github.com/VirusTotal/yara-python, https://github.com/VirusTotal/yara |

The exact installed versions are recorded in the image's `/etc/cyberlab/versions.json`.

The LGPL libraries are dynamically loaded Python extension modules in their own virtual
environments (`/opt/venv`, `/opt/plaso`) and remain replaceable by the user; their source is
available at the links above. Nothing in TSK, libewf, the libyal bindings or Plaso is patched:
the libyal bindings that ship no cp312 wheel are compiled from their unmodified, hash-pinned
source distributions in the image's builder stage, and only the resulting wheels are installed.

**No GPL component is in the production image.** TSK's only GPL file (`srch_strings.c`) is not
built into pytsk3, and the build asserts that no `srch_strings`, `fls`, `icat` or `mmls` binary
and no Debian `sleuthkit`, `python3-tsk` or `ewf-tools` package is present
(`docker/finalize_image.py`). The synthetic image generator's tools, several of them GPL
(dosfstools, mtools, e2fsprogs, exfatprogs, ntfs-3g, fdisk / util-linux, ewf-tools, hivex), are
installed in the **dev / test target only** (`docker/diskgen-packages.txt`), run only at test
time, and are not part of the `prod` target.

The CyberLab adapter code (`disk_worker/`, `cyberlab_plaso_launch`, `cyberlab_plaso_export`) is
CyberLab's own and only calls these libraries through their public APIs. CyberLab's
documentation links to upstream and does not reproduce upstream source.

Known-file hash sets (for example NIST NSRL RDSv3) are not part of this image: an operator
imports them into a local volume, under the terms of whoever supplied them.
