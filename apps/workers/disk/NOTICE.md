# CyberLab disk forensics analyzer: third-party notices

This image redistributes, **unmodified**, the following components (license texts of every
installed distribution: `/usr/share/doc/cyberlab-disk/licenses/`). Not legal advice.

| Component | Version | License | Source |
|---|---|---|---|
| The Sleuth Kit (statically embedded in the pytsk3 wheel) | 4.15.0 | IBM Public License 1.0 / Common Public License 1.0 (weak copyleft for the library itself) | https://github.com/sleuthkit/sleuthkit |
| pytsk3 | 20260715 | Apache-2.0 | https://github.com/py4n6/pytsk |
| libewf-python (pyewf, libewf) | 20260924 | LGPL-3.0-or-later | https://github.com/libyal/libewf |
| libyal bindings used by Plaso (libevtx, libregf, libfsntfs, libfsext, libfsfat, libbde, libfsapfs, libvsgpt, ...) | per /opt/plaso | LGPL-3.0-or-later | https://github.com/libyal |
| Plaso, dfVFS, dfWinReg, dfDateTime, artifacts | 20261027 / per /opt/plaso | Apache-2.0 | https://github.com/log2timeline |
| yara-python (YARA) | 4.x | Apache-2.0 (YARA: BSD-3-Clause) | https://github.com/VirusTotal/yara-python |

The LGPL libraries are dynamically loaded Python extension modules in their own virtual
environments and remain replaceable by the user. Nothing in TSK, libewf, the libyal bindings or
Plaso is patched. TSK's only GPL file (`srch_strings.c`) is not built into pytsk3, and no GPL
tool is installed in the production image (the test-only image generator tools live in the dev
target).

The CyberLab adapter code (`disk_worker/`, `cyberlab_plaso_launch`, `cyberlab_plaso_export`) is
CyberLab's own and only calls these libraries through their public APIs.
