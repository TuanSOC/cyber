# CyberLab reverse-engineering analyzer: third-party notices

This image runs the following third-party components (this notice: `/usr/share/doc/cyberlab-re/NOTICE`; licence texts under `/usr/share/doc/cyberlab-re/`, see below). The exact installed versions and the SHA-256 / digest of each downloaded artefact are recorded in the image's `/etc/cyberlab/versions.json`. Not legal advice.

| Component | Version | License | Source |
|---|---|---|---|
| Ghidra | 12.2 (`ghidra_12.2_PUBLIC_20261016.zip`, SHA-256-pinned) | Apache-2.0, with Ghidra's NOTICE; bundled third-party files and native helpers under their own licences (texts kept) | https://github.com/NationalSecurityAgency/ghidra (tag `Ghidra_12.2_build`) |
| PyGhidra | 3.2.x (the wheel bundled in the Ghidra zip, installed with `--no-deps --no-index`) | Apache-2.0 | https://github.com/NationalSecurityAgency/ghidra/tree/Ghidra_12.2_build/Ghidra/Features/PyGhidra |
| JPype1 | 1.6.0 | Apache-2.0 | https://github.com/jpype-project/jpype ; https://pypi.org/project/JPype1/1.6.0/ |
| Eclipse Temurin JDK | 25 (`eclipse-temurin:25-jdk-noble`, digest-pinned) | GPLv2 with the Classpath Exception (and the third-party notices in its `legal/` directory) | https://adoptium.net/temurin/ ; source: https://github.com/adoptium/jdk25u |
| radare2 | 6.2.6 (`radare2_6.2.6_amd64.deb`, SHA-256-pinned) | LGPL-3.0 (some parts under other permissive licences, per its copyright file) | https://github.com/radareorg/radare2/releases/tag/6.2.6 (source tarball on the same page) |

Licence texts in the image (`docker/trim-ghidra.sh`, `docker/finalize_image.py`): **every** `LICENSE*`, `NOTICE*` and `licenses/` file of the Ghidra install, including those of the modules deleted below, path-preserving under `licenses/` (staged before anything is deleted; the build fails if they are missing); the top-level licence and NOTICE files of Ghidra and the JDK (`ghidra-<name>`, `openjdk-<name>`); the JDK's `legal/` directory (`jdk-legal/`); radare2's Debian copyright file (`radare2-copyright`).

**Modification notice (Ghidra).** The Ghidra install in `/opt/ghidra` was modified **by deleting files only** (`docker/trim-ghidra.sh`; the list is provisional until the M10 phase-2 spike reports): every processor module under `Ghidra/Processors/` except `x86` and `DATA`; `Ghidra/Features/Jython`; `Ghidra/Debug`; `server/`; `docs/`; the bundled extensions `Extensions/Ghidra`, `Extensions/Eclipse` and `Extensions/IDAPro`. Its `support/launch.properties` was replaced by CyberLab's copy (`docker/launch.properties`: JVM arguments only). No Ghidra file is patched and nothing is added to the install. The native decompiler and Ghidra's other native helpers, some under licences other than Apache-2.0, are kept unmodified with their licence texts.

**radare2** is installed unmodified from the upstream release package and runs only as a separate process (`radare2 -q -NN -S -2 -i /opt/re/r2/quick.r2 <sample>`); CyberLab does not link to it and does not use r2pipe (the image build fails if r2pipe is importable).

**What this means (not legal advice).**
- **Running the image for your own use** (including the platform you operate for your own organization) brings no source obligation.
- **Redistributing the image** to third parties brings the source obligations of its copyleft parts: the GPLv2 + Classpath Exception JDK (the Temurin source of the pinned build) and the LGPL-3.0 radare2 (the 6.2.6 source tarball), plus Apache-2.0's notice and modification-notice requirements for Ghidra (this file; the Ghidra source tag `Ghidra_12.2_build` for completeness). Ship this notice, the licence texts under `/usr/share/doc/cyberlab-re/` and the source links above with the image.
- **Unlike M8's Volatility Software License**, none of these licences requires publishing CyberLab's own adapter code in `re_worker/`, which only drives the tools through PyGhidra's public API and radare2's command line.
- The **dev / test target** also installs gcc, mingw-w64 (x86 and x64) and binutils (GPL, from Debian) to compile the synthetic samples at test time; they are **not** in the `prod` target (`finalize_image.py --target prod` fails if a compiler is present).

The CyberLab adapter code in `re_worker/` is CyberLab's own. **Samples are never executed**: no debugger, no emulator, no ESIL. The image ships no third-party binary or sample corpus; the synthetic samples are compiled from this repository's sources at test time only. CyberLab's documentation links to upstream and does not reproduce upstream source.
