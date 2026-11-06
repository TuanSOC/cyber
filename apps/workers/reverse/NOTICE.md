# CyberLab reverse-engineering worker: third-party notices

This image runs, unmodified except for the deletions listed below, the following software. It
is built for the operator's own use; redistributing the image carries the source obligations
of the GPL / LGPL components (not legal advice; see docs/REVERSE_ENGINEERING.md, phase 11).

| Component | Version | License | Use |
|---|---|---|---|
| Ghidra | 12.2 | Apache-2.0 (native helpers: their own texts, kept) | headless analysis and decompilation, library mode |
| PyGhidra | 3.2.x (the wheel bundled in the Ghidra zip) | Apache-2.0 | starts the JVM from Python |
| JPype1 | 1.6.0 | Apache-2.0 | Python / Java bridge |
| Eclipse Temurin JDK | 25 | GPLv2 with the Classpath Exception | runs Ghidra |
| radare2 | 6.2.6 | LGPL-3.0 | optional `quick` profile, a separate process |

**Modification notice (Ghidra).** The Ghidra install in `/opt/ghidra` was modified by
deleting files only (`docker/trim-ghidra.sh`): every processor module but `x86` and `DATA`,
`Ghidra/Features/Jython`, `Ghidra/Debug`, `server/`, `docs/` and the bundled extensions; and
`support/launch.properties` was replaced by CyberLab's copy (JVM arguments). Every license and
notice text, including those of deleted modules, is kept under
`/usr/share/doc/cyberlab-re/licenses/`.

The CyberLab adapter code in `re_worker/` is CyberLab's own and only drives these tools; samples
are never executed (no debugger, no emulation).
