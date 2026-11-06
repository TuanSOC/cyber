#!/bin/sh
# Trim a verified Ghidra install by DELETION ONLY (M10 phase 1; PROVISIONAL until the phase-2
# spike reports the final list). Every LICENSE* file and licenses/ directory is copied to
# $2 (path-preserving) BEFORE anything is deleted, so the texts of removed modules stay in the
# image (/usr/share/doc/cyberlab-re/licenses). Nothing is patched or added.
#
#   trim-ghidra.sh /opt/ghidra /licenses
set -eu

GHIDRA="$1"
LICENSES="$2"
[ -f "$GHIDRA/Ghidra/application.properties" ] || { echo "not a Ghidra install: $GHIDRA" >&2; exit 1; }

mkdir -p "$LICENSES"
cd "$GHIDRA"
find . \( -name 'LICENSE*' -o -name 'NOTICE*' -o -path '*/licenses/*' \) -type f \
  | while read -r file; do
      mkdir -p "$LICENSES/$(dirname "$file")"
      cp -p "$file" "$LICENSES/$file"
    done

# Processors: x86 and DATA only (ARM, MIPS, PowerPC, ... go to ROADMAP "Later").
for dir in Ghidra/Processors/*; do
  case "$(basename "$dir")" in
    x86|DATA) ;;
    *) rm -rf "$dir" ;;
  esac
done

# No Jython (no script runtime), no debugger, no Ghidra Server, no docs, no bundled extensions
# (PyGhidra must find no plugin to install, RT1).
rm -rf \
  Ghidra/Features/Jython \
  Ghidra/Debug \
  server \
  docs \
  Extensions/Ghidra \
  Extensions/Eclipse \
  Extensions/IDAPro

# Must remain: the decompiler native binary (the decompile stage) and PyGhidra's wheel.
[ -x Ghidra/Features/Decompiler/os/linux_x86_64/decompile ] \
  || { echo "decompiler binary missing after the trim" >&2; exit 1; }
ls Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-*.whl >/dev/null \
  || { echo "PyGhidra wheel missing after the trim" >&2; exit 1; }
