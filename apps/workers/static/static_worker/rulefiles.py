"""YARA rule files and their namespaces (shared by the yara probe and the root process).

Namespaces are `<source>.<file stem>`: source `image` for the baked rule directory, `test` for
the test-only one. Root hashes the same files (it never parses them) so the severity
allowlist can be keyed on the rule file's sha256, not on a name a mounted file could copy.
"""

import hashlib
from pathlib import Path

SOURCES = ("image", "test")
MAX_RULE_FILE = 64 * 1024**2


def rule_files(directories: list[Path]) -> dict[str, Path]:
    """namespace -> rule file, in a stable order (`*.yar`, `*.yara`, sorted)."""
    files: dict[str, Path] = {}
    for source, directory in zip(SOURCES, directories, strict=False):
        if not directory.is_dir():
            continue
        for path in sorted([*directory.glob("*.yar"), *directory.glob("*.yara")]):
            files[f"{source}.{path.stem}"[:128]] = path
    return files


def rule_hashes(directories: list[Path]) -> dict[str, str]:
    """namespace -> sha256 of the rule file (files that cannot be read are left out)."""
    hashes: dict[str, str] = {}
    for namespace, path in rule_files(directories).items():
        try:
            with open(path, "rb") as f:
                hashes[namespace] = hashlib.sha256(f.read(MAX_RULE_FILE)).hexdigest()
        except OSError:
            continue
    return hashes
