"""YARA rule files, their namespaces and the severity allow-list (M3; lifted into the worker kit
by M9 phase 1, RT8, so the static and disk analyzers share one implementation).

- Rule files: namespaces are `<source>.<file stem>`, source `image` for the baked rule
  directory, `test` for the test-only one. Root hashes the same files (it never parses them)
  so the severity allow-list can be keyed on the rule file's sha256, not on a name a mounted
  file could copy. The probes compile the sources at scan time (no `.yarc`: a compiled file
  has no source sha256 to key the allow-list on).
- Severity: rule meta `severity`, default `low`; only allow-listed rules may go above `low`, up
  to the allow-listed ceiling. Unknown values fall back to `low`. Test-rule entries apply only
  when the test rule directory is configured (test profile only).

`static_worker.rulefiles` and the YARA parts of `static_worker.detections.signatures`
re-export these objects unchanged (shims).
"""

import hashlib
from pathlib import Path
from typing import Literal, Protocol

Severity = Literal["info", "low", "medium", "high"]
SEVERITY_RANK: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3}

SOURCES = ("image", "test")
MAX_RULE_FILE = 64 * 1024**2

YARA_DEFAULT: Severity = "low"
# sha256 of apps/workers/static/rules/yara/cyberlab_baseline.yar (update together with the
# file; the static unit test compares, and the disk image build asserts it, RT8) and of the
# test-only apps/workers/static/tests/rules/yara/cyberlab_test.yar.
BASELINE_SHA256 = "ee13bafb7a0ec8c90670fc7388549f817c3d7d8b6ec37ac4baac2d9cb0cf8599"
TEST_RULES_SHA256 = "df6bb6fd2829e4d0a69845bc827b267f076923e9e79bad813cbafdf2a1018baa"
# (rule file sha256, rule name) -> highest severity the rule's own meta may claim.
YARA_SEVERITY_ALLOWLIST: dict[tuple[str, str], Severity] = {
    (BASELINE_SHA256, "CyberLab_Embedded_PE_In_Overlay"): "medium",
    (BASELINE_SHA256, "CyberLab_Embedded_PE_In_Resource"): "medium",
}
YARA_TEST_ALLOWLIST: dict[tuple[str, str], Severity] = {
    (TEST_RULES_SHA256, "CyberLab_Test_Marker"): "medium",
}


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


def cap(severity: Severity, ceiling: Severity) -> Severity:
    return severity if SEVERITY_RANK[severity] <= SEVERITY_RANK[ceiling] else ceiling


def yara_ceilings(rule_hashes: dict[str, str], *, test_rules: bool) -> dict[str, Severity]:
    """ "<namespace>:<rule>" -> ceiling, for the rule files this job actually loaded.

    `rule_hashes`: namespace -> sha256 of its rule file, computed by root.
    """
    allowlist = YARA_SEVERITY_ALLOWLIST | (YARA_TEST_ALLOWLIST if test_rules else {})
    return {
        f"{namespace}:{rule}": ceiling
        for namespace, sha256 in rule_hashes.items()
        for (allowed_sha256, rule), ceiling in allowlist.items()
        if sha256 == allowed_sha256
    }


class YaraMatch(Protocol):
    """What `yara_severity` reads of a match (`cyberlab_jobs.static.SignatureMatch` fits)."""

    @property
    def name(self) -> str: ...

    @property
    def namespace(self) -> str | None: ...

    @property
    def meta(self) -> dict[str, str]: ...


def yara_severity(match: YaraMatch, ceilings: dict[str, Severity] | None = None) -> Severity:
    claimed = match.meta.get("severity", YARA_DEFAULT).strip().lower()
    if claimed not in SEVERITY_RANK:
        return YARA_DEFAULT
    ceiling = (ceilings or {}).get(f"{match.namespace}:{match.name}", YARA_DEFAULT)
    return cap(claimed, ceiling)  # type: ignore[arg-type]


__all__ = [
    "BASELINE_SHA256",
    "MAX_RULE_FILE",
    "SEVERITY_RANK",
    "SOURCES",
    "TEST_RULES_SHA256",
    "YARA_DEFAULT",
    "YARA_SEVERITY_ALLOWLIST",
    "YARA_TEST_ALLOWLIST",
    "Severity",
    "YaraMatch",
    "cap",
    "rule_files",
    "rule_hashes",
    "yara_ceilings",
    "yara_severity",
]
