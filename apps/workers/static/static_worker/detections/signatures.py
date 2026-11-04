"""Signature engines (signature:clamav@1, signature:yara@1) and capa capabilities
(capability:capa@1) as findings.

- ClamAV: `PUA.*` -> medium, `Heuristics.*` -> info, anything else -> high (RT11).
- YARA: rule meta `severity`, default `low`; only allowlisted rules may go above `low`, up
  to the allowlisted ceiling. Unknown values fall back to `low`. The allowlist is keyed on
  the rule file's sha256 (hashed by root) + rule name, so a mounted file that merely reuses
  a baseline file or rule name inherits nothing. Test-rule entries apply only when the
  test rule directory is configured (STATIC_YARA_TEST_RULES).
- capa: only rules in high-risk namespaces that carry an ATT&CK technique become findings
  (capped at `medium`: static capability, not observed behaviour). Plain helpers such as
  "allocate or change RWX memory" (MinGW's runtime does this) stay capability records.
"""

from cyberlab_jobs.static import CapabilityRecord, SignatureMatch

from static_worker.detections.base import (
    HEURISTIC_MAX,
    SEVERITY_RANK,
    Finding,
    Severity,
    cap,
    joined,
    refs,
)

CLAMAV_METHOD = "signature:clamav@1"
YARA_METHOD = "signature:yara@1"
CAPA_METHOD = "capability:capa@1"

YARA_DEFAULT: Severity = "low"
# sha256 of rules/yara/cyberlab_baseline.yar (update together with the file; a unit test
# compares) and of the test-only tests/rules/yara/cyberlab_test.yar.
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

# namespace prefix -> (finding type, severity)
CAPA_HIGH_RISK: tuple[tuple[str, str, Severity], ...] = (
    ("host-interaction/process/inject", "capability_injection", "medium"),
    ("collection/keylog", "capability_keylogging", "medium"),
    ("collection/credentials", "capability_credential_access", "medium"),
    ("collection/password-manager", "capability_credential_access", "medium"),
    ("persistence", "capability_persistence", "medium"),
    ("anti-analysis", "capability_anti_analysis", "low"),
)


def clamav_severity(name: str) -> Severity:
    if name.startswith("PUA."):
        return "medium"
    if name.startswith("Heuristics."):
        return "info"
    return "high"


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


def yara_severity(match: SignatureMatch, ceilings: dict[str, Severity] | None = None) -> Severity:
    claimed = match.meta.get("severity", YARA_DEFAULT).strip().lower()
    if claimed not in SEVERITY_RANK:
        return YARA_DEFAULT
    ceiling = (ceilings or {}).get(f"{match.namespace}:{match.name}", YARA_DEFAULT)
    return cap(claimed, ceiling)  # type: ignore[arg-type]


def signature_findings(
    matches: list[SignatureMatch], ceilings: dict[str, Severity] | None = None
) -> list[Finding]:
    out = []
    for m in matches:
        if m.engine == "clamav":
            out.append(
                Finding(
                    type="av_signature_match",
                    severity=clamav_severity(m.name),
                    confidence=0.9,
                    method=CLAMAV_METHOD,
                    values={"name": m.name},
                    key=m.name,
                    refs=refs([f"clamav:{m.name}"]),
                    attributes={"name": m.name, "engine": "clamav"},
                )  # fmt: skip
            )
        else:
            description = m.meta.get("description", "none")
            out.append(
                Finding(
                    type="yara_match",
                    severity=yara_severity(m, ceilings),
                    confidence=0.8,
                    method=YARA_METHOD,
                    values={
                        "name": m.name,
                        "namespace": m.namespace or "",
                        "description": description,
                    },
                    key=f"{m.namespace}:{m.name}",
                    refs=refs([f"yara:{m.namespace}:{m.name}"]),
                    attributes={
                        "name": m.name,
                        "namespace": (m.namespace or "")[:255],
                        "engine": "yara",
                        "description": description[:255],
                    },
                )  # fmt: skip
            )
    return out


def capability_findings(capabilities: list[CapabilityRecord]) -> list[Finding]:
    groups: dict[str, tuple[Severity, list[CapabilityRecord]]] = {}
    for c in capabilities:
        if not c.attack or not c.namespace:
            continue
        for prefix, kind, severity in CAPA_HIGH_RISK:
            if c.namespace == prefix or c.namespace.startswith(prefix + "/"):
                groups.setdefault(kind, (severity, []))[1].append(c)
                break
    out = []
    for kind, (severity, members) in sorted(groups.items()):
        attack = sorted({a for c in members for a in c.attack})
        names = [c.name for c in members]
        out.append(
            Finding(
                type=kind,
                severity=cap(severity, HEURISTIC_MAX),
                confidence=min(0.9, 0.6 + 0.1 * len(members)),
                method=CAPA_METHOD,
                values={
                    "count": len(members),
                    "rules": joined(names, 900),
                    "attack": joined(attack),
                },
                refs=refs([f"capa:{n}" for n in names]),
                attributes={
                    "rules": joined(names),
                    "attack": joined(attack),
                    "namespaces": joined(sorted({c.namespace or "" for c in members})),
                },
            )  # fmt: skip
        )
    return out
