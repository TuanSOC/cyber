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
# M9 phase 1 (RT8): the YARA allow-list lives in the worker kit, shared with the disk analyzer;
# re-exported here unchanged.
from cyberlab_worker.yara_rules import (  # noqa: F401 - re-exports (shim)
    BASELINE_SHA256,
    TEST_RULES_SHA256,
    YARA_DEFAULT,
    YARA_SEVERITY_ALLOWLIST,
    YARA_TEST_ALLOWLIST,
    yara_ceilings,
    yara_severity,
)

from static_worker.detections.base import (
    HEURISTIC_MAX,
    Finding,
    Severity,
    cap,
    joined,
    refs,
)

CLAMAV_METHOD = "signature:clamav@1"
YARA_METHOD = "signature:yara@1"
CAPA_METHOD = "capability:capa@1"

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
