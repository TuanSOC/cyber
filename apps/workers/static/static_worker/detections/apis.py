"""Suspicious API *sets* (heuristic:suspicious_api@1).

Each category fires only on a combination of API groups (`any_of`: every group of one
combination present), never on a single API: one API name says nothing on its own. Import
evidence alone is capped at `medium`.
"""

from cyberlab_worker.apisets import API_SETS, RUN_KEY_FLAG, ApiSet

from static_worker.detections.base import HEURISTIC_MAX, Finding, cap, joined, refs

METHOD = "heuristic:suspicious_api@1"
# M10 phase 1 (RT7): `ApiSet`, `API_SETS` and `RUN_KEY_FLAG` live in `cyberlab_worker.apisets`
# (shared with the RE worker); re-exported here unchanged.
__all__ = ["API_SETS", "METHOD", "RUN_KEY_FLAG", "ApiSet", "detect"]


def detect(apis: set[str]) -> list[Finding]:
    """`apis`: imported function names (plus pseudo-API flags such as RUN_KEY_FLAG)."""
    findings = []
    for api_set in API_SETS:
        present = {name: sorted(group & apis) for name, group in api_set.groups.items()}
        combos = [c for c in api_set.any_of if all(present[g] for g in c)]
        if not combos:
            continue
        groups = sorted(set().union(*combos))
        matched = [api for g in groups for api in present[g] if api != RUN_KEY_FLAG]
        evidence = matched + (["Run-key path in strings"] if RUN_KEY_FLAG in apis else [])
        findings.append(
            Finding(
                type=api_set.type,
                severity=cap(api_set.severity, HEURISTIC_MAX),
                confidence=min(0.9, api_set.confidence + 0.05 * (len(matched) - len(groups))),
                method=METHOD,
                values={"apis": joined(evidence, 900)},
                refs=refs([f"import:{api}" for api in matched]),
                attributes={
                    "apis": joined(evidence),
                    "api_count": len(matched),
                    "groups": joined(groups),
                },
            )
        )
    return findings
