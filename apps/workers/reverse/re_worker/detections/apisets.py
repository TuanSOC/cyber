"""`heuristic:re_api_set_function@1` (M10 phase 5, RT7): an M3 suspicious API set fires
**within one function**, with the M3 semantics read from `cyberlab_worker.apisets` (no copy):
every group of one `any_of` combination has at least one API the function calls, directly
or through a thunk (A / W variants as M3 lists them). The pseudo-API `string:run_key` counts
when the function references a Run / RunOnce registry-path string. Groups split across two
functions never fire (the M3 file-level rule would). Severity: the set's, capped at `medium`.
"""

from cyberlab_worker.apisets import API_SETS, RUN_KEY_FLAG, ApiSet
from cyberlab_worker.iocs import has_run_key

from re_worker.detections.base import (
    SET_LABELS,
    Finding,
    base_attributes,
    joined,
    name_values,
)
from re_worker.view import ReView

RUN_KEY_EVIDENCE = "a Run-key registry path it references"


def references_run_key(view: ReView, entry: int) -> bool:
    return any(has_run_key(view.strings[i].value) for i in view.strings_referenced(entry))


def matches(api_set: ApiSet, names: frozenset[str]) -> tuple[list[str], list[str]] | None:
    """(groups, matched APIs) of the firing combinations, or None (M3 `detect` semantics)."""
    present = {group: sorted(apis & names) for group, apis in api_set.groups.items()}
    combos = [c for c in api_set.any_of if all(present[g] for g in c)]
    if not combos:
        return None
    groups = sorted(set().union(*combos))
    return groups, [api for g in groups for api in present[g]]


def detect(view: ReView, entry: int, names: frozenset[str]) -> list[Finding]:
    """`names`: the APIs the function calls (normalized); the run-key flag is added here."""
    if references_run_key(view, entry):
        names = names | {RUN_KEY_FLAG}
    findings = []
    for api_set in API_SETS:
        found = matches(api_set, names)
        if found is None:
            continue
        groups, matched = found
        apis = [api for api in matched if api != RUN_KEY_FLAG]
        evidence = apis + ([RUN_KEY_EVIDENCE] if RUN_KEY_FLAG in matched else [])
        label = SET_LABELS[api_set.type]
        findings.append(
            Finding(
                type=api_set.type,
                entry=entry,
                severity=api_set.severity,
                confidence=min(0.9, api_set.confidence + 0.05 * (len(matched) - len(groups))),
                values={
                    **name_values(view, entry),
                    "set_label": label,
                    "apis": joined(evidence, 900),
                    "groups": joined(groups, 300),
                },
                refs=[f"import:{api}" for api in apis],
                attributes={
                    **base_attributes(view, entry),
                    "set": api_set.type,
                    "groups": joined(groups),
                    "apis": joined(evidence),
                    "api_count": len(apis),
                },
            )
        )
    return findings
