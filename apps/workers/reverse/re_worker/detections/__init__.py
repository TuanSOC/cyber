"""RE detections (M10 phase 5; the signature `run(view, limits) -> DetectionOutput` is frozen
in phase 1).

Three verdict-free, function-level heuristics over the validated `ReView`, each capped at
`medium` and citing its function in `attributes.function_entry` (`0x…`):
`heuristic:re_api_set_function@1` (`apisets.py`), `heuristic:re_runtime_api_resolution@1`
and `heuristic:re_network_string_function@1` (`rules.py`); plus the IOCs (URL / domain / IP)
of strings referenced by code (`iocs.py`). Thunks, externals and FID library functions are
never cited. Deterministic: findings are ordered by severity, method, entry and type, and
their ids are uuid5 of (program sha256, method, type, entry). Findings and IOCs carry the
analysis time (`now()`; static analysis has no event time, as in M3).
"""

from datetime import UTC, datetime

from cyberlab_jobs.reverse import ReLimits

from re_worker.detections import apisets, iocs, rules
from re_worker.detections.api_names import API_NAMES
from re_worker.detections.base import (
    METHOD_MAX,
    SEVERITY_RANK,
    Finding,
    called_api_names,
    eligible,
)
from re_worker.view import DetectionOutput, ReView

KNOWN_APIS = API_NAMES | rules.RESOLVERS | rules.NETWORK_APIS
StringIocs = dict[int, list[tuple[str, str, int]]]


def now() -> datetime:
    return datetime.now(UTC)


def raw_findings(view: ReView, per_string: StringIocs) -> list[Finding]:
    found: list[Finding] = []
    for entry in view.functions:
        if not eligible(view, entry):
            continue
        names = called_api_names(view, entry, KNOWN_APIS)
        found += apisets.detect(view, entry, names)
        if (resolution := rules.runtime_resolution(view, entry, names, API_NAMES)) is not None:
            found.append(resolution)
        indicators = sorted(
            {value for i in view.strings_referenced(entry) for _, value, _ in per_string.get(i, [])}
        )
        if (network := rules.network_string(view, entry, names, indicators)) is not None:
            found.append(network)
    return found


def run(view: ReView, limits: ReLimits) -> DetectionOutput:
    ts = now()
    per_string = iocs.string_iocs(view)
    found = raw_findings(view, per_string)
    found.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.method, f.entry, f.type))
    kept = found[: limits.max_findings]
    findings = [f.record(view.program.sha256, ts) for f in kept]
    table, capped = iocs.collect(view, limits.max_iocs, per_string)
    return DetectionOutput(
        findings=findings,
        iocs=iocs.records(table, ts),
        truncated=capped or len(found) > len(kept),
    )


__all__ = ["METHOD_MAX", "run"]
