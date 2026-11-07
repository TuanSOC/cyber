"""Shared pieces of the RE detections (M10 phase 5): methods, severity ceilings, templates,
API-name normalization and the per-function facts every rule reads from `ReView`.

Findings describe what one function does in the static program (which APIs it calls, which
strings it references), with the measured values. They never call the program malicious:
every title and description comes from `TEMPLATES` (checked for verdict words by
`tests/unit/test_finding_wording.py`), and function names are engine-supplied, attacker-
chosen text, so they appear only quoted and attributed ("named "x" by the engine"). Every
heuristic is capped at `medium` (`METHOD_MAX`).
"""

import re
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from cyberlab_jobs.results import FindingRecord

from re_worker.view import ReView

Severity = Literal["info", "low", "medium", "high"]
SEVERITY_RANK: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3}

METHOD_API_SET = "heuristic:re_api_set_function@1"
METHOD_RESOLUTION = "heuristic:re_runtime_api_resolution@1"
METHOD_NETWORK = "heuristic:re_network_string_function@1"
METHOD_MAX: dict[str, Severity] = {
    METHOD_API_SET: "medium",
    METHOD_RESOLUTION: "medium",
    METHOD_NETWORK: "low",
}
FINDING_NAMESPACE = uuid.UUID("5d3c2b1a-7e6f-4a8b-9c0d-1e2f3a4b5c6d")
MAX_REFS = 50
TITLE_NAME_CHARS = 64

# The M3 set types, worded for a title ("calls the <label> API combination").
SET_LABELS: dict[str, str] = {
    "api_injection": "process-injection",
    "api_keylogging": "keyboard-hook / key-state",
    "api_anti_debug": "debugger-detection",
    "api_credential_access": "credential-store access",
    "api_persistence": "persistence",
    "api_downloader": "download-and-execute",
}

_API_SET_TEXT = (
    'Function "{name}" calls the {set_label} API combination',
    'The function at {entry} (named "{full_name}" by the engine) calls {apis}, directly or '
    "through import thunks: every group of one {set_label} combination ({groups}) is present "
    "in this single function. Debuggers, installers and security tools use the same APIs; "
    "read the function before drawing conclusions. Static observation, the code was not run.",
)
# type -> (method, title template, description template). Every finding text comes from here.
TEMPLATES: dict[str, tuple[str, str, str]] = {
    **{kind: (METHOD_API_SET, *_API_SET_TEXT) for kind in SET_LABELS},
    "runtime_api_resolution": (
        METHOD_RESOLUTION,
        'Function "{name}" resolves APIs by name at run time',
        'The function at {entry} (named "{full_name}" by the engine) calls {resolvers} and '
        "references {count} strings that are exact API names: {names}.{set_note} Resolving "
        "APIs at run time keeps them out of the import table; plug-in hosts, loaders and "
        "compatibility shims do the same. Static observation, the code was not run.",
    ),
    "network_string_function": (
        METHOD_NETWORK,
        'Function "{name}" references a network address and calls network APIs',
        'The function at {entry} (named "{full_name}" by the engine) references {indicators} '
        "and calls {apis}. Updaters, telemetry and licence checks do the same; the addresses "
        "are listed as IOCs. Static observation, the code was not run.",
    ),
}

_DECORATION_RE = re.compile(r"@\d+$")
_PREFIXES = ("sym.imp.", "__imp__", "__imp_", "_imp__", "imp.")


def cap(severity: Severity, ceiling: Severity) -> Severity:
    return severity if SEVERITY_RANK[severity] <= SEVERITY_RANK[ceiling] else ceiling


def joined(values: Iterable[str], limit: int = 255) -> str:
    text = ", ".join(values)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def shown(name: str, limit: int) -> str:
    """An engine-supplied name cut for display (the full value stays in the records)."""
    return name if len(name) <= limit else name[: limit - 1] + "…"


def hex_address(value: int) -> str:
    return f"0x{value:x}"


def api_name(raw: str, known: frozenset[str]) -> str:
    """An import / thunk name as the plain API name: `__imp_X`, `__imp__X@8`, `X@plt`,
    radare2's `sym.imp.KERNEL32.dll_X` and i386 `_X` (when `X` is known) become `X`."""
    name = raw
    for prefix in _PREFIXES:
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    lowered = name.lower()
    if ".dll_" in lowered:
        name = name[lowered.index(".dll_") + 5 :]
    name = _DECORATION_RE.sub("", name.split("@plt", 1)[0])
    if name not in known and name.startswith("_") and name[1:] in known:
        name = name[1:]
    return name


def eligible(view: ReView, entry: int) -> bool:
    """Findings and priority classes 2-6 never cite thunks, externals or library code."""
    f = view.functions[entry]
    return not (f.is_thunk or f.is_external or f.is_library)


def called_api_names(view: ReView, entry: int, known: frozenset[str]) -> frozenset[str]:
    """The APIs a function calls: its import references, plus the names of the thunk /
    external functions it calls (and what those thunks reference), normalized."""
    names = {api_name(n, known) for n in view.import_names_called(entry)}
    for callee in view.callees(entry):
        target = view.functions.get(callee)
        if target is None or not (target.is_thunk or target.is_external):
            continue
        names.add(api_name(target.name, known))
        if target.is_thunk:
            names.update(api_name(n, known) for n in view.import_names_called(callee))
            for inner in view.callees(callee):
                deeper = view.functions.get(inner)
                if deeper is not None and (deeper.is_thunk or deeper.is_external):
                    names.add(api_name(deeper.name, known))
    return frozenset(names)


@dataclass
class Finding:
    """Detector output before it becomes a `finding` line."""

    type: str
    entry: int
    severity: Severity
    confidence: float
    values: dict[str, object]
    refs: list[str] = field(default_factory=list)
    attributes: dict[str, str | int | float | bool] = field(default_factory=dict)

    @property
    def method(self) -> str:
        return TEMPLATES[self.type][0]

    def record(self, program_sha256: str, ts: datetime) -> FindingRecord:
        method, title, description = TEMPLATES[self.type]
        refs = [f"function:{hex_address(self.entry)}"]
        for ref in self.refs:
            if ref[:64] not in refs and len(refs) < MAX_REFS:
                refs.append(ref[:64])
        return FindingRecord(
            finding_id=uuid.uuid5(
                FINDING_NAMESPACE, f"{program_sha256}|{method}|{self.type}|{self.entry}"
            ),
            ts=ts,
            type=self.type,
            title=title.format(**self.values)[:255],
            description=description.format(**self.values)[:2048],
            severity=cap(self.severity, METHOD_MAX[method]),
            confidence=round(self.confidence, 3),
            detection_method=method,
            evidence_refs=refs,
            attributes={k[:64]: v for k, v in list(self.attributes.items())[:20]},
        )


def name_values(view: ReView, entry: int) -> dict[str, object]:
    name = view.functions[entry].name
    return {
        "name": shown(name, TITLE_NAME_CHARS),
        "full_name": shown(name, 255),
        "entry": hex_address(entry),
    }


def base_attributes(view: ReView, entry: int) -> dict[str, str | int | float | bool]:
    return {"function_entry": hex_address(entry), "function_name": view.functions[entry].name}
