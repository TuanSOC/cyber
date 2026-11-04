"""Shared pieces of the static detectors.

Findings describe *what is present* in the file (API sets, packer traits, anomalies,
signature and capability matches) with the measured values behind them. They never call a
file malicious: every title / description comes from the templates below, which a test
checks for verdict wording. Engine-supplied names (ClamAV / YARA / capa) are inserted
verbatim into placeholders and are labelled as such.

Severity policy (plan RT11 / phase 3):
- imports, entropy, structure and capability heuristics: at most `medium`;
- only signature engines (ClamAV; YARA only for allowlisted rules) may yield `high`.
"""

import uuid
from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["info", "low", "medium", "high"]
SEVERITY_RANK: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3}
HEURISTIC_MAX: Severity = "medium"
FINDING_NAMESPACE = uuid.UUID("0b6d6f3e-6f1a-4c55-8d0e-5a7a3c1e9b42")
MAX_REFS = 50

# type -> (title template, description template). Every finding text comes from here.
TEMPLATES: dict[str, tuple[str, str]] = {
    "api_injection": (
        "Process-injection API set imported",
        "The import table contains APIs that together can allocate memory in, write to and "
        "start code in another process: {apis}. Legitimate debuggers and some security "
        "tools use the same set; review how the calls are used.",
    ),
    "api_keylogging": (
        "Keyboard hook / key-state API set imported",
        "The import table combines keyboard hooking or raw-input registration with key-state "
        "polling: {apis}. This combination can record keystrokes; accessibility and hotkey "
        "tools also use it.",
    ),
    "api_anti_debug": (
        "Debugger-detection API set imported",
        "The import table combines debugger checks with process-information queries: {apis}. "
        "These can be used to change behaviour under analysis.",
    ),
    "api_credential_access": (
        "Credential-store access API set imported",
        "The import table combines APIs that read stored credentials, protected data or "
        "process memory dumps: {apis}. Password managers and backup tools use some of these.",
    ),
    "api_persistence": (
        "Persistence API set present",
        "The file can register itself to start automatically: {apis}. Installers and "
        "services do this legitimately.",
    ),
    "api_downloader": (
        "Download-and-execute API set imported",
        "The import table combines fetching content from a URL with starting a program: "
        "{apis}. Updaters and installers use the same pattern.",
    ),
    "packer_indicators": (
        "Packer / compression indicators ({count})",
        "Structural traits typical of packed or compressed executables: {indicators}. "
        "Packing hides the real code from static analysis; it is also used to shrink "
        "legitimate programs.",
    ),
    "timestamp_anomaly": (
        "Implausible compile timestamp",
        "The PE header timestamp is {timestamp} ({reason}). Timestamps are easily set to any "
        "value, so this only says the header was not written by a normal build.",
    ),
    "tls_callbacks": (
        "TLS callbacks present ({count})",
        "The PE registers {count} TLS callback(s), which run before the entry point. Common "
        "in MinGW / Delphi runtimes; also used to run code early.",
    ),
    "high_entropy_resource": (
        "High-entropy resources ({count})",
        "{count} resource(s) have entropy above {threshold} (largest: {largest} bytes), "
        "consistent with compressed or encrypted embedded data.",
    ),
    "overlay": (
        "Overlay data after the last section ({size} bytes)",
        "{size} bytes follow the last section (entropy of the whole file: {entropy}). "
        "Installers and self-extracting archives store payloads this way.",
    ),
    "av_signature_match": (
        "ClamAV signature match: {name}",
        "ClamAV reported the signature {name} (engine-supplied name) for this file. Review "
        "the signature and the file before drawing conclusions; test signatures and "
        "potentially-unwanted-application signatures are included.",
    ),
    "yara_match": (
        "YARA rule match: {name}",
        "The YARA rule {namespace}:{name} (rule-supplied description: {description}) "
        "matched this file.",
    ),
    "capability_injection": (
        "capa: process-injection capabilities ({count})",
        "capa found code patterns for: {rules} (ATT&CK {attack}). Static capability "
        "detection; the code was not observed running.",
    ),
    "capability_keylogging": (
        "capa: keystroke-capture capabilities ({count})",
        "capa found code patterns for: {rules} (ATT&CK {attack}). Static capability "
        "detection; the code was not observed running.",
    ),
    "capability_anti_analysis": (
        "capa: anti-analysis capabilities ({count})",
        "capa found code patterns for: {rules} (ATT&CK {attack}). Static capability "
        "detection; the code was not observed running.",
    ),
    "capability_persistence": (
        "capa: persistence capabilities ({count})",
        "capa found code patterns for: {rules} (ATT&CK {attack}). Static capability "
        "detection; the code was not observed running.",
    ),
    "capability_credential_access": (
        "capa: credential-access capabilities ({count})",
        "capa found code patterns for: {rules} (ATT&CK {attack}). Static capability "
        "detection; the code was not observed running.",
    ),
}


def cap(severity: Severity, ceiling: Severity) -> Severity:
    return severity if SEVERITY_RANK[severity] <= SEVERITY_RANK[ceiling] else ceiling


@dataclass
class Finding:
    """Detector output before it becomes a `finding` result line."""

    type: str
    severity: Severity
    confidence: float
    method: str
    values: dict[str, object]
    key: str = ""  # discriminates several findings of one type (stable id)
    refs: list[str] = field(default_factory=list)
    attributes: dict[str, str | int | float | bool] = field(default_factory=dict)

    @property
    def title(self) -> str:
        return TEMPLATES[self.type][0].format(**self.values)[:255]

    @property
    def description(self) -> str:
        return TEMPLATES[self.type][1].format(**self.values)[:2048]

    def finding_id(self, job_id: uuid.UUID) -> uuid.UUID:
        """Stable: the same observation in the same job always gets the same id."""
        return uuid.uuid5(FINDING_NAMESPACE, f"{job_id}|{self.method}|{self.type}|{self.key}")


def refs(values: list[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        ref = value[:64]
        if ref and ref not in out:
            out.append(ref)
            if len(out) >= MAX_REFS:
                break
    return out


def joined(values: list[str], limit: int = 255) -> str:
    text = ", ".join(values)
    return text if len(text) <= limit else text[: limit - 3] + "..."
