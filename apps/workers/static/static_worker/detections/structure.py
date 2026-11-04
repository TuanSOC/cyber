"""Structure heuristics: packer indicators (heuristic:packer@1) and PE anomalies
(heuristic:pe_anomaly@1). Entropy / structure evidence is capped at `medium`."""

import time
from dataclasses import dataclass, field

from cyberlab_jobs.static import PeInfo, ResourceRecord, SectionRecord

from static_worker.detections.base import HEURISTIC_MAX, Finding, cap, joined, refs

PACKER_METHOD = "heuristic:packer@1"
ANOMALY_METHOD = "heuristic:pe_anomaly@1"

PACKER_SECTIONS = {
    "upx0", "upx1", "upx2", "upx!", ".aspack", ".adata", ".nsp0", ".nsp1", ".nsp2", ".mpress1",
    ".mpress2", ".petite", ".themida", ".vmp0", ".vmp1", ".vmp2", ".packed", ".rlpack", "pec2",
    "pecompact2", ".perplex", ".yp", ".y0da", "fsg!", ".enigma1", ".enigma2", "mew", ".mew",
    ".pebundle", ".winlice", ".boom", "kkrunchy", ".spack", ".svkp", "pelock", ".pelock",
}  # fmt: skip
TEXT_LIKE = {".text", "code", ".code", "text", ".itext"}
HIGH_ENTROPY = 7.2
MIN_ENTROPY_BYTES = 512
TINY_IMPORTS = 5
RAW_RATIO = 10
MIN_VIRTUAL = 0x10000
EARLIEST_TS = 788_918_400  # 1995-01-01
FUTURE_SLACK_S = 86_400
RESOURCE_ENTROPY = 7.5
MIN_RESOURCE_BYTES = 1024
# Image resources are compressed (PNG icons): high entropy there is normal.
IMAGE_RESOURCES = {"RT_ICON", "RT_GROUP_ICON", "RT_CURSOR", "RT_GROUP_CURSOR", "RT_BITMAP"}
SIGNIFICANT_OVERLAY = 4096


@dataclass
class Structure:
    file_format: str
    size: int
    entropy: float
    pe: PeInfo | None = None
    sections: list[SectionRecord] = field(default_factory=list)
    resources: list[ResourceRecord] = field(default_factory=list)
    imports: set[str] = field(default_factory=set)
    import_count: int = 0


def packer(s: Structure) -> list[Finding]:
    found: dict[str, str] = {}  # indicator -> evidence
    names = [sec.name for sec in s.sections]
    known = [n for n in names if n.lower().rstrip("\x00 ") in PACKER_SECTIONS]
    if known:
        found["packer_section_names"] = joined(known)
    hot = [
        sec for sec in s.sections
        if "execute" in sec.flags and sec.entropy > HIGH_ENTROPY
        and sec.raw_size >= MIN_ENTROPY_BYTES
    ]  # fmt: skip
    if hot:
        found["high_entropy_code"] = joined([f"{h.name} ({h.entropy:.2f})" for h in hot])
    hollow = [
        sec for sec in s.sections
        if "execute" in sec.flags and sec.virtual_size >= MIN_VIRTUAL
        and sec.raw_size * RAW_RATIO < sec.virtual_size
    ]  # fmt: skip
    if hollow:
        found["raw_much_smaller_than_virtual"] = joined(
            [f"{h.name} (raw {h.raw_size} / virtual {h.virtual_size})" for h in hollow]
        )
    if s.pe is not None:
        loaders = {"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"}
        if s.import_count < TINY_IMPORTS and s.imports & loaders and "GetProcAddress" in s.imports:
            found["tiny_import_table"] = (
                f"{s.import_count} imports incl. LoadLibrary/GetProcAddress"
            )
        entry = s.pe.entry_section
        if entry is None and s.pe.entry_point and not s.pe.is_dll:
            found["entry_outside_sections"] = f"entry RVA 0x{s.pe.entry_point:x}"
        elif entry is not None and entry.lower() not in TEXT_LIKE:
            last = bool(names) and names[-1] == entry
            found["entry_outside_text"] = entry + (" (last section)" if last else "")
    if len(found) < 2:
        return []
    return [
        Finding(
            type="packer_indicators",
            severity=cap("medium" if len(found) >= 3 else "low", HEURISTIC_MAX),
            confidence=min(0.9, 0.4 + 0.1 * len(found)),
            method=PACKER_METHOD,
            values={"count": len(found), "indicators": joined(list(found), 900)},
            refs=refs([f"section:{n}" for n in known + [h.name for h in hot + hollow]]),
            attributes={k: v[:255] for k, v in found.items()} | {"indicator_count": len(found)},
        )
    ]


def anomalies(s: Structure, now: float | None = None) -> list[Finding]:
    pe = s.pe
    if pe is None:
        return []
    now = time.time() if now is None else now
    out: list[Finding] = []
    ts = pe.compile_timestamp
    if ts:  # 0 = reproducible build, not an anomaly
        reason = None
        if ts < EARLIEST_TS:
            reason = "before 1995"
        elif ts > now + FUTURE_SLACK_S:
            reason = "in the future"
        if reason:
            out.append(
                Finding(
                    type="timestamp_anomaly",
                    severity="low",
                    confidence=0.6,
                    method=ANOMALY_METHOD,
                    values={"timestamp": ts, "reason": reason},
                    attributes={"timestamp": ts, "reason": reason},
                )  # fmt: skip
            )
    if pe.tls_callbacks:
        out.append(
            Finding(
                type="tls_callbacks",
                severity="info",
                confidence=0.9,
                method=ANOMALY_METHOD,
                values={"count": pe.tls_callbacks},
                attributes={"count": pe.tls_callbacks},
            )  # fmt: skip
        )
    hot = [
        r for r in s.resources
        if r.entropy > RESOURCE_ENTROPY and r.size >= MIN_RESOURCE_BYTES
        and r.type not in IMAGE_RESOURCES
    ]  # fmt: skip
    if hot:
        largest = max(r.size for r in hot)
        out.append(
            Finding(
                type="high_entropy_resource",
                severity="low",
                confidence=0.6,
                method=ANOMALY_METHOD,
                values={"count": len(hot), "threshold": RESOURCE_ENTROPY, "largest": largest},
                refs=refs([f"resource:{r.type}/{r.name}" for r in hot]),
                attributes={
                    "count": len(hot),
                    "largest_bytes": largest,
                    "max_entropy": max(r.entropy for r in hot),
                },
            )  # fmt: skip
        )
    if pe.overlay_size:
        out.append(
            Finding(
                type="overlay",
                severity="low" if pe.overlay_size >= SIGNIFICANT_OVERLAY else "info",
                confidence=0.9,
                method=ANOMALY_METHOD,
                values={"size": pe.overlay_size, "entropy": f"{s.entropy:.2f}"},
                attributes={
                    "overlay_bytes": pe.overlay_size,
                    "overlay_ratio": round(pe.overlay_size / max(s.size, 1), 3),
                },
            )  # fmt: skip
        )
    return out
