"""`heuristic:mem_unlinked_module@1` (profile `full`, `ldrmodules`): a mapped module with a
path that is missing from all three loader lists.

The process's own image is excluded, and so are mapped files that are not loadable modules
(`.mui`, `.nls`, `.dat`, ...: data files the loader never lists).
"""

from memory_worker.detections.base import Context, Finding, basename, hex_addr, refs
from memory_worker.detections.mask import excerpt
from memory_worker.view import MemoryView

# Attribute keys of `ldr_unlinked` artifacts (phase-2 normalizer).
IN_LISTS = ("in_load", "in_init", "in_mem")
MODULE_EXTENSIONS = (".dll", ".exe", ".sys", ".ocx", ".cpl", ".drv", ".scr", ".ax", ".tlb")
CONFIDENCE = 0.5


def _norm(path: str) -> str:
    return path.strip().replace("/", "\\").lower()


def detect(view: MemoryView, ctx: Context) -> list[Finding]:
    if view.os != "windows":
        return []
    out: list[Finding] = []
    for artifact in view.artifacts:
        if artifact.type != "ldr_unlinked" or artifact.pid is None:
            continue
        attrs = artifact.attributes
        path = attrs.get("path")
        if not isinstance(path, str) or not path.strip():
            continue
        if any(attrs.get(key) is not False for key in IN_LISTS):
            continue
        lowered = _norm(path)
        if not lowered.endswith(MODULE_EXTENSIONS):
            continue
        procs = ctx.by_pid.get(artifact.pid, [])
        own = {_norm(p.image_path) for p in procs if p.image_path}
        names = {p.name.lower() for p in procs}
        if lowered in own or basename(lowered) in names:
            continue
        base = attrs.get("base")
        base_text = hex_addr(base) if isinstance(base, int) and base >= 0 else "unknown"
        out.append(
            Finding(
                type="mem_unlinked_module",
                severity="medium",
                confidence=CONFIDENCE,
                values={
                    "pid": artifact.pid,
                    "name": excerpt(ctx.name_of(artifact.pid) or "unknown", 64),
                    "path": excerpt(path, 300),
                    "base": base_text,
                },
                key=f"{artifact.pid}|{base_text}|{lowered}",
                pid=artifact.pid,
                refs=refs([f"pid:{artifact.pid}", f"module:{base_text}"]),
                attributes={"pid": artifact.pid, "path": excerpt(path, 255), "base": base_text},
            )
        )
    return out
