"""Shared constructor of file findings (one finding = one listed file entry)."""

from cyberlab_jobs.disk import DiskFileRecord

from disk_worker.detections.base import (
    MAX_ATTRIBUTES,
    Context,
    FileFacts,
    Finding,
    Severity,
    file_ref,
    file_time,
    shown,
)

EXEC_MAGIC = frozenset({"pe", "elf"})
MAGIC_LABEL = {"pe": "PE", "elf": "ELF"}


def size_text(file: DiskFileRecord) -> str:
    return "unknown" if file.size is None else str(file.size)


def file_finding(
    kind: str,
    severity: Severity,
    confidence: float,
    file: DiskFileRecord,
    facts: FileFacts,
    ctx: Context,
    values: dict[str, object],
    *,
    subject: str | None = None,
    discriminator: str = "",
    attributes: dict[str, str | int | float | bool] | None = None,
) -> Finding:
    del ctx
    attrs: dict[str, str | int | float | bool] = {
        "subject": shown(subject or file.path, 255),
        "partition_index": file.partition_index,
        "path": shown(file.path, 255),
    }
    if file.stream is not None:
        attrs["stream"] = shown(file.stream, 255)
    if file.sha256 is not None:
        attrs["sha256"] = file.sha256
    if file.known is not None:
        attrs["known"] = file.known  # informational: `known` never suppresses a rule (RT18)
    attrs.update(attributes or {})
    return Finding(
        type=kind,
        severity=severity,
        confidence=confidence,
        values=values,
        subject=subject or file.path,
        key=f"{file_ref(file)}|{file.path}|{discriminator}",
        ts=file_time(file),
        files=[file],
        paths=[facts.norm],
        attributes=dict(list(attrs.items())[:MAX_ATTRIBUTES]),
    )


__all__ = ["EXEC_MAGIC", "MAGIC_LABEL", "file_finding", "size_text"]
