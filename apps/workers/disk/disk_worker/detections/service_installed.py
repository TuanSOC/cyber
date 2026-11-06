"""`heuristic:disk_service_installed@1`: EVTX System 7045 (Service Control Manager).

- medium: the image path is in a user-writable class;
- low: the image path is outside the standard program directories (System32, SysWOW64,
  Program Files, the .NET and servicing directories, Defender's platform directories);
- nothing: installs into the standard directories (a legitimate installer's service, Defender's
  driver updates).

Fields come from the positional strings (`ServiceName`, `ImagePath`); an unknown layout skips the
event and is counted (`evtx_layout_unknown`). Repeated installs of one service with one image
(PsExec-style tools reinstall theirs every run) are one finding citing the events.
"""

from dataclasses import dataclass, field

from cyberlab_jobs.disk import DiskEventRecord

from disk_worker.detections import events as ev
from disk_worker.detections import evtx_fields, paths
from disk_worker.detections.base import Context, Finding, Rule, iso, quoted

CONFIDENCE = 0.6


@dataclass
class _Pending:
    finding: Finding
    norm: str


@dataclass
class ServiceInstalled(Rule):
    pending: dict[str, _Pending] = field(default_factory=dict)

    def observe(self, event: DiskEventRecord, ctx: Context) -> None:
        record = ctx.evtx(event)
        if record is None or record.event_id != 7045 or record.provider != evtx_fields.SCM:
            return
        if record.fields is None:
            ctx.counts["evtx_layout_unknown"] += 1
            return
        service = record.get("ServiceName") or "unknown"
        image = record.get("ImagePath") or ""
        targets = paths.windows_targets(image)
        norm = paths.windows_path(targets[0]) if targets else ""
        writable = paths.user_writable_class(norm, "windows") if norm else None
        if writable is not None:
            severity, location = "medium", f"in {writable}"
        elif norm and paths.is_standard_program(norm):
            ctx.counts["service_standard_location"] += 1
            return
        else:
            severity, location = "low", "outside the standard program directories"
        key = f"{service.casefold()}|{image.casefold()}"
        item = self.pending.get(key)
        if item is None:
            if not ctx.budget.take():
                return
            item = _Pending(
                Finding(
                    type="disk_service_installed",
                    severity="medium" if severity == "medium" else "low",
                    confidence=CONFIDENCE,
                    values={
                        "service": quoted(service, 128),
                        "when": iso(event.ts),
                        "image": quoted(image),
                        "location": location,
                    },
                    subject=service,
                    key=key,
                    ts=event.ts,
                    paths=[norm] if norm else [],
                    texts=[quoted(image, 2048)],
                    attributes={
                        "subject": quoted(service, 255),
                        "image_path": quoted(image, 255),
                    },
                ),
                norm,
            )
            self.pending[key] = item
        item.finding.cite(ev.cited(event, "service_install", f"Service {service} installed"))

    def finish(self, ctx: Context) -> list[Finding]:
        out: list[Finding] = []
        for item in self.pending.values():
            listed = ctx.indexed_files.get(item.norm)
            if listed is not None:
                item.finding.files.append(listed)
            if len(item.finding.events) + item.finding.cited_more > 1:
                item.finding.attributes["installs"] = (
                    len(item.finding.events) + item.finding.cited_more
                )
            out.append(item.finding)
        return out
