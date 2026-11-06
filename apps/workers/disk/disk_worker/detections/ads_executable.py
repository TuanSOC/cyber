"""`heuristic:disk_ads_executable@1` (medium): an NTFS named stream whose content starts with a
PE header. `Zone.Identifier` (the mark of the web) is never one, whatever its magic."""

from cyberlab_jobs.disk import DiskFileRecord

from disk_worker.detections.base import Context, FileFacts, Finding, Rule, shown
from disk_worker.detections.file_rules import file_finding, size_text

NEVER_STREAMS = frozenset({"zone.identifier"})
CONFIDENCE = 0.8


class AdsExecutable(Rule):
    def check_file(self, file: DiskFileRecord, facts: FileFacts, ctx: Context) -> list[Finding]:
        if file.stream is None or file.type != "reg" or file.magic != "pe":
            return []
        if file.stream.strip().casefold() in NEVER_STREAMS:
            return []
        return [
            file_finding(
                "disk_ads_executable",
                "medium",
                CONFIDENCE,
                file,
                facts,
                ctx,
                {
                    "path": shown(file.path),
                    "stream": shown(file.stream, 128),
                    "size": size_text(file),
                    "magic": "PE",
                },
                subject=f"{file.path}:{file.stream}",
            )
        ]
