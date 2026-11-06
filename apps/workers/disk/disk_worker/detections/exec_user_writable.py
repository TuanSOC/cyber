"""`heuristic:disk_exec_user_writable@1` (low): PE / ELF content in a user-writable path class
(`paths.WINDOWS_CLASSES` / `paths.LINUX_CLASSES`, minus the clean-system exclusions). A file in a
reference hash set still fires (`known` never suppresses a heuristic, RT18). Named streams are
the ADS rule's."""

from cyberlab_jobs.disk import DiskFileRecord

from disk_worker.detections.base import Context, FileFacts, Finding, Rule, shown
from disk_worker.detections.file_rules import EXEC_MAGIC, MAGIC_LABEL, file_finding, size_text

CONFIDENCE = 0.5


class ExecUserWritable(Rule):
    def check_file(self, file: DiskFileRecord, facts: FileFacts, ctx: Context) -> list[Finding]:
        if file.type != "reg" or file.stream is not None or file.magic not in EXEC_MAGIC:
            return []
        if facts.writable is None:
            return []
        return [
            file_finding(
                "disk_exec_user_writable",
                "low",
                CONFIDENCE,
                file,
                facts,
                ctx,
                {
                    "path": shown(file.path),
                    "magic": MAGIC_LABEL[file.magic or "pe"],
                    "size": size_text(file),
                    "path_class": facts.writable,
                },
                attributes={"path_class": facts.writable},
            )
        ]
