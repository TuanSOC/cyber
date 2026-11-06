"""`signature:yara@1`: one finding per (file, rule) for each YARA hit phase 5 recorded in
`DiskFileRecord.yara_rules` (`<namespace>.<rule>`). The severity comes from
`Context.yara_severity` (phase 5 computes it with `cyberlab_worker.yara_rules.yara_severity` over
the M3 sha256-keyed allow-list); a rule missing there is `low`, the M3 default. This is the only
method that may reach `high`.
"""

from cyberlab_jobs.disk import DiskFileRecord

from disk_worker.detections.base import Context, FileFacts, Finding, Rule, quoted, shown
from disk_worker.detections.file_rules import file_finding, size_text

CONFIDENCE = 0.7


class YaraMatches(Rule):
    def check_file(self, file: DiskFileRecord, facts: FileFacts, ctx: Context) -> list[Finding]:
        out: list[Finding] = []
        for stored in dict.fromkeys(file.yara_rules):
            namespace, _, rule = stored.rpartition(".")
            severity = ctx.yara_severity.get(stored, "low")
            out.append(
                file_finding(
                    "disk_yara_match",
                    severity,
                    CONFIDENCE,
                    file,
                    facts,
                    ctx,
                    {
                        "rule": quoted(rule, 128),
                        "namespace": quoted(namespace or "unknown", 128),
                        "name": shown(file.name, 128),
                        "path": shown(file.path),
                        "size": size_text(file),
                    },
                    subject=f"{file.path}|{stored}",
                    discriminator=stored,
                    attributes={"rule": stored},
                )
            )
        return out
