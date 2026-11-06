"""`known_file:hashset@1`: a file whose hash is in an operator `known_bad` / `notable` set
(`known = bad | notable`), at most `medium` (operator lists are unverified). `known = good` is
never a finding: it only marks the file "known (reference set)" for the UI, and it never
suppresses a heuristic (RT18).
"""

from cyberlab_jobs.disk import DiskFileRecord

from disk_worker.detections.base import Context, FileFacts, Finding, Rule, quoted, shown
from disk_worker.detections.file_rules import file_finding, size_text

CONFIDENCE = 0.8
KNOWN_KINDS = {"bad": "known_bad", "notable": "notable"}


class HashSetMatches(Rule):
    def check_file(self, file: DiskFileRecord, facts: FileFacts, ctx: Context) -> list[Finding]:
        kind = KNOWN_KINDS.get(file.known or "")
        if kind is None:
            return []
        set_name = file.known_set or "unknown"
        return [
            file_finding(
                "disk_hashset_match",
                "medium",
                CONFIDENCE,
                file,
                facts,
                ctx,
                {
                    "path": shown(file.path),
                    "size": size_text(file),
                    "kind": kind,
                    "set_name": quoted(set_name, 64),
                },
                attributes={"hashset": set_name, "hashset_kind": kind},
            )
        ]
