"""Shim (M9 phase 1, RT8): YARA rule files and their namespaces now live in the worker kit as
`cyberlab_worker.yara_rules`, shared with the disk analyzer. Same objects, same behaviour."""

from cyberlab_worker.yara_rules import MAX_RULE_FILE, SOURCES, rule_files, rule_hashes

__all__ = ["MAX_RULE_FILE", "SOURCES", "rule_files", "rule_hashes"]
