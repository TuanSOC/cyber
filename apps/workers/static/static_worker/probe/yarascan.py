"""`yara` mode: compile the rule directories and scan the sample with a timeout.

A rule file that does not compile is dropped (reported as `yara_rule_error`); the others
still run. Namespaces: `<source>.<file stem>` where source is the directory's role
(`image` for the baked rules, `test` for the test-only directory; `static_worker.rulefiles`).
"""

from pathlib import Path
from typing import Any

import yara

from static_worker.probe.common import emit, error, text
from static_worker.rulefiles import rule_files


def _rule_files(directories: list[Path]) -> dict[str, str]:
    return {namespace: str(path) for namespace, path in rule_files(directories).items()}


def _compile(files: dict[str, str]) -> Any:
    try:
        return yara.compile(filepaths=files)
    except yara.Error:
        good = {}
        for namespace, path in files.items():
            try:
                yara.compile(filepath=path)
            except yara.Error as exc:
                error("yara_rule_error", f"{namespace}: {exc}")
                continue
            good[namespace] = path
        return yara.compile(filepaths=good) if good else None


def run(sample: Path, directories: list[Path], *, timeout: int, max_matches: int) -> None:
    files = _rule_files(directories)
    if not files:
        error("yara_no_rules")
        return
    rules = _compile(files)
    if rules is None:
        return
    try:
        matches = rules.match(str(sample), timeout=max(1, timeout))
    except yara.TimeoutError:
        error("yara_timeout")
        return
    except yara.Error as exc:
        error("yara_failed", str(exc))
        return
    for match in matches[:max_matches]:
        emit(
            {
                "kind": "signature_match",
                "engine": "yara",
                "name": text(match.rule, 255),
                "namespace": text(match.namespace, 128),
                "tags": [text(t, 64) for t in match.tags[:20]],
                "meta": {text(k, 64): text(v, 255) for k, v in list(match.meta.items())[:20]},
            }
        )
    emit({"kind": "summary", "truncated": {"signature_matches": len(matches) > max_matches}})
