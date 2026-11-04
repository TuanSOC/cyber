"""Run a probe mode as the tool uid and turn its JSON lines into validated contract records.

The probe's output is untrusted: each line is bounded by the kit's JsonLines reader, then
validated against the frozen `static.v1` models, and only the record kinds that mode may
produce are accepted (a compromised `strings` probe cannot inject a finding). Probe error
codes and truncation flags are accepted from closed allowlists only.
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cyberlab_jobs.static import STATIC_RECORD_ADAPTER, StaticRecordLine
from cyberlab_worker import sandbox
from cyberlab_worker.parsing import RECORD_ERRORS, JsonLines, clip, count

from static_worker.config import Engines
from static_worker.engines.workspace import Workspace

PROBE_MEMORY = 1024**3
OUTPUT = "probe.jsonl"
MODULE = "static_worker.probe"

KINDS = {
    "pe": {"pe", "section", "import", "export", "resource"},
    "elf": {"elf", "section", "import", "export"},
    "strings": {"string"},
    "yara": {"signature_match"},
    "capa": {"capability"},
    "floss": {"string"},
}
ERRORS = {
    "archive": set(),
    "facts": {"ssdeep_failed", "libmagic_failed"},
    "pe": {"pe_parse_error", "pe_partial"},
    "elf": {"elf_parse_error", "elf_partial"},
    "strings": set(),
    "yara": {"yara_rule_error", "yara_timeout", "yara_failed", "yara_no_rules"},
    "capa": {"capa_failed", "capa_output_too_large"},
    "floss": {"floss_failed", "floss_output_too_large"},
}
TRUNCATION_KEYS = {
    "sections", "imports", "exports", "resources", "strings", "signature_matches",
    "capabilities", "capa_output", "floss_output",
}  # fmt: skip
ARCHIVE_FORMATS = {"none", "zip", "7z", "rar"}
ARCHIVE_COUNTS = ("members", "declared_bytes", "largest_member", "depth")
HEX = {32: re.compile(r"^[0-9a-f]{32}$"), 40: re.compile(r"^[0-9a-f]{40}$")}
SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class ProbeRun:
    mode: str
    dirs: sandbox.JobDirs
    max_lines: int
    errors: list[str]
    truncated: dict[str, bool]
    skipped: int = 0

    def lines(self) -> Iterator[dict[str, Any]]:
        """Raw items, with error/summary lines consumed here."""
        source = JsonLines(self.dirs, OUTPUT, max_lines=self.max_lines)
        for item in source:
            kind = item.get("kind")
            if kind == "error":
                code = item.get("code")
                if isinstance(code, str) and code in ERRORS[self.mode] and code not in self.errors:
                    self.errors.append(code)
            elif kind == "summary":
                flags = item.get("truncated")
                if isinstance(flags, dict):
                    for key, value in flags.items():
                        if key in TRUNCATION_KEYS and value is True:
                            self.truncated[key] = True
            else:
                yield item
        self.skipped += source.skipped
        if source.capped:
            self.truncated[f"{self.mode}_output"] = True

    def records(self) -> Iterator[StaticRecordLine]:
        allowed = KINDS[self.mode]
        for item in self.lines():
            if item.get("kind") not in allowed:
                self.skipped += 1
                continue
            try:
                record = STATIC_RECORD_ADAPTER.validate_python(item)
                record.model_dump_json()  # serializable (no lone surrogates etc.)
            except RECORD_ERRORS:
                self.skipped += 1
                continue
            if record.kind == "signature_match" and record.engine != "yara":
                self.skipped += 1
                continue
            yield record


def run_probe(
    ws: Workspace,
    engines: Engines,
    mode: str,
    options: list[str],
    *,
    seconds: float,
    max_lines: int,
    errors: list[str],
    truncated: dict[str, bool],
    target: Path | None = None,
    memory_bytes: int = PROBE_MEMORY,
) -> ProbeRun:
    """Run one probe mode on the sample (or on `target`, a tool's output to reduce).

    cwd is the root-owned, read-only input dir: nothing there was written by a tool.
    """
    dirs = ws.engine(f"probe-{mode}")
    path = str(target or ws.sample)
    argv = [engines.python, "-I", "-s", "-B", "-m", MODULE, mode, path, *options]
    try:
        sandbox.run_tool(
            argv,
            dirs,
            timeout_s=seconds,
            stdout_name=OUTPUT,
            memory_bytes=memory_bytes,
            cwd=ws.dirs.input,
        )
    except sandbox.ToolTimeout:
        errors.append(f"{mode}_timeout")
    except sandbox.ToolFailed:
        errors.append(f"{mode}_failed")
    # Partial output of a crashed / killed probe is still read (bounded, validated).
    return ProbeRun(mode, dirs, max_lines, errors, truncated)


@dataclass
class Facts:
    size: int | None = None
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    entropy: float | None = None
    ssdeep: str | None = None
    file_type: str | None = None
    mime: str | None = None


def facts(run: ProbeRun) -> Facts:
    out = Facts()
    for item in run.lines():
        try:
            if item.get("kind") == "facts":
                out.size = count(item.get("size"))
                out.md5 = _hex(item.get("md5"), 32)
                out.sha1 = _hex(item.get("sha1"), 40)
                sha = item.get("sha256")
                out.sha256 = sha if isinstance(sha, str) and SHA256.match(sha) else None
                value = item.get("entropy")
                if isinstance(value, int | float) and 0 <= value <= 8:
                    out.entropy = float(value)
                out.file_type = clip(item.get("file_type"), 255)
                out.mime = clip(item.get("mime"), 128)
            elif item.get("kind") == "ssdeep":
                out.ssdeep = clip(item.get("value"), 128)
            else:
                run.skipped += 1
        except RECORD_ERRORS:
            run.skipped += 1
    return out


@dataclass
class Archive:
    """The `archive` probe's result. `record` None: no line (timed out, crashed, skipped)."""

    record: dict[str, int | bool | str] | None = None
    sha256: str | None = None  # of the bytes the probe checked


def archive_result(run: ProbeRun) -> Archive:
    """The first `archive` line; everything else is skipped."""
    for item in run.lines():
        if item.get("kind") != "archive":
            run.skipped += 1
            continue
        sha = item.get("sha256")
        return Archive(archive(item), sha if isinstance(sha, str) and SHA256.match(sha) else None)
    return Archive()


def archive(item: dict[str, Any]) -> dict[str, int | bool | str]:
    """The pre-check record; any malformed field makes it `unchecked` (fail closed)."""
    fmt = item.get("format")
    valid = isinstance(fmt, str) and fmt in ARCHIVE_FORMATS
    out: dict[str, int | bool | str] = {"format": str(fmt) if valid else "unknown"}
    for key in ARCHIVE_COUNTS:
        value = item.get(key)
        valid = valid and isinstance(value, int) and not isinstance(value, bool)
        out[key] = count(value)
        valid = valid and out[key] == value
    for key in ("encrypted", "unchecked"):
        value = item.get(key)
        valid = valid and isinstance(value, bool)
        out[key] = value is True
    if not valid:
        out["unchecked"] = True
    return out


def _hex(value: object, length: int) -> str | None:
    return value if isinstance(value, str) and HEX[length].match(value) else None
