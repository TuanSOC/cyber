"""Static analysis of one sample: every parser / engine as the tool uid, then `static.v1`.

Engine order (RT5): ClamAV -> YARA -> archive pre-check -> sample facts -> pefile / ELF ->
strings -> capa -> FLOSS (emulators last). Each engine gets a fresh tool-owned out dir
created after every tool process was killed. Root only hashes the file (hashlib, no parsing)
and reads bounded, validated tool output. Profile `av` runs ClamAV + YARA (+ archive
pre-check and sample facts) only.

Anything capped, skipped or not run is reported in the header (`truncated`,
`engine_errors`); an AV scan that could not cover the whole file is `av_not_fully_scanned`,
never a silent "clean". That includes an AV scan whose coverage is unknown because the
archive pre-check (facts probe) produced no usable result.
"""

import hashlib
import math
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from cyberlab_jobs.capture import ExecutableFormat, executable_format
from cyberlab_jobs.static import (
    CapabilityRecord,
    ElfInfo,
    ExportRecord,
    ImportRecord,
    PeInfo,
    Profile,
    ResourceRecord,
    SampleInfo,
    SectionRecord,
    SignatureMatch,
    StaticJobV1,
    StaticLimits,
    StaticResultHeader,
    StringRecord,
)
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed
from cyberlab_worker.result_writer import ResultWriter, Spool
from cyberlab_worker.transfer import download

from static_worker.config import Engines, tool_versions
from static_worker.detections.run import Detection
from static_worker.detections.signatures import yara_ceilings
from static_worker.detections.structure import Structure
from static_worker.engines import capa, clamav, floss
from static_worker.engines.probes import Facts, ProbeRun, archive_result, facts, run_probe
from static_worker.engines.workspace import Budget, Workspace
from static_worker.rulefiles import rule_hashes

CAPA_MAX_BYTES = 16 * 1024**2  # RT4
FLOSS_MAX_BYTES = 8 * 1024**2  # RT4
# RT4 allowed 64 MiB, but ppdeep is pure Python (~0.2 MiB/s measured: ~290 s for 62 MiB).
SSDEEP_MAX_BYTES = 4 * 1024**2
YARA_TIMEOUT_S = 120
FLOSS_RESERVE = 0.25  # share of max_strings kept for FLOSS when it will run
CHUNK = 1024 * 1024
HEAD = 4096
MAX_ERRORS = 32

FileFormat = Literal["pe", "elf", "other"]


def file_format(sample: Path) -> FileFormat:
    """Magic numbers only (the shared contract helper; no parsing)."""
    with open(sample, "rb") as f:
        fmt = executable_format(f.read(HEAD))
    if fmt == ExecutableFormat.PE:
        return "pe"
    if fmt == ExecutableFormat.ELF:
        return "elf"
    return "other"


@dataclass
class Hashes:
    size: int
    md5: str
    sha1: str
    sha256: str
    entropy: float


def hash_file(sample: Path) -> Hashes:
    """Trusted values for the `sample` line (ingest compares sha256/size to the evidence)."""
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()  # noqa: S324 - IDs
    counts: Counter[int] = Counter()
    size = 0
    with open(sample, "rb") as f:
        while chunk := f.read(CHUNK):
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            counts.update(chunk)
    entropy = 0.0
    if size:
        entropy = -sum(c / size * math.log2(c / size) for c in counts.values())
    return Hashes(
        size, md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest(), round(min(entropy, 8.0), 4)
    )


@dataclass
class Collected:
    errors: list[str] = field(default_factory=list)
    truncated: dict[str, bool] = field(default_factory=dict)
    skipped: Counter[str] = field(default_factory=Counter)
    signatures: list[SignatureMatch] = field(default_factory=list)
    capabilities: list[CapabilityRecord] = field(default_factory=list)
    facts: Facts = field(default_factory=Facts)
    info: PeInfo | ElfInfo | None = None


def analyze(job: StaticJobV1, dirs: sandbox.JobDirs) -> Path:
    budget = Budget(job.limits)
    ws = Workspace(dirs)
    download(
        job.evidence_url,
        ws.sample,
        expected_sha256=job.expected_sha256,
        size_bytes=job.size_bytes,
        max_bytes=job.limits.max_bytes,
        too_large_code="sample_too_large",
    )
    return analyze_file(dirs, job.job_id, job.profile, job.limits, budget, Engines.from_env())


def analyze_file(
    dirs: sandbox.JobDirs,
    job_id: uuid.UUID,
    profile: Profile,
    limits: StaticLimits,
    budget: Budget,
    engines: Engines,
) -> Path:
    """Analyze the sample already in `dirs.input/sample` (hash-verified by the caller)."""
    ws = Workspace(dirs)
    analysed_at = datetime.now(UTC).replace(microsecond=0)
    fmt = file_format(ws.sample)
    hashes = hash_file(ws.sample)
    got = Collected()
    errors, truncated = got.errors, got.truncated
    spool = {
        kind: Spool(dirs.root / f"{kind}.spool", limit)
        for kind, limit in (
            ("section", limits.max_sections),
            ("import", limits.max_imports),
            ("export", limits.max_exports),
            ("resource", limits.max_resources),
            ("string", limits.max_strings),
        )
    }
    structure = Structure(file_format=fmt, size=hashes.size, entropy=hashes.entropy)
    detection = Detection(job_id, analysed_at, structure, limits.max_iocs)

    # 1. ClamAV (RT2 limits) -------------------------------------------------------------
    got.signatures += clamav.scan(
        ws, engines, budget.tool(), size=hashes.size, errors=errors, truncated=truncated
    )
    av_verdict = not {"av_unavailable", "av_timeout"} & set(errors)
    # 2. YARA (yara-python in the probe, with its own timeout) -----------------------------
    seconds = budget.tool()
    if seconds is None:
        errors.append("yara_skipped")
    else:
        directories = [engines.yara_rules]
        if engines.yara_test_rules is not None:
            directories.append(engines.yara_test_rules)
        rules = [arg for d in directories for arg in ("--rules", str(d))]
        detection.yara_ceilings = yara_ceilings(
            rule_hashes(directories), test_rules=engines.yara_test_rules is not None
        )
        timeout = int(max(1, min(seconds - 2, YARA_TIMEOUT_S)))
        run = run_probe(
            ws, engines, "yara",
            [*rules, "--timeout", str(timeout), "--max-matches", str(limits.max_signature_matches)],
            seconds=seconds, max_lines=limits.max_signature_matches + 100,
            errors=errors, truncated=truncated,
        )  # fmt: skip
        got.signatures += [r for r in run.records() if isinstance(r, SignatureMatch)]
        got.skipped["yara"] += run.skipped
    # 3. Archive pre-check (own process and out dir, before libmagic) -----------------------
    archive = None
    seconds = budget.tool()
    if seconds is None:
        errors.append("archive_skipped")
    else:
        run = run_probe(
            ws, engines, "archive", [], seconds=seconds, max_lines=10, errors=errors,
            truncated=truncated,
        )  # fmt: skip
        pre = archive_result(run)
        if pre.record is not None and pre.sha256 != hashes.sha256:
            errors.append("probe_inconsistent")  # not the bytes root hashed: discard
        else:
            archive = pre.record
    incomplete = None
    if archive is None:
        # No usable pre-check (skipped, timed out, crashed or discarded): what ClamAV could
        # not see is unknown, so its result cannot count as complete.
        incomplete = "archive_precheck_missing" if av_verdict else None
    elif clamav.exceeds_limits(archive):
        incomplete = "clamav_limits"
    if incomplete is not None:
        truncated[incomplete] = True
        if "av_not_fully_scanned" not in errors:
            errors.append("av_not_fully_scanned")
    # 4. Sample facts (libmagic, ssdeep) ----------------------------------------------------
    seconds = budget.tool()
    if seconds is not None:
        run = run_probe(
            ws, engines, "facts", ["--ssdeep-max-bytes", str(SSDEEP_MAX_BYTES)],
            seconds=seconds, max_lines=100, errors=errors, truncated=truncated,
        )  # fmt: skip
        got.facts = facts(run)
        if got.facts.sha256 is not None and got.facts.sha256 != hashes.sha256:
            errors.append("probe_inconsistent")
            got.facts = Facts()
    else:
        errors.append("facts_skipped")
    if hashes.size > SSDEEP_MAX_BYTES:
        truncated["ssdeep_size_cap"] = True

    if profile == Profile.FULL:
        _full(ws, engines, fmt, hashes.size, limits, budget, got, spool, detection)

    for kind, s in spool.items():
        s.finish()
        truncated[f"{kind}s"] = truncated.get(f"{kind}s", False) or s.truncated

    signatures = got.signatures
    if len(signatures) > limits.max_signature_matches:
        truncated["signature_matches"] = True
        signatures = signatures[: limits.max_signature_matches]
    findings, truncated["findings"] = detection.findings(
        signatures, got.capabilities, limits.max_findings
    )
    iocs = detection.ioc_records()
    truncated["iocs"] = detection.iocs.capped

    sample = SampleInfo(
        size=hashes.size,
        md5=hashes.md5,
        sha1=hashes.sha1,
        sha256=hashes.sha256,
        ssdeep=got.facts.ssdeep,
        file_type=got.facts.file_type,
        mime=got.facts.mime,
        entropy=hashes.entropy,
    )
    unique_errors = list(dict.fromkeys(errors))
    flags = {k: True for k, v in truncated.items() if v}
    if len(unique_errors) > MAX_ERRORS or len(flags) > 32:
        flags = dict(list(flags.items())[:31]) | {"engine_report": True}
    header = StaticResultHeader(
        job_id=job_id,
        profile=profile,
        file_format=fmt,
        tool_versions=tool_versions(engines),
        engine_errors=unique_errors[:MAX_ERRORS],
        truncated=flags,
    )
    result = dirs.root / "result.ndjson.gz"
    with ResultWriter(result) as writer:
        writer.write(header)
        writer.write(sample)
        if got.info is not None:
            writer.write(got.info)
        for kind in ("section", "import", "export", "resource", "string"):
            for line in spool[kind].lines():
                writer.write_line(line)
        for record in (*signatures, *got.capabilities, *findings, *iocs):
            writer.write(record)
    if result.stat().st_size > limits.max_result_bytes:
        raise JobFailed("result_too_large")
    return result


def _full(
    ws: Workspace,
    engines: Engines,
    fmt: FileFormat,
    size: int,
    limits: StaticLimits,
    budget: Budget,
    got: Collected,
    spool: dict[str, Spool],
    detection: Detection,
) -> None:
    errors, truncated = got.errors, got.truncated
    structure = detection.structure
    # 5. pefile / pyelftools ---------------------------------------------------------------
    if fmt in ("pe", "elf"):
        seconds = budget.tool()
        if seconds is None:
            errors.append(f"{fmt}_skipped")
        else:
            options = [
                "--max-sections", str(limits.max_sections), "--max-imports",
                str(limits.max_imports), "--max-exports", str(limits.max_exports),
                "--max-resources", str(limits.max_resources),
            ]  # fmt: skip
            run = run_probe(
                ws, engines, fmt, options, seconds=seconds,
                max_lines=limits.max_sections + limits.max_imports + limits.max_exports
                + limits.max_resources + 100,
                errors=errors, truncated=truncated,
            )  # fmt: skip
            _structure(run, got, spool, structure)
    # 6. strings ------------------------------------------------------------------------------
    floss_will_run = engines.floss_enabled and fmt == "pe" and size <= FLOSS_MAX_BYTES
    static_cap = limits.max_strings
    if floss_will_run:
        static_cap = max(1, limits.max_strings - int(limits.max_strings * FLOSS_RESERVE))
    seconds = budget.tool()
    if seconds is None:
        errors.append("strings_skipped")
    else:
        run = run_probe(
            ws, engines, "strings", ["--max-strings", str(static_cap)], seconds=seconds,
            max_lines=static_cap + 10, errors=errors, truncated=truncated,
        )  # fmt: skip
        for record in run.records():
            if isinstance(record, StringRecord):
                spool["string"].add(record)
                detection.string(record.value, "strings")
        got.skipped["strings"] += run.skipped
    # 7. capa ---------------------------------------------------------------------------------
    if not engines.capa_enabled:
        pass
    elif fmt not in ("pe", "elf"):
        errors.append("capa_skipped")
        truncated["capa_skipped_not_pe_or_elf"] = True
    elif size > CAPA_MAX_BYTES:
        errors.append("capa_skipped")
        truncated["capa_skipped_size_cap"] = True
    elif (seconds := budget.tool()) is None:
        errors.append("capa_skipped")
        truncated["capa_skipped_time"] = True
    else:
        got.capabilities = capa.run(
            ws, engines, seconds, budget=budget, limit=limits.max_capabilities, errors=errors,
            truncated=truncated,
        )  # fmt: skip
    # 8. FLOSS (emulation: last) ------------------------------------------------------------
    if not engines.floss_enabled:
        pass
    elif fmt != "pe":
        errors.append("floss_skipped")
        truncated["floss_skipped_not_pe"] = True
    elif size > FLOSS_MAX_BYTES:
        errors.append("floss_skipped")
        truncated["floss_skipped_size_cap"] = True
    elif (seconds := budget.tool()) is None:
        errors.append("floss_skipped")
        truncated["floss_skipped_time"] = True
    else:
        room = limits.max_strings - spool["string"].count
        for record in floss.run(
            ws, engines, seconds, budget=budget, limit=max(0, room), errors=errors,
            truncated=truncated,
        ):  # fmt: skip
            spool["string"].add(record)
            detection.string(record.value, "floss")
    sandbox.kill_tool_processes()


def _structure(run: ProbeRun, got: Collected, spool: dict[str, Spool], s: Structure) -> None:
    for record in run.records():
        if isinstance(record, PeInfo | ElfInfo):
            if got.info is None:  # one per result; the probe mode fixes which kind
                got.info = record
                s.pe = record if isinstance(record, PeInfo) else None
            continue
        if isinstance(record, SectionRecord):
            if spool["section"].count < spool["section"].limit:
                s.sections.append(record)
            spool["section"].add(record)
        elif isinstance(record, ImportRecord):
            s.import_count += 1
            if record.function and spool["import"].count < spool["import"].limit:
                s.imports.add(record.function)
            spool["import"].add(record)
        elif isinstance(record, ExportRecord):
            spool["export"].add(record)
        elif isinstance(record, ResourceRecord):
            if spool["resource"].count < spool["resource"].limit:
                s.resources.append(record)
            spool["resource"].add(record)
    got.skipped[run.mode] += run.skipped
