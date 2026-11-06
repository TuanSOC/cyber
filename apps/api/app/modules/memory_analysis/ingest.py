"""Trusted ingest of `memory.v1` results (M8 phase 1 STUBS; phase 6 owns the bodies, never
the signatures). Called from `app.workers.ingest` by the job's analyzer:

- `ingest_memory(job, msg, path)`: a `succeeded` report with its downloaded result file;
  validate the whole stream, then write it in one transaction (`memory_*` tables, findings,
  IOCs, timeline, the job summary, the final state, custody and audit);
- `ingest_memory_diagnostic(job, msg, path)`: a `failed` / `symbols_missing` report that
  carries a result version: the diagnostic stream (header, at most the image line, trailer);
  store the requirement in `memory_images` and fail the job `symbols_missing`.

Phase 1 raises NotImplementedError: the ingest worker then fails the job `ingest_error`. No
phase-1 worker ever reports a memory success or a diagnostic stream.
"""

from pathlib import Path

from cyberlab_jobs import IngestMessageV1

from app.modules.analysis.models import AnalysisJob


async def ingest_memory(job: AnalysisJob, msg: IngestMessageV1, path: Path) -> None:
    raise NotImplementedError("memory ingest lands in M8 phase 6")


async def ingest_memory_diagnostic(job: AnalysisJob, msg: IngestMessageV1, path: Path) -> None:
    raise NotImplementedError("memory diagnostic ingest lands in M8 phase 6")
