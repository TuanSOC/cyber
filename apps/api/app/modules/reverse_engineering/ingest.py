"""Trusted ingest of an `re.v1` result (M10 phase 1 entry points; phase 7 owns the bodies,
never the signatures).

Run by the shared ingest worker (`workers/ingest.py`: `SUCCESS_INGESTERS[REVERSE]`,
`DIAGNOSTIC_INGESTERS[REVERSE]`):

- `ingest_re(job, msg, path)`: a `succeeded` report with its downloaded result. Validates the
  whole stream first (framing with the RE bounds `RE_MAX_RESULT_DECOMPRESSED_BYTES` and
  `Settings.re_max_result_lines()`, the contract, `cyberlab_jobs.reverse.StreamChecker`, the
  program's sha256 / size against the evidence, `engine: replay` refused unless the test
  profile), then writes in ONE transaction: `re_programs`, `re_functions` (with the
  decompile status), `re_call_edges`, `re_imports` + `re_import_refs`, `re_strings` +
  `re_string_refs`, `re_decompilations`, the capa links (`re_function_capabilities`, joined on
  file virtual addresses with the source job, RT8), `analysis_findings`, `iocs`, the summary,
  the final state, custody and audit.
- `ingest_re_diagnostic(job, msg, path)`: a `failed` report (`unsupported_architecture` /
  `unsupported_managed_code`) with its diagnostic stream (header, program, trailer):
  `re_programs` only, and the job fails with the worker's code.

Until phase 7 both raise NotImplementedError (the shared ingest turns it into
`ingest_error`).
"""

from pathlib import Path

from cyberlab_jobs import IngestMessageV1

from app.modules.analysis.models import AnalysisJob


async def ingest_re(job: AnalysisJob, msg: IngestMessageV1, path: Path) -> None:
    raise NotImplementedError("M10 phase 7")


async def ingest_re_diagnostic(job: AnalysisJob, msg: IngestMessageV1, path: Path) -> None:
    raise NotImplementedError("M10 phase 7")
