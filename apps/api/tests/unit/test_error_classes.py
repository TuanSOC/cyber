"""`ops/error_classes.py` (M7 phase 1): every error code the platform can store on a failed
job, run or render has a class. Sources: the contracts (`RENDER_ERROR_CODES`, `AiErrorCode`,
the TI item reasons), the reaper's codes, the literal codes of the api's own failure paths
(AST scan of `app/`), and the analyzers' codes (`ANALYZER_CODES`, pinned here against the
worker sources when they are mounted)."""

import ast
import re
from pathlib import Path

import pytest
from cyberlab_jobs.memory import MEMORY_ERROR_CODES
from cyberlab_jobs.report import RENDER_ERROR_CODES

from app.modules.ai.contracts import AiErrorCode
from app.modules.ops.error_classes import ANALYZER_CODES, ERROR_CLASS, ErrorClass, classify
from app.modules.threat_intel.models import ITEM_REASONS
from app.workers.reaper import CODES as REAPER_CODES

APP = Path(__file__).resolve().parents[2] / "app"
WORKERS = Path(__file__).resolve().parents[4] / "apps" / "workers"
CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
# Calls / keywords whose string literal argument is a stored error code.
FAIL_CALLS = {"_fail", "_fail_job", "JobFailed"}


def _literal_codes(path: Path) -> set[str]:
    codes: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.keyword) and node.arg in ("error_code", "too_large_code"):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                codes.add(node.value.value)
        elif isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Attribute) and t.attr == "error_code" for t in node.targets
        ):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                codes.add(node.value.value)
        elif isinstance(node, ast.Call):
            name = getattr(node.func, "id", getattr(node.func, "attr", ""))
            if name in FAIL_CALLS:
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        if CODE.fullmatch(arg.value):
                            codes.add(arg.value)
            if name == "_fail" and len(node.args) >= 3:
                arg = node.args[2]
                if isinstance(arg, ast.BoolOp):  # `msg.error_code or "analyzer_failed"`
                    codes |= {
                        v.value
                        for v in arg.values
                        if isinstance(v, ast.Constant) and isinstance(v.value, str)
                    }
    return {c for c in codes if CODE.fullmatch(c)}


def _api_codes() -> set[str]:
    paths = [
        *(APP / "workers").glob("*.py"),
        *(APP / "modules" / "analysis").glob("*.py"),
        *(APP / "modules" / "reports").glob("*.py"),
        *(APP / "modules" / "memory_analysis").glob("*.py"),
    ]
    return set().union(*(_literal_codes(p) for p in paths))


def test_every_contract_code_is_classified() -> None:
    codes = {
        *RENDER_ERROR_CODES,
        *(c.value for c in AiErrorCode),
        *ITEM_REASONS,
        *REAPER_CODES.values(),
        *ANALYZER_CODES,
        *MEMORY_ERROR_CODES,  # M8: the memory analyzer, its ingest and the API refusals
        "snapshot_too_large",  # the renderer's download cap (report-worker tasks.py)
    }
    missing = sorted(codes - set(ERROR_CLASS))
    assert missing == [], f"classify these error codes in ops/error_classes.py: {missing}"


def test_every_literal_code_of_the_api_is_classified() -> None:
    codes = _api_codes()
    assert {"invalid_result", "ingest_error", "analyzer_failed", "enqueue_failed"} <= codes
    missing = sorted(codes - set(ERROR_CLASS))
    assert missing == [], f"classify these error codes in ops/error_classes.py: {missing}"


@pytest.mark.skipif(not WORKERS.is_dir(), reason="worker sources are not mounted in this image")
def test_analyzer_codes_match_the_worker_sources() -> None:  # pragma: no cover - host only
    paths = [
        p
        for sub in ("pcap/pcap_worker", "static/static_worker", "memory/memory_worker")
        for p in (WORKERS / sub).rglob("*.py")
    ]
    found = set().union(*(_literal_codes(p) for p in paths))
    assert found - set(ANALYZER_CODES) - set(MEMORY_ERROR_CODES) == set()


def test_memory_codes_have_the_planned_classes() -> None:
    """M8 (plan Frozen interfaces 6; RT25: a missing symbol is an operator gap)."""
    assert classify("symbols_missing") is ErrorClass.INPUT
    assert classify("memory_parse_failed") is ErrorClass.PARSE
    assert classify("os_undetermined") is ErrorClass.PARSE
    assert classify("unsupported_memory_format") is ErrorClass.INPUT
    assert classify("memory_image_too_large") is ErrorClass.INPUT
    assert classify("insufficient_disk") is ErrorClass.INFRA
    assert classify("plugin_timeout") is ErrorClass.INFRA
    assert set(MEMORY_ERROR_CODES) <= set(ERROR_CLASS)


def test_classes_and_fallbacks() -> None:
    assert classify("unparseable_capture") is ErrorClass.PARSE
    assert classify("timed_out") is ErrorClass.INFRA
    assert classify("policy_blocked") is ErrorClass.POLICY
    assert classify("provider_unavailable") is ErrorClass.PROVIDER
    assert classify("capture_too_large") is ErrorClass.INPUT
    assert classify(None) is ErrorClass.OTHER
    assert classify("never_heard_of_it") is ErrorClass.OTHER
    assert all(CODE.fullmatch(code) for code in ERROR_CLASS)
    with pytest.raises(TypeError):
        ERROR_CLASS["x"] = ErrorClass.OTHER  # type: ignore[index]
