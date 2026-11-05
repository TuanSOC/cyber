"""Platform metrics for `/internal/metrics` (M7 phase 5).

`platform_metrics` reads `job_outcomes` (system table, no tenant data) and the active queue
gauges of the `*_index` tables in a system session; `render_prometheus` turns the result into
the Prometheus text exposition format 0.0.4:
- `cyberlab_jobs{kind,subkind,status,window}`: terminal jobs, runs and renders per window
  (1h, 24h, 7d);
- `cyberlab_job_failure_ratio{kind,subkind,window}`: failed over terminal;
- `cyberlab_job_duration_seconds{kind,subkind,phase,window,quantile}`: a summary (p50, p95,
  p99, plus `_sum` / `_count`) of the run and queue durations;
- `cyberlab_parse_success_ratio{kind,window}`: analyzers only, succeeded over (succeeded +
  failed with error class `parse`);
- `cyberlab_job_failures_by_class{kind,subkind,class,window}`;
- `cyberlab_jobs_active{kind,status}`: queued / running / waiting now.

Every label value comes from a fixed enum: kinds, subkinds (profiles, TI / AI providers,
report formats, `multi`, `none` for no subkind, `other` for anything unknown), statuses,
windows, phases, quantiles and error classes. Error codes are never labels: they are
classified first (`error_classes.classify`). One SQL statement per window, each under
`SET LOCAL statement_timeout = '2s'`.
"""

import math
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from cyberlab_jobs.static import Profile
from sqlalchemy import RowMapping, Text, bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.ai.catalog import AI_PROVIDER_NAMES
from app.modules.ai.contracts import RUN_ACTIVE as AI_RUN_ACTIVE
from app.modules.ops.error_classes import ErrorClass, classify
from app.modules.ops.models import KINDS
from app.modules.reports.dispatch import ACTIVE as RENDER_ACTIVE
from app.modules.reports.models import RENDER_FORMATS
from app.modules.threat_intel.catalog import PROVIDER_NAMES as TI_PROVIDER_NAMES
from app.modules.threat_intel.models import RUN_ACTIVE as TI_RUN_ACTIVE

WINDOWS: dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
}
ANALYZER_KINDS = ("pcap", "static")
NO_SUBKIND = "none"
OTHER = "other"
SUBKINDS: frozenset[str] = frozenset(
    {
        *(p.value for p in Profile),
        *TI_PROVIDER_NAMES,
        "multi",
        *AI_PROVIDER_NAMES,
        *RENDER_FORMATS,
        NO_SUBKIND,
        OTHER,
    }
)
# Terminal statuses of the four sources (the trigger's WHEN lists), plus `other`.
STATUSES: frozenset[str] = frozenset(
    {"succeeded", "failed", "completed", "partial", "refused", OTHER}
)
SUCCESS_STATUSES = ("succeeded", "completed")
FAILED = "failed"
PHASES = ("queue", "run")
QUANTILES = ("0.5", "0.95", "0.99")
# (kind, active statuses) of the gauges; every pair is reported, zeros included.
ACTIVE_STATUSES: dict[str, tuple[str, ...]] = {
    "pcap": ("queued", "running"),
    "static": ("queued", "running"),
    "ti": tuple(TI_RUN_ACTIVE),
    "ai": tuple(s.value for s in AI_RUN_ACTIVE),
    "report": tuple(RENDER_ACTIVE),
}
STATEMENT_TIMEOUT = "SET LOCAL statement_timeout = '2s'"

# One statement per window. Subkinds and statuses are mapped to the fixed enums in SQL, so the
# quantile groups are keyed exactly like the labels. GROUPING SETS: the fine rows (status,
# error code) give the counts; the (kind, subkind) rows give the duration quantiles.
_WINDOW_SQL = text(
    """
WITH o AS (
  SELECT kind,
         CASE WHEN subkind IS NULL THEN 'none'
              WHEN subkind = ANY(:subkinds) THEN subkind ELSE 'other' END AS subkind,
         CASE WHEN status = ANY(:statuses) THEN status ELSE 'other' END AS status,
         error_code, queue_ms, run_ms
  FROM job_outcomes
  WHERE finished_at > :since AND finished_at <= :now
)
SELECT kind, subkind, status, error_code,
       GROUPING(status, error_code) AS rollup,
       count(*) AS n,
       percentile_cont(ARRAY[0.5, 0.95, 0.99]) WITHIN GROUP (ORDER BY run_ms) AS run_q,
       percentile_cont(ARRAY[0.5, 0.95, 0.99]) WITHIN GROUP (ORDER BY queue_ms) AS queue_q,
       count(run_ms) AS run_n, coalesce(sum(run_ms), 0) AS run_sum,
       count(queue_ms) AS queue_n, coalesce(sum(queue_ms), 0) AS queue_sum
FROM o
GROUP BY GROUPING SETS ((kind, subkind, status, error_code), (kind, subkind))
"""
).bindparams(
    bindparam("subkinds", type_=ARRAY(Text)),
    bindparam("statuses", type_=ARRAY(Text)),
)

_ACTIVE_SQL = text(
    """
SELECT analyzer::text AS kind, status::text AS status, count(*) AS n
  FROM analysis_job_index WHERE status::text IN ('queued', 'running') GROUP BY 1, 2
UNION ALL
SELECT 'ti', status, count(*) FROM ti_run_index WHERE status = ANY(:ti) GROUP BY 2
UNION ALL
SELECT 'ai', status, count(*) FROM ai_run_index WHERE status = ANY(:ai) GROUP BY 2
UNION ALL
SELECT 'report', status, count(*) FROM report_render_index WHERE status = ANY(:report)
  GROUP BY 2
"""
).bindparams(
    bindparam("ti", type_=ARRAY(Text)),
    bindparam("ai", type_=ARRAY(Text)),
    bindparam("report", type_=ARRAY(Text)),
)


@dataclass(frozen=True)
class PlatformMetrics:
    generated_at: datetime
    # (kind, subkind, status, window) -> count
    jobs: dict[tuple[str, str, str, str], int] = field(default_factory=dict)
    # (kind, subkind, window) -> ratio
    failure_ratio: dict[tuple[str, str, str], float] = field(default_factory=dict)
    # (kind, subkind, phase "queue" | "run", window, quantile "0.5" | "0.95" | "0.99") -> s
    duration_seconds: dict[tuple[str, str, str, str, str], float] = field(default_factory=dict)
    # (kind, subkind, phase, window) -> (observations, sum in seconds): the summary's
    # `_count` / `_sum`.
    duration_totals: dict[tuple[str, str, str, str], tuple[int, float]] = field(
        default_factory=dict
    )
    # (analyzer, window) -> ratio
    parse_success_ratio: dict[tuple[str, str], float] = field(default_factory=dict)
    # (kind, subkind, error class, window) -> failed count
    failures_by_class: dict[tuple[str, str, str, str], int] = field(default_factory=dict)
    # (kind, status) -> gauge
    active: dict[tuple[str, str], int] = field(default_factory=dict)


@dataclass
class _Acc:
    """Per (kind, subkind) accumulation of one window."""

    statuses: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    classes: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    parse_failed: int = 0


async def platform_metrics(session: AsyncSession, *, now: datetime) -> PlatformMetrics:
    """The platform-wide numbers at `now` (aware datetime). `session` is a system session
    (`tenant_session(None, None)`): `job_outcomes` and the `*_index` tables hold no tenant
    data."""
    await session.execute(text(STATEMENT_TIMEOUT))
    m = PlatformMetrics(generated_at=now)
    for window, span in WINDOWS.items():
        rows = (
            await session.execute(
                _WINDOW_SQL,
                {
                    "since": now - span,
                    "now": now,
                    "subkinds": sorted(SUBKINDS),
                    "statuses": sorted(STATUSES),
                },
            )
        ).mappings()
        accs: dict[tuple[str, str], _Acc] = defaultdict(_Acc)
        for row in rows:
            kind, subkind = row["kind"], row["subkind"]
            if kind not in KINDS:  # pragma: no cover - CHECK constraint
                continue
            if row["rollup"]:
                _add_durations(m, kind, subkind, window, row)
                continue
            acc = accs[(kind, subkind)]
            acc.statuses[row["status"]] += row["n"]
            if row["status"] == FAILED:
                klass = classify(row["error_code"])
                acc.classes[klass.value] += row["n"]
                if klass is ErrorClass.PARSE:
                    acc.parse_failed += row["n"]
        parse: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for (kind, subkind), acc in accs.items():
            total = sum(acc.statuses.values())
            for status, n in acc.statuses.items():
                m.jobs[(kind, subkind, status, window)] = n
            if total:
                m.failure_ratio[(kind, subkind, window)] = acc.statuses.get(FAILED, 0) / total
            for class_name, n in acc.classes.items():
                m.failures_by_class[(kind, subkind, class_name, window)] = n
            if kind in ANALYZER_KINDS:
                ok = sum(acc.statuses.get(s, 0) for s in SUCCESS_STATUSES)
                parse[kind][0] += ok
                parse[kind][1] += ok + acc.parse_failed
        for kind, (ok, denominator) in parse.items():
            if denominator:
                m.parse_success_ratio[(kind, window)] = ok / denominator

    active = (
        await session.execute(
            _ACTIVE_SQL,
            {
                "ti": list(ACTIVE_STATUSES["ti"]),
                "ai": list(ACTIVE_STATUSES["ai"]),
                "report": list(ACTIVE_STATUSES["report"]),
            },
        )
    ).all()
    for kind, statuses in ACTIVE_STATUSES.items():
        for status in statuses:
            m.active[(kind, status)] = 0
    for kind, status, n in active:
        if (kind, status) in m.active:
            m.active[(kind, status)] += int(n)
    return m


def _add_durations(
    m: PlatformMetrics, kind: str, subkind: str, window: str, row: RowMapping
) -> None:
    for phase in PHASES:
        count = int(row[f"{phase}_n"])
        if not count:
            continue
        values = row[f"{phase}_q"]
        if isinstance(values, Sequence):
            for quantile, value in zip(QUANTILES, values, strict=True):
                if value is not None:
                    m.duration_seconds[(kind, subkind, phase, window, quantile)] = (
                        float(value) / 1000
                    )
        total = float(row[f"{phase}_sum"]) / 1000
        m.duration_totals[(kind, subkind, phase, window)] = (count, total)


# --- Prometheus text exposition 0.0.4 -------------------------------------------------------


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(pairs: Sequence[tuple[str, str]]) -> str:
    return "{" + ",".join(f'{k}="{_escape(v)}"' for k, v in pairs) + "}"


def _number(value: float) -> str:
    if isinstance(value, int):
        return str(value)
    if math.isnan(value) or math.isinf(value):  # pragma: no cover - never produced
        raise ValueError("metric values are finite")
    return repr(float(value))


def _family(
    out: list[str], name: str, kind: str, help_text: str, samples: list[tuple[str, str, float]]
) -> None:
    """`samples`: (sample name suffix, rendered labels, value)."""
    out.append(f"# HELP {name} {help_text}")
    out.append(f"# TYPE {name} {kind}")
    for suffix, labels, value in samples:
        out.append(f"{name}{suffix}{labels} {_number(value)}")


def render_prometheus(metrics: PlatformMetrics) -> str:
    """Text exposition format 0.0.4 (HELP and TYPE per family, escaped label values; series
    sorted, so the output is deterministic)."""
    out: list[str] = []
    _family(
        out,
        "cyberlab_jobs",
        "gauge",
        "Terminal analysis jobs, TI runs, AI runs and report renders in the window.",
        [
            ("", _labels([("kind", k), ("subkind", s), ("status", st), ("window", w)]), n)
            for (k, s, st, w), n in sorted(metrics.jobs.items())
        ],
    )
    _family(
        out,
        "cyberlab_job_failure_ratio",
        "gauge",
        "Failed over terminal in the window.",
        [
            ("", _labels([("kind", k), ("subkind", s), ("window", w)]), r)
            for (k, s, w), r in sorted(metrics.failure_ratio.items())
        ],
    )
    durations: list[tuple[str, str, float]] = []
    for (k, s, p, w), (count, total) in sorted(metrics.duration_totals.items()):
        base = [("kind", k), ("subkind", s), ("phase", p), ("window", w)]
        for q in QUANTILES:
            value = metrics.duration_seconds.get((k, s, p, w, q))
            if value is not None:
                durations.append(("", _labels([*base, ("quantile", q)]), value))
        durations.append(("_sum", _labels(base), total))
        durations.append(("_count", _labels(base), count))
    _family(
        out,
        "cyberlab_job_duration_seconds",
        "summary",
        "Queue (created to started) and run (started to finished) durations in the window.",
        durations,
    )
    _family(
        out,
        "cyberlab_parse_success_ratio",
        "gauge",
        "Analyzers: succeeded over (succeeded + failed with error class parse).",
        [
            ("", _labels([("kind", k), ("window", w)]), r)
            for (k, w), r in sorted(metrics.parse_success_ratio.items())
        ],
    )
    _family(
        out,
        "cyberlab_job_failures_by_class",
        "gauge",
        "Failed jobs, runs and renders in the window by error class.",
        [
            ("", _labels([("kind", k), ("subkind", s), ("class", c), ("window", w)]), n)
            for (k, s, c, w), n in sorted(metrics.failures_by_class.items())
        ],
    )
    _family(
        out,
        "cyberlab_jobs_active",
        "gauge",
        "Jobs, runs and renders queued, running or waiting now.",
        [
            ("", _labels([("kind", k), ("status", st)]), n)
            for (k, st), n in sorted(metrics.active.items())
        ],
    )
    return "\n".join(out) + "\n"
