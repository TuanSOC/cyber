"""`render_prometheus` (M7 phase 5): the text exposition format 0.0.4, checked by a strict
validator (`prometheus_client` is not in the lock, so a small regex parser), fixed label
enums only, escaped label values, deterministic output."""

import math
import re
from datetime import UTC, datetime

import pytest

from app.modules.ops.error_classes import ErrorClass
from app.modules.ops.metrics import (
    ACTIVE_STATUSES,
    PHASES,
    QUANTILES,
    STATUSES,
    SUBKINDS,
    WINDOWS,
    PlatformMetrics,
    _escape,
    render_prometheus,
)
from app.modules.ops.models import KINDS

NAME = r"[a-zA-Z_:][a-zA-Z0-9_:]*"
LABEL_VALUE = r'"(?:[^"\\\n]|\\\\|\\"|\\n)*"'
LABEL = rf"[a-zA-Z_][a-zA-Z0-9_]*={LABEL_VALUE}"
SAMPLE = re.compile(
    rf"^(?P<name>{NAME})(?:\{{(?P<labels>{LABEL}(?:,{LABEL})*)?\}})? (?P<value>\S+)$"
)
HELP = re.compile(rf"^# HELP (?P<name>{NAME}) (?P<text>.*)$")
TYPE = re.compile(rf"^# TYPE (?P<name>{NAME}) (?P<type>counter|gauge|summary|histogram|untyped)$")
LABEL_PAIR = re.compile(rf"([a-zA-Z_][a-zA-Z0-9_]*)=({LABEL_VALUE})")

FAMILIES = {
    "cyberlab_jobs": ("gauge", {"kind", "subkind", "status", "window"}),
    "cyberlab_job_failure_ratio": ("gauge", {"kind", "subkind", "window"}),
    "cyberlab_job_duration_seconds": ("summary", {"kind", "subkind", "phase", "window"}),
    "cyberlab_parse_success_ratio": ("gauge", {"kind", "window"}),
    "cyberlab_job_failures_by_class": ("gauge", {"kind", "subkind", "class", "window"}),
    "cyberlab_jobs_active": ("gauge", {"kind", "status"}),
}
ACTIVE = {s for statuses in ACTIVE_STATUSES.values() for s in statuses}
ALLOWED_VALUES = {
    "kind": set(KINDS),
    "subkind": set(SUBKINDS),
    "status": set(STATUSES) | ACTIVE,
    "window": set(WINDOWS),
    "phase": set(PHASES),
    "quantile": set(QUANTILES),
    "class": {c.value for c in ErrorClass},
}


def _unescape(raw: str) -> str:
    return re.sub(r"\\(.)", lambda m: "\n" if m.group(1) == "n" else m.group(1), raw[1:-1])


def parse(text: str) -> dict[str, list[tuple[str, dict[str, str], float]]]:
    """Strict 0.0.4 parse: HELP then TYPE once per family before its samples, every sample in
    a declared family (summary: base / `_sum` / `_count`), finite values, unique series."""
    assert text.endswith("\n") and not text.endswith("\n\n")
    families: dict[str, list[tuple[str, dict[str, str], float]]] = {}
    types: dict[str, str] = {}
    helped: set[str] = set()
    current: str | None = None
    seen: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
    for line in text[:-1].split("\n"):
        if m := HELP.match(line):
            assert m["name"] not in helped, f"duplicate HELP {line}"
            helped.add(m["name"])
            continue
        if m := TYPE.match(line):
            name = m["name"]
            assert name in helped and name not in types, f"TYPE out of order: {line}"
            types[name] = m["type"]
            families[name] = []
            current = name
            continue
        assert not line.startswith("#"), f"unexpected comment {line!r}"
        m = SAMPLE.match(line)
        assert m, f"not a valid sample line: {line!r}"
        assert current is not None
        name = m["name"]
        allowed = {current}
        if types[current] == "summary":
            allowed |= {f"{current}_sum", f"{current}_count"}
        assert name in allowed, f"{name} outside family {current}"
        labels = {k: _unescape(v) for k, v in LABEL_PAIR.findall(m["labels"] or "")}
        value = float(m["value"])
        assert math.isfinite(value)
        series = (name, tuple(sorted(labels.items())))
        assert series not in seen, f"duplicate series {line}"
        seen.add(series)
        families[current].append((name, labels, value))
    return families


def _sample() -> PlatformMetrics:
    m = PlatformMetrics(generated_at=datetime(2026, 11, 6, tzinfo=UTC))
    m.jobs[("pcap", "none", "succeeded", "1h")] = 3
    m.jobs[("pcap", "none", "failed", "1h")] = 1
    m.jobs[("static", "full", "failed", "24h")] = 2
    m.jobs[("ti", "multi", "partial", "7d")] = 5
    m.failure_ratio[("pcap", "none", "1h")] = 0.25
    m.failure_ratio[("static", "full", "24h")] = 1.0
    m.duration_seconds[("pcap", "none", "run", "1h", "0.5")] = 1.5
    m.duration_seconds[("pcap", "none", "run", "1h", "0.95")] = 2.25
    m.duration_seconds[("pcap", "none", "run", "1h", "0.99")] = 2.9
    m.duration_totals[("pcap", "none", "run", "1h")] = (4, 6.5)
    m.duration_totals[("pcap", "none", "queue", "1h")] = (4, 0.04)
    m.duration_seconds[("pcap", "none", "queue", "1h", "0.5")] = 0.01
    m.parse_success_ratio[("pcap", "1h")] = 0.75
    m.failures_by_class[("pcap", "none", "parse", "1h")] = 1
    m.failures_by_class[("static", "full", "infra", "24h")] = 2
    for kind, statuses in ACTIVE_STATUSES.items():
        for status in statuses:
            m.active[(kind, status)] = 0
    m.active[("pcap", "running")] = 2
    return m


def test_render_is_valid_exposition_with_fixed_labels() -> None:
    text = render_prometheus(_sample())
    families = parse(text)
    assert set(families) == set(FAMILIES)
    for name, (kind, labels) in FAMILIES.items():
        assert f"# TYPE {name} {kind}\n" in text
        for sample, got, _ in families[name]:
            expected = labels | ({"quantile"} if sample == name and kind == "summary" else set())
            assert set(got) == expected, (sample, got)
            for label, value in got.items():
                assert value in ALLOWED_VALUES[label], (label, value)
    assert 'cyberlab_jobs{kind="pcap",subkind="none",status="succeeded",window="1h"} 3\n' in text
    assert "cyberlab_job_failure_ratio" in text and " 0.25\n" in text
    summary = families["cyberlab_job_duration_seconds"]
    duration = {(s, lb.get("quantile")): v for s, lb, v in summary}
    assert duration[("cyberlab_job_duration_seconds", "0.95")] == 2.25
    assert duration[("cyberlab_job_duration_seconds_count", None)] == 4
    assert 'cyberlab_jobs_active{kind="pcap",status="running"} 2\n' in text
    assert len(families["cyberlab_jobs_active"]) == sum(map(len, ACTIVE_STATUSES.values()))


def test_render_is_deterministic_and_valid_when_empty() -> None:
    m = _sample()
    assert render_prometheus(m) == render_prometheus(m)
    empty = render_prometheus(PlatformMetrics(generated_at=datetime.now(UTC)))
    families = parse(empty)
    assert set(families) == set(FAMILIES)
    assert all(not samples for samples in families.values())


def test_summary_without_observations_has_no_series() -> None:
    m = PlatformMetrics(generated_at=datetime.now(UTC))
    m.jobs[("report", "pdf", "failed", "1h")] = 1  # never started: no durations
    text = render_prometheus(m)
    assert "cyberlab_job_duration_seconds{" not in text
    assert "cyberlab_job_duration_seconds_count" not in text


@pytest.mark.parametrize(
    ("raw", "escaped"),
    [('a"b', 'a\\"b'), ("a\\b", "a\\\\b"), ("a\nb", "a\\nb"), ("plain", "plain")],
)
def test_label_values_are_escaped(raw: str, escaped: str) -> None:
    assert _escape(raw) == escaped
    m = PlatformMetrics(generated_at=datetime.now(UTC))
    m.active[("pcap", raw)] = 1  # not a real status: only the escaping is checked here
    [(_, labels, _)] = parse(render_prometheus(m))["cyberlab_jobs_active"]
    assert labels["status"] == raw


def test_validator_rejects_malformed_text() -> None:
    good = "# HELP x y\n# TYPE x gauge\nx 1\n"
    parse(good)
    for bad in (
        "# TYPE x gauge\nx 1\n",  # no HELP
        "# HELP x y\n# TYPE x gauge\nx{a=b} 1\n",  # unquoted label value
        "# HELP x y\n# TYPE x gauge\nx 1\nx 2\n",  # duplicate series
        "# HELP x y\n# TYPE x gauge\nz 1\n",  # outside its family
        "# HELP x y\n# TYPE x gauge\nx NaN\n",  # not finite
        "# HELP x y\n# TYPE x gauge\nx 1",  # no final newline
    ):
        with pytest.raises((AssertionError, ValueError)):
            parse(bad)
