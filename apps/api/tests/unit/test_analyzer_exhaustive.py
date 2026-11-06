"""Every analyzer-keyed map and Literal covers every `Analyzer` member (M8 phase 1, RT1).

Before M8 a dozen two-way branches sent "not static" to the pcap code path: a memory job would
have linked to `/pcap/{id}`, failed the org operations page (`kind: Literal["pcap",
"static"]`), built a pcap AI digest and mislabelled citations and timeline titles. Each map
below is the single place its branch reads from; a new analyzer fails here first.

M9 phase 1 adds `disk` (route `forensics`, profiles `triage` / `full` / `extract`); M10 phase 1
`reverse` (route `reverse-engineering`, profiles `quick` / `full`, RT10).
"""

import typing
import uuid

import pytest

from app.core.config import Settings
from app.modules.ai.schemas import DeepLinkRoute
from app.modules.ai.service_outputs import ANALYZER_LINKS
from app.modules.analysis import analyzers
from app.modules.analysis.dispatch import task_and_queue
from app.modules.analysis.models import (
    ANALYZER_ROUTES,
    ANALYZER_TITLES,
    DEFAULT_PROFILE,
    PROFILES,
    Analyzer,
    JobProfile,
    analyzer_route,
)
from app.modules.analysis.schemas import AnalysisCreate
from app.modules.analysis.service import TOO_LARGE
from app.modules.case_attack.sources import Resolved, path
from app.modules.investigations.timeline import _ANALYZER_TITLE
from app.modules.ops.metrics import ACTIVE_STATUSES, ANALYZER_KINDS, SUBKINDS
from app.modules.ops.models import KINDS
from app.modules.ops.schemas import AnalyzerKind, OutcomeKind, RecentFailureOut
from app.modules.reports.citations import _TABS
from app.modules.search.service import _job_href
from app.workers.ingest import SUCCESS_INGESTERS

ALL = {a.value for a in Analyzer}
SETTINGS = Settings(
    database_url="postgresql+asyncpg://cyberlab_app:x@postgres/cyberlab",
    redis_url="redis://redis:6379/0",
    jwt_secret="x" * 48,
    minio_endpoint="minio:9000",
    minio_access_key="a",
    minio_secret_key="b",
    broker_url="redis://api:x@redis-broker:6379/0",
)


def test_memory_disk_and_reverse_are_analyzers() -> None:
    assert ALL == {"pcap", "static", "memory", "disk", "reverse"}


@pytest.mark.parametrize(
    "mapping",
    [ANALYZER_ROUTES, ANALYZER_TITLES, PROFILES, DEFAULT_PROFILE, TOO_LARGE, SUCCESS_INGESTERS],
    ids=["routes", "titles", "profiles", "default_profile", "too_large", "ingesters"],
)
def test_analyzer_keyed_maps_are_complete(mapping: typing.Mapping[Analyzer, object]) -> None:
    assert set(mapping) == set(Analyzer)


def test_routes_are_distinct_and_memory_has_its_own() -> None:
    assert ANALYZER_ROUTES[Analyzer.MEMORY] == "memory"
    assert ANALYZER_ROUTES[Analyzer.DISK] == "forensics"
    assert ANALYZER_ROUTES[Analyzer.REVERSE] == "reverse-engineering"
    assert len(set(ANALYZER_ROUTES.values())) == len(Analyzer)
    assert analyzer_route("memory") == "memory" and analyzer_route("nope") is None
    assert set(ANALYZER_ROUTES.values()) <= set(typing.get_args(DeepLinkRoute))


def test_per_analyzer_parameters_and_queues() -> None:
    for analyzer in Analyzer:
        assert analyzers.max_bytes(SETTINGS, analyzer) > 0
        assert analyzers.timeout_s(SETTINGS, analyzer) > 0
        assert analyzers.max_result_bytes(SETTINGS, analyzer) > 0
        task, queue = task_and_queue(analyzer, SETTINGS)
        assert task == f"{analyzer.value}.analyze"
        assert queue == f"{SETTINGS.queue_prefix}{analyzer.value}"
    assert analyzers.max_bytes(SETTINGS, Analyzer.MEMORY) == SETTINGS.memory_max_bytes
    assert analyzers.max_bytes(SETTINGS, Analyzer.DISK) == SETTINGS.disk_max_upload_bytes
    assert analyzers.timeout_s(SETTINGS, Analyzer.DISK) == SETTINGS.analysis_disk_timeout_s
    assert analyzers.max_bytes(SETTINGS, Analyzer.REVERSE) == SETTINGS.re_max_bytes
    assert analyzers.timeout_s(SETTINGS, Analyzer.REVERSE) == SETTINGS.analysis_re_timeout_s
    assert analyzers.max_result_bytes(SETTINGS, Analyzer.REVERSE) == SETTINGS.re_max_result_bytes


def test_profiles_per_analyzer() -> None:
    assert PROFILES[Analyzer.PCAP] == frozenset()
    assert PROFILES[Analyzer.STATIC] == {JobProfile.FULL, JobProfile.AV}
    assert PROFILES[Analyzer.MEMORY] == {JobProfile.TRIAGE, JobProfile.FULL}
    assert PROFILES[Analyzer.DISK] == {JobProfile.TRIAGE, JobProfile.FULL, JobProfile.EXTRACT}
    assert PROFILES[Analyzer.REVERSE] == {JobProfile.QUICK, JobProfile.FULL}
    reverse = AnalysisCreate(analyzer=Analyzer.REVERSE, decompile_addresses=["0x401000"])
    assert (reverse.profile, reverse.os_hint) == (JobProfile.FULL, None)
    assert reverse.decompile_address_values() == [0x401000]
    disk = AnalysisCreate(analyzer=Analyzer.DISK, segments=[uuid.uuid4()])
    assert (disk.profile, disk.os_hint) == (JobProfile.TRIAGE, "auto")
    assert AnalysisCreate(analyzer=Analyzer.MEMORY).profile is JobProfile.TRIAGE
    assert AnalysisCreate(analyzer=Analyzer.MEMORY).os_hint == "auto"
    assert AnalysisCreate(analyzer=Analyzer.STATIC).profile is JobProfile.FULL
    assert AnalysisCreate(analyzer=Analyzer.PCAP).profile is None
    for bad in (
        {"analyzer": "memory", "profile": "av"},
        {"analyzer": "static", "profile": "triage"},
        {"analyzer": "pcap", "profile": "full"},
        {"analyzer": "static", "os_hint": "linux"},
        {"analyzer": "memory", "os_hint": "macos"},
        {"analyzer": "disk"},  # no segments
        {"analyzer": "disk", "segments": []},
        {"analyzer": "disk", "segments": [str(uuid.UUID(int=1))] * 2},
        {"analyzer": "disk", "segments": [str(uuid.uuid4())], "profile": "extract"},
        {"analyzer": "disk", "segments": [str(uuid.uuid4())], "profile": "av"},
        {"analyzer": "static", "segments": [str(uuid.uuid4())]},
        {"analyzer": "reverse", "profile": "triage"},
        {"analyzer": "reverse", "os_hint": "auto"},
        {"analyzer": "reverse", "profile": "quick", "decompile_addresses": ["0x1"]},
        {"analyzer": "reverse", "decompile_addresses": ["0x1", "0x1"]},
        {"analyzer": "reverse", "decompile_addresses": ["0x12345678901234567"]},
        {"analyzer": "static", "source_job_id": str(uuid.uuid4())},
    ):
        with pytest.raises(ValueError):
            AnalysisCreate.model_validate(bad)


def test_ops_kinds_and_literals_cover_every_analyzer() -> None:
    assert set(ANALYZER_KINDS) == ALL
    assert ALL <= set(KINDS)
    assert ALL <= set(ACTIVE_STATUSES)
    assert set(typing.get_args(AnalyzerKind)) == ALL
    assert ALL <= set(typing.get_args(OutcomeKind))
    assert {"triage", "full", "av", "extract", "quick"} <= SUBKINDS
    # A failed memory job renders on the org operations page (RT1).
    RecentFailureOut(
        job_id=uuid.uuid4(),
        kind="memory",
        subkind="triage",
        error_code="symbols_missing",
        error_class="input",
        finished_at=None,
        investigation_id=uuid.uuid4(),
        evidence_id=uuid.uuid4(),
        href="/memory/x",
    )


def test_timeline_titles_cover_every_analyzer() -> None:
    assert set(_ANALYZER_TITLE) == ALL
    assert _ANALYZER_TITLE["memory"] == "Memory analysis"
    assert _ANALYZER_TITLE["disk"] == "Disk analysis"


def test_links_of_memory_jobs_go_to_the_memory_page() -> None:
    job = uuid.uuid4()
    assert _job_href("memory", job, "findings") == f"/memory/{job}?tab=findings"
    assert _job_href("static", job, "iocs") == f"/malware/{job}?tab=iocs"
    assert _job_href("pcap", job, "alerts") == f"/pcap/{job}?tab=alerts"
    org = uuid.uuid4()
    finding = Resolved("finding", "r1", job, None, "memory")
    assert path(org, finding) == f"/o/{org}/memory/{job}?tab=findings&ref=r1"
    assert set(ANALYZER_LINKS) == ALL
    assert ANALYZER_LINKS["memory"][0] == "memory"
    assert ANALYZER_LINKS["disk"][0] == "forensics"
    assert _job_href("disk", job, "findings") == f"/forensics/{job}?tab=findings"
    assert ANALYZER_LINKS["reverse"][0] == "reverse-engineering"
    assert _job_href("reverse", job, "iocs") == f"/reverse-engineering/{job}?tab=iocs"
    re_finding = Resolved("finding", "r3", job, None, "reverse")
    assert path(org, re_finding) == f"/o/{org}/reverse-engineering/{job}?tab=findings&ref=r3"
    disk_finding = Resolved("finding", "r2", job, None, "disk")
    assert path(org, disk_finding) == f"/o/{org}/forensics/{job}?tab=findings&ref=r2"
    for table in ("analysis_findings", "iocs", "analysis_jobs"):
        assert set(_TABS[table]) == ALL, table


def test_a_failed_disk_job_renders_on_the_operations_page() -> None:
    RecentFailureOut(
        job_id=uuid.uuid4(),
        kind="disk",
        subkind="extract",
        error_code="no_supported_filesystem",
        error_class="input",
        finished_at=None,
        investigation_id=uuid.uuid4(),
        evidence_id=uuid.uuid4(),
        href="/forensics/x",
    )


def test_a_failed_re_job_renders_on_the_operations_page() -> None:
    RecentFailureOut(
        job_id=uuid.uuid4(),
        kind="reverse",
        subkind="quick",
        error_code="unsupported_architecture",
        error_class="input",
        finished_at=None,
        investigation_id=uuid.uuid4(),
        evidence_id=uuid.uuid4(),
        href="/reverse-engineering/x",
    )
    assert _ANALYZER_TITLE["reverse"] == "Reverse engineering"
