"""The committed cases and golden files: format, twins, payloads, seeding, natural keys."""

import json
import secrets
from urllib.parse import quote

import pytest
from sqlalchemy import func, select

from app.core.tenancy import tenant_session
from app.modules.ai.contracts import AiTask
from app.modules.threat_intel.models import TiResult
from tests.ai_eval import cases as c
from tests.ai_eval.golden import golden_names, load_golden
from tests.ai_eval.inject_payloads import PAYLOADS
from tests.integration.seed import seed_tenant

NAMES = c.case_names()
# Built from parts: the whole EICAR string must never sit in a committed file (host AV).
EICAR_MARK = "EICAR-STANDARD-" + "ANTIVIRUS-TEST-FILE"


def test_there_is_a_clean_and_injected_twin_for_every_scenario() -> None:
    clean = c.clean_names()
    assert len(clean) >= 26
    pcap = {n for n in clean if n.startswith("pcap_")}
    assert {
        f"pcap_{s}"
        for s in (
            "normal_web",
            "dns_traffic",
            "tls_sessions",
            "beacon",
            "dns_anomalies",
            "port_scan",
            "suspicious_http",
            "mixed",
        )
    } <= pcap
    assert any(c.load_case(n).kind == "investigation" for n in clean)
    for name in clean:
        twin = name + c.TWIN_SUFFIX
        if name != "static_eicar":  # labels.json has no EICAR twin
            assert twin in NAMES, twin
    for name in NAMES:
        case = c.load_case(name)
        assert case.base in clean
        assert set(golden_names()) >= {case.base}
        for task in case.tasks:
            AiTask(task)


@pytest.mark.parametrize("name", NAMES)
def test_committed_form_is_canonical(name: str) -> None:
    path = c.CASES_DIR / f"{name}.json"
    text = path.read_text(encoding="utf-8")
    assert text == c.dumps_case(json.loads(text))
    assert EICAR_MARK not in text


@pytest.mark.parametrize("name", [n for n in NAMES if n.endswith(c.TWIN_SUFFIX)])
def test_injected_twins_plant_the_shared_payloads(name: str) -> None:
    case = c.load_case(name)
    assert case.plants and case.clean
    seen = set()
    for plant in case.plants:
        pid, carrier, value = plant["payload"], plant["carrier"], plant["value"]
        seen.add(pid)
        text = PAYLOADS[pid]
        if carrier == "dns.query":
            assert value.replace(".", "").startswith(text.replace(".", ""))
            assert all(len(label.encode()) <= 63 for label in value.split("."))
        elif carrier == "http.uri":
            assert value == "/" + quote(text, safe="/:;!")
        else:
            assert value == text, (carrier, value)
    assert {"P1", "P2", "P8"} <= seen
    clean = c.load_case(case.clean or "")
    assert clean.tasks == case.tasks and clean.kind == case.kind


def test_every_golden_file_is_valid() -> None:
    for name in golden_names():
        golden = load_golden(name)
        assert name in NAMES
        for m in golden.must_mention:
            assert m.table in c.TABLES


async def test_every_case_seeds_and_every_natural_key_resolves() -> None:
    for name in NAMES:
        case = c.load_case(name)
        tenant = await seed_tenant(f"case{secrets.token_hex(6)}")
        seeded = await c.seed_case(case, tenant)
        golden = load_golden(case.base)
        for m in golden.must_mention:
            seeded.resolve(m.table, m.where, m.job)  # exactly one row, or CaseError
        for plant in case.plants:
            if plant.get("table"):
                assert seeded.find(plant["table"], plant["where"], plant.get("job")), plant
        async with tenant_session(tenant.org_id, tenant.owner_id) as s:
            for job in case.jobs:
                for table_name, rows in job["tables"].items():
                    table = c.TABLES[table_name]
                    count = await s.scalar(
                        select(func.count())
                        .select_from(table)
                        .where(table.c.job_id == seeded.job_ids[job["key"]])
                    )
                    assert count == len(rows), (name, table_name)
            ti = await s.scalar(select(func.count()).select_from(TiResult))
            assert ti == len(case.ti), name


async def test_ambiguous_or_missing_keys_fail_loudly() -> None:
    case = c.load_case("pcap_port_scan")
    seeded = await c.seed_case(case, await seed_tenant(f"case{secrets.token_hex(6)}"))
    with pytest.raises(c.CaseError):
        seeded.resolve("analysis_findings", {"src_ip": "10.0.4.40"})  # two scans
    with pytest.raises(c.CaseError):
        seeded.resolve("analysis_findings", {"type": "beaconing"})
    with pytest.raises(c.CaseError):
        seeded.resolve("no_such_table", {"x": 1})


def test_row_ids_sort_in_case_order_whatever_the_salt() -> None:
    for _ in range(20):
        salt = secrets.token_bytes(8)
        ids = [
            c.case_uuid(salt, 16 + t, j, n) for t in range(3) for j in range(2) for n in (0, 1, 300)
        ]
        assert [i.bytes for i in ids] == sorted(i.bytes for i in ids)


def test_case_rows_reject_unknown_columns() -> None:
    with pytest.raises(c.CaseError):
        c.from_json_row(c.TABLES["iocs"], {"id": "x"})
    with pytest.raises(c.CaseError):
        c.from_json_row(c.TABLES["iocs"], {"organization": "x"})
