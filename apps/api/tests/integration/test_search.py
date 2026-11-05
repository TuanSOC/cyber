"""Org search (M7 phase 4): `POST /orgs/{org}/search` (RT13).

Every type finds its seeded row and never another org's; deleted notes are absent; hostile
FTS input never 500s; a per-type timeout is isolated (`partial`); the rate limit answers
429; the query text never reaches the logs (also on a 422 and a timeout); `GET` is 405; the
queries use the phase-1 indexes (EXPLAIN with sequential scans disabled, so an expression
drift shows up as a Seq Scan on any volume).
"""

import json
import logging
import secrets
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import text, update
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.investigations.models import Investigation
from app.modules.pcap_analysis.models import AnalysisFinding, NetworkAlert
from app.modules.search import queries, service
from tests.factories import csrf, register
from tests.integration.seed import Tenant
from tests.integration.test_correlation_indexer import member_client, seed_indexed
from tests.integration.test_search_perf import RLS_PLANS, seed_volume
from tests.ops_helpers import CorrelatedSeed, now

API = "/api/v1/orgs"
WORD = "quokka"


async def _case_number(t: Tenant, case_id: uuid.UUID) -> int:
    async with tenant_session(t.org_id, None) as s:
        return int(
            (
                await s.execute(
                    text("SELECT case_number FROM investigations WHERE id = :i"), {"i": case_id}
                )
            ).scalar_one()
        )


async def _decorate(t: Tenant, case_id: uuid.UUID, job_id: uuid.UUID, tag: str) -> None:
    """A case description, a finding and an alert carrying WORD (plus a per-org tag)."""
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            update(Investigation)
            .where(Investigation.id == case_id)
            .values(description=f"Beaconing to {WORD} infrastructure ({tag})")
        )
        s.add(
            AnalysisFinding(
                organization_id=t.org_id,
                job_id=job_id,
                finding_id=uuid.uuid4(),
                type="beacon",
                title=f"Periodic {WORD} beacon",
                description=f"Regular callbacks every 60 s ({tag})",
                severity="high",
                confidence=0.9,
                detection_method="interval",
                ts=now(),
                evidence_refs=[],
                attributes={},
            )
        )
        s.add(
            NetworkAlert(
                organization_id=t.org_id,
                job_id=job_id,
                ts=now(),
                signature_id=2_000_000 + secrets.randbelow(1000),
                rev=1,
                signature=f"ET MALWARE {WORD.title()} CnC Checkin",
                category="A Network Trojan was detected",
                severity=1,
            )
        )


async def _note(c: AsyncClient, org_id: uuid.UUID, case_id: uuid.UUID, body: str) -> str:
    r = await c.post(
        f"{API}/{org_id}/investigations/{case_id}/notes", json={"body": body}, headers=csrf(c)
    )
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


async def _world() -> tuple[CorrelatedSeed, AsyncClient, dict[str, str]]:
    seed = await seed_indexed()
    a, b = seed.org_a, seed.org_b
    await _decorate(a, seed.case_a1, seed.job_a1, "org a")
    await _decorate(b, seed.case_b, seed.job_b, "org b")
    c = await member_client(a.org_id)
    cb = await member_client(b.org_id)
    kept = await _note(c, a.org_id, seed.case_a1, f"Pivot on the {WORD} domain next")
    deleted = await _note(c, a.org_id, seed.case_a1, f"Wrong {WORD} lead, ignore")
    r = await c.delete(f"{API}/{a.org_id}/notes/{deleted}", headers=csrf(c))
    assert r.status_code == 204, r.text
    other = await _note(cb, b.org_id, seed.case_b, f"Org B {WORD} note")
    return seed, c, {"kept": kept, "deleted": deleted, "other": other}


async def _search(c: AsyncClient, org_id: uuid.UUID, q: str, **body: Any) -> dict[str, Any]:
    r = await c.post(f"{API}/{org_id}/search", json={"q": q, **body}, headers=csrf(c))
    assert r.status_code == 200, r.text
    return dict(r.json())


def _groups(body: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    return {g["type"]: g["hits"] for g in body["groups"]}


async def test_every_type_finds_its_row_and_never_another_orgs() -> None:
    seed, c, notes = await _world()
    org = seed.org_a.org_id
    org_a_cases = {str(seed.case_a1), str(seed.case_a2)}
    async with tenant_session(org, seed.org_a.owner_id) as s:
        await s.execute(
            update(Investigation).where(Investigation.id == seed.case_a1).values(tlp="red")
        )
    body = await _search(c, org, WORD)
    groups = _groups(body)
    assert [g["type"] for g in body["groups"]] == [
        "observable",
        "case",
        "evidence",
        "finding",
        "alert",
        "note",
    ]
    assert body["partial"] is False
    [case] = groups["case"]
    assert (case["id"], case["match"]) == (str(seed.case_a1), "fts")
    assert case["case_ref"].startswith("CASE-") and WORD in case["snippet"]
    assert case["href"] == f"/investigations/{seed.case_a1}"
    # M7 follow-up: the case TLP on every hit, and the matches in the snippet as ranges.
    assert case["tlp"] == "red"
    assert [case["snippet"][r["start"] : r["end"]] for r in case["snippet_ranges"]] == [WORD]
    [finding] = groups["finding"]
    assert finding["job_id"] == str(seed.job_a1) and finding["href"].endswith("?tab=findings")
    [alert] = groups["alert"]
    assert alert["title"] == "ET MALWARE Quokka CnC Checkin"
    assert alert["href"] == f"/pcap/{seed.job_a1}?tab=alerts"
    [note] = groups["note"]  # the deleted note and org B's note are absent
    assert note["id"] == notes["kept"] and note["href"].endswith("?tab=notes")
    for hits in groups.values():
        for hit in hits:
            assert hit["investigation_id"] in org_a_cases
            assert "org b" not in (hit["snippet"] or "")
            expected = "red" if hit["investigation_id"] == str(seed.case_a1) else "amber"
            assert hit["tlp"] == expected, hit
    assert [note["snippet"][r["start"] : r["end"]] for r in note["snippet_ranges"]] == [WORD]
    assert all(g["error"] is None for g in body["groups"])

    observables = _groups(await _search(c, org, "C2.Shared-Example.NET"))["observable"]
    [domain] = observables
    assert (domain["kind"], domain["match"], domain["title"]) == (
        "domain",
        "exact",
        "c2.shared-example.net",
    )
    assert domain["snippet"] == "domain, seen in 2 jobs" and domain["href"].endswith("?tab=iocs")
    assert domain["investigation_id"] in org_a_cases
    # A summary, not matched text: no ranges.
    assert domain["snippet_ranges"] == [] and domain["tlp"] in {"red", "amber"}
    partial = _groups(await _search(c, org, "shared-exam", types=["observable"]))["observable"]
    assert [(h["kind"], h["match"]) for h in partial] == [("domain", "trigram")]

    evidence = _groups(await _search(c, org, "shared.pcap", types=["evidence"]))["evidence"]
    assert len(evidence) == 2 and {h["investigation_id"] for h in evidence} == org_a_cases

    number = await _case_number(seed.org_a, seed.case_a2)
    by_number = _groups(await _search(c, org, f"CASE-{number:05d}", types=["case"]))["case"]
    assert [(h["id"], h["match"]) for h in by_number] == [(str(seed.case_a2), "exact")]


async def test_types_and_cursor_select_the_groups() -> None:
    seed, c, _ = await _world()
    body = await _search(c, seed.org_a.org_id, WORD, types=["note", "case", "note"])
    assert [g["type"] for g in body["groups"]] == ["case", "note"]
    assert all(g["next_cursor"] is None for g in body["groups"])
    cursor = service.encode_cursor("finding", 20)
    body = await _search(c, seed.org_a.org_id, WORD, cursor=cursor)
    assert [(g["type"], g["hits"]) for g in body["groups"]] == [("finding", [])]
    r = await c.post(
        f"{API}/{seed.org_a.org_id}/search",
        json={"q": WORD, "cursor": "bm90LWEtY3Vyc29y"},
        headers=csrf(c),
    )
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_cursor"


async def test_the_next_cursor_pages_one_type(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "search_hits_per_type", 1)
    seed, c, _ = await _world()
    first = await _search(c, seed.org_a.org_id, "shared.pcap", types=["evidence"])
    [group] = first["groups"]
    assert len(group["hits"]) == 1 and group["next_cursor"]
    second = await _search(c, seed.org_a.org_id, "shared.pcap", cursor=group["next_cursor"])
    [group2] = second["groups"]
    assert len(group2["hits"]) == 1 and group2["next_cursor"] is None
    assert group2["hits"][0]["id"] != group["hits"][0]["id"]


@pytest.mark.parametrize(
    "q",
    [
        '""',
        '"quokka',
        "quokka & | ! beacon",
        "!!!",
        "'; DROP TABLE investigations; --",
        "a:* | b:*",
        "(((",
        "<script>alert(1)</script>",
        "%_\\%",
        "日本語 検索",
        "ü" * 256,
        "-quokka or -",
    ],
)
async def test_hostile_queries_never_fail(q: str) -> None:
    reg = await register()
    body = await _search(reg.client, reg.org_id, q)
    assert body["partial"] is False
    assert "<script>" not in json.dumps(body)


@pytest.mark.parametrize("q", [" a ", "x" * 257, "ab\x01cd", "  \t  "])
async def test_an_invalid_query_is_422_without_echo(q: str) -> None:
    reg = await register()
    c = reg.client
    r = await c.post(f"{API}/{reg.org_id}/search", json={"q": q}, headers=csrf(c))
    assert r.status_code == 422
    assert r.json()["error"]["code"] in {"search_query_invalid", "validation_error"}
    if len(q.strip()) >= 3:
        assert q.strip() not in r.text


async def test_get_is_405_and_csrf_applies() -> None:
    reg = await register()
    c = reg.client
    r = await c.get(f"{API}/{reg.org_id}/search", params={"q": WORD})
    assert r.status_code == 405
    r = await c.post(f"{API}/{reg.org_id}/search", json={"q": WORD})
    assert r.status_code == 403


async def test_the_rate_limit_answers_429(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "search_per_user_per_min", 2)
    reg = await register()
    c = reg.client
    for _ in range(2):
        await _search(c, reg.org_id, WORD)
    r = await c.post(f"{API}/{reg.org_id}/search", json={"q": WORD}, headers=csrf(c))
    assert r.status_code == 429 and r.headers["Retry-After"]


async def _slow(*_: Any) -> service.Page:
    session = _[0]
    await session.execute(text("SELECT pg_sleep(5)"))
    return [], False


async def test_a_timeout_is_isolated_per_type_and_nothing_logs_the_query(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    secret = f"{WORD} or zebra-{secrets.token_hex(6)}"
    caplog.set_level(logging.DEBUG, logger="app")
    caplog.set_level(logging.DEBUG, logger="uvicorn")
    seed, c, _ = await _world()
    monkeypatch.setattr(get_settings(), "search_statement_timeout_s", 1)
    monkeypatch.setitem(service.RUNNERS, "case", _slow)
    body = await _search(c, seed.org_a.org_id, secret)
    assert body["partial"] is True
    groups = {g["type"]: g for g in body["groups"]}
    assert groups["case"]["hits"] == [] and groups["case"]["next_cursor"] is None
    # M7 follow-up: the timed-out group says so itself; the others carry no error.
    assert groups["case"]["error"] == "timeout"
    assert {t: g["error"] for t, g in groups.items() if t != "case"} == dict.fromkeys(
        ("observable", "evidence", "finding", "alert", "note")
    )
    # The later types still answer in the same transaction (the SAVEPOINT was rolled back).
    assert [h["job_id"] for h in groups["alert"]["hits"]] == [str(seed.job_a1)]
    assert len(groups["note"]["hits"]) == 1
    # A 422 and a timeout: the query text is in no log record, and the timeout is logged.
    r = await c.post(
        f"{API}/{seed.org_a.org_id}/search", json={"q": secret + "\x02"}, headers=csrf(c)
    )
    assert r.status_code == 422 and secret not in r.text
    assert "search: the case query timed out" in caplog.text
    assert secret not in caplog.text and "zebra" not in caplog.text


async def test_the_query_fragments_match_the_phase_1_index_expressions(
    owner_engine: AsyncEngine,
) -> None:
    """The drift guard: each fragment the queries use, on a temp copy of its table with the
    same indexes (`LIKE ... INCLUDING INDEXES`, no RLS), with sequential scans disabled. A
    fragment that drifted from its index expression can only be a (disabled) Seq Scan."""
    checks = {
        "investigations i": f"{queries.FTS_CASE} @@ {queries.TSQUERY}",
        "investigations i ": queries.CASE_NUMBER_LIKE,
        "analysis_findings f": f"{queries.FTS_FINDING} @@ {queries.TSQUERY}",
        "network_alerts a": f"{queries.FTS_ALERT} @@ {queries.TSQUERY}",
        "analyst_note_versions v": f"{queries.FTS_NOTE} @@ {queries.TSQUERY}",
        "evidence e": queries.TRGM_EVIDENCE,
        "correlation_keys ck": queries.TRGM_OBSERVABLE,
    }
    params = {"q": "xylophone", "like": "%xylophone%", "number_like": "%4242%"}
    async with owner_engine.begin() as conn:
        for table in {key.split()[0] for key in checks}:
            await conn.execute(
                text(
                    f"CREATE TEMP TABLE m7_{table} (LIKE {table} INCLUDING INDEXES) ON COMMIT DROP"
                )
            )
        await conn.execute(text("SET LOCAL enable_seqscan = off"))
        for relation, fragment in checks.items():
            table, alias = relation.split()
            sql = f"EXPLAIN (FORMAT JSON) SELECT 1 FROM m7_{table} {alias} WHERE {fragment}"
            plan = json.dumps((await conn.execute(text(sql), params)).scalar_one())
            assert "Bitmap Index Scan" in plan and "Seq Scan" not in plan, (relation, plan)


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "RLS: `@@`, `%` and ILIKE are not LEAKPROOF, so Postgres never uses them as index "
        "quals under a tenant_isolation policy (restriction_is_securely_promotable); the "
        "queries fall back to the organization_id btree plus a filter. Parent decision "
        "(0015): LEAKPROOF operators (superuser) or a SECURITY DEFINER search function."
    ),
)
async def test_the_queries_use_the_phase_1_indexes_under_rls(owner_engine: AsyncEngine) -> None:
    """The full queries, EXPLAINed in a tenant session on a small seeded volume (ANALYZEd)
    for a rare term. test_search_perf.py records the plans at 200 k keys."""
    reg = await register()
    t = Tenant(reg.org_id, reg.user_id, uuid.uuid4())
    await seed_volume(
        owner_engine,
        t,
        cases=1_000,
        jobs_per_case=1,
        keys_per_job=10,
        findings_per_job=5,
        alerts_per_job=5,
        notes_per_case=1,
    )
    rare = "xylophone"
    params = {
        "org": t.org_id,
        "q": rare,
        "like": f"%{rare}%",
        "number_like": "%4242%",
        "limit": 21,
        "offset": 0,
    }
    async with tenant_session(t.org_id, None) as s:
        await s.execute(text("SET LOCAL enable_seqscan = off"))
        missing = []
        for index, stmt in RLS_PLANS.items():
            sql = "EXPLAIN (FORMAT JSON) " + stmt.text
            if index not in json.dumps((await s.execute(text(sql), params)).scalar_one()):
                missing.append(index)
    # The route still answers on that volume.
    body = await _search(reg.client, reg.org_id, "beacon host-42")
    assert body["partial"] is False
    assert missing == []


@pytest.mark.parametrize(
    ("snippet", "q", "expected"),
    [
        ("Beaconing to quokka infra", "QUOKKA", [(13, 19)]),
        # Overlapping words merge; a 1-character word is ignored.
        ("quokkas and quokka", "quo quokka a", [(0, 6), (12, 18)]),
        # UTF-16 offsets (JavaScript string indexes): the emoji counts 2 code units.
        ("😀 Quokka quokka", "quokka", [(3, 9), (10, 16)]),
        ("nothing here", "quokka", []),
        (None, "quokka", []),
    ],
)
def test_snippet_ranges(snippet: str | None, q: str, expected: list[tuple[int, int]]) -> None:
    assert [(r.start, r.end) for r in service.snippet_ranges(snippet, q)] == expected


def test_snippet_ranges_are_bounded() -> None:
    ranges = service.snippet_ranges("ab " * 100, "ab")
    assert len(ranges) == service.MAX_RANGES
