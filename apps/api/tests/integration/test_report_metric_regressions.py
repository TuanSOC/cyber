"""Regressions of the M6 §14 report metric run of 261106 (`tests/reports_metric/harness.py`).

- **verify_report pass rate 72/76**: the two seeded fixture versions (golden, hostile) were
  signed with the manifest's `finalized_at` = now while their snapshot kept the fixture's
  `report.finalized_at`, so `scripts/verify_report.py` refused both the snapshot and the
  PDF ("the snapshot finalized_at differs from the manifest"). `seed_fixture_version` signs
  the snapshot's own time, as finalize does; the old seeding is kept as a negative control.
- **citation accuracy 634/662**: an `external` `report_citations` row records the hash of
  the redacted copy the report shows (pseudonymized IPs and hosts), so a re-resolution of
  the live row without that projection cannot match it. The harness re-resolves external
  citations through `service.build_redacted` (the finalize code path); this checks that the
  projection reproduces every recorded hash and that the case really exercises redaction.
"""

import json
import subprocess
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from cyberlab_jobs.report import parse_snapshot
from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.investigations.models import Investigation
from app.modules.pcap_analysis.models import AnalysisFinding, NetworkAlert
from app.modules.reports import citations as cites
from app.modules.reports.models import Report, ReportCitation
from app.modules.reports.service import build_redacted
from tests.factories import Registered
from tests.report_helpers import (
    FIXTURES,
    SigningKeys,
    purge_reports_test_bucket,
    seed_report,
    seed_version,
    use_signing_keys,
)
from tests.reports_metric.harness import seed_fixture_version
from tests.security.idor_cases_reports import (
    API,
    Dispatched,
    api_create,
    api_finalize,
    api_patch,
    draft,
    fake_case_iocs,
    fake_dispatch,
    owner_case,
    pcap_job,
    rows_of,
)
from tests.unit.test_verify_report_script import SCRIPT

CHANGE_NOTE = "External regression"


@pytest.fixture
def keys(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[SigningKeys]:
    installed = use_signing_keys(monkeypatch, tmp_path)
    fake_case_iocs(monkeypatch)
    yield installed
    purge_reports_test_bucket()


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch, keys: SigningKeys) -> Dispatched:
    return fake_dispatch(monkeypatch)


async def _verify_snapshot(
    reg: Registered, report_id: uuid.UUID, keys: SigningKeys, d: Path
) -> subprocess.CompletedProcess[str]:
    assert SCRIPT is not None
    url = f"{API}/{reg.org_id}/reports/{report_id}/versions/1"
    content = await reg.client.get(f"{url}/content")
    sig = await reg.client.get(f"{url}/signature")
    assert content.status_code == 200, content.text
    assert sig.status_code == 200, sig.text
    d.mkdir(parents=True, exist_ok=True)
    (d / "snapshot.json").write_bytes(content.content)
    (d / "sig.json").write_bytes(sig.content)
    (d / "keys.json").write_text(json.dumps({keys.kid: keys.public_b64}), encoding="utf-8")
    command = [sys.executable, str(SCRIPT), "--snapshot", str(d / "snapshot.json")]
    command += ["--sig", str(d / "sig.json"), "--keys", str(d / "keys.json"), "--quiet"]
    return subprocess.run(command, capture_output=True, text=True, check=False)


@pytest.mark.skipif(SCRIPT is None, reason="scripts/verify_report.py is not mounted")
@pytest.mark.parametrize("name", ["golden", "hostile"])
async def test_seeded_fixture_versions_verify_offline(
    keys: SigningKeys, tmp_path: Path, name: str
) -> None:
    reg, t = await owner_case(title=f"Fixture {name}")
    _, snapshot = await seed_fixture_version(t, keys, name)
    result = await _verify_snapshot(reg, snapshot.report.report_id, keys, tmp_path / "ok")
    assert result.returncode == 0, result.stderr

    # Negative control: the pre-fix seeding (manifest `finalized_at` = now) is refused.
    base = parse_snapshot((FIXTURES / f"{name}_snapshot.json").read_bytes())
    tlp, profile = str(base.report.tlp), str(base.report.profile)
    report_id = await seed_report(t, title=f"Stale {name}", tlp=tlp, profile=profile)
    info = base.report.model_copy(update={"report_id": report_id, "version": 1})
    stale = base.model_copy(update={"report": info})
    await seed_version(t, report_id, keys, snapshot=stale, tlp=tlp, profile=profile)
    refused = await _verify_snapshot(reg, report_id, keys, tmp_path / "stale")
    assert refused.returncode == 1
    assert "finalized_at differs from the manifest" in refused.stderr


async def test_external_citations_re_resolve_under_the_redaction_projection(
    sent: Dispatched,
) -> None:
    reg, t = await owner_case()
    _, job = await pcap_job(reg, t)
    cited = [("alert", r) for r in await rows_of(t, NetworkAlert, job)]
    cited += [("finding", r) for r in await rows_of(t, AnalysisFinding, job)]
    report = (await api_create(reg, t, profile="external")).json()
    patched = await api_patch(
        reg,
        report["id"],
        distribution="Partner CERT only (regression)",
        draft=draft(cited_rows=[{"kind": k, "ref_id": str(r.id)} for k, r in cited]),
    )
    assert patched.status_code == 200, patched.text
    response = await api_finalize(
        reg, report["id"], acknowledge_external_review=True, change_note=CHANGE_NOTE
    )
    assert response.status_code == 201, response.text
    version_id = uuid.UUID(response.json()["id"])
    content = await reg.client.get(f"{API}/{reg.org_id}/reports/{report['id']}/versions/1/content")
    snapshot = parse_snapshot(content.content)
    shown = {c.cite_no: c.fields_sha256 for c in snapshot.citations.items}

    async with tenant_session(t.org_id, t.owner_id) as s:
        rows = list(
            await s.scalars(
                select(ReportCitation)
                .where(ReportCitation.version_id == version_id)
                .order_by(ReportCitation.cite_no)
            )
        )
        case = await s.get(Investigation, t.investigation_id)
        assert case is not None
        scope = await cites.CaseScope.load(s, t.org_id, case)
        requests = [
            cites.CiteRequest(r.kind, r.ref_id, r.job_id, r.source, r.ai_citation_id, r.ref_table)
            for r in rows
        ]
        live = await cites.resolve(s, scope, requests, with_paths=False)
        row = await s.get(Report, uuid.UUID(report["id"]))
        assert row is not None
        _, again = await build_redacted(
            s, t.org_id, t.owner_id, row, case, snapshot.report.finalized_at, CHANGE_NOTE
        )

    # The row records the hash of the copy the report shows.
    assert len(rows) == len(cited)
    assert {r.cite_no: r.fields_sha256 for r in rows} == shown
    # The case exercises redaction: some live (unredacted) copies hash differently ...
    live_hashes = {r.cite_no: live[cites.cite_key(r.kind, r.ref_id, r.job_id)] for r in rows}
    assert any(live_hashes[r.cite_no].fields_sha256 != r.fields_sha256 for r in rows)
    assert all(live_hashes[r.cite_no].ref_table == r.ref_table for r in rows)
    # ... and the same projection of the live rows reproduces every recorded hash.
    assert {c.cite_no: (c.kind, c.ref_table, c.ref_id) for c in again.citations.items} == {
        r.cite_no: (r.kind, r.ref_table, r.ref_id) for r in rows
    }
    assert {c.cite_no: c.fields_sha256 for c in again.citations.items} == shown
