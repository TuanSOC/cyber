"""Seed and check the restore drill's data (M7 phase 2, `pnpm restore:drill` only).

Runs as a one-off container of the drill project (`docker compose -p cyberlab-drill run --rm
--no-deps -T api python -m app.scripts.drill_seed seed|check`), never as the `api` service, and
talks to the drill api over the drill network (`DRILL_API_URL`, default `http://api:8000`).

`seed` (stdout: the seeded ids and the drill users' credentials as JSON, which the drill keeps
in memory only) creates through the real API: two orgs, three users (owner, analyst, viewer),
a case per org with three evidence uploads each (locked: the drill sets EVIDENCE_LOCK_DAYS=1),
a note, a collection with a manual item, a TLP change, a legal hold on the second org's case,
a dry-run retention policy, and a finalized report with one queued render (no render worker).
Where no API exists it writes as the owner (`DRILL_OWNER_DATABASE_URL`, `app.org_id` set):
synthetic TI and AI rows labelled `drill`, and an evidence purge tombstone whose object version
it deletes with the drill MinIO root and governance bypass (`DRILL_MINIO_ROOT_USER` /
`DRILL_MINIO_ROOT_PASSWORD`, RT17: the purge user cannot delete a locked version).

Guard: both modes refuse to run (exit 1, nothing sent) unless `CYBERLAB_DRILL=1` and
`CYBERLAB_DRILL_PROJECT=cyberlab-drill` (set by scripts/restore-drill.mjs) and the api env is
the drill overlay's (`EVIDENCE_LOCK_DAYS=1`, infra/backup/docker-compose.drill.yml): the
seeder registers users, writes as the owner and deletes a locked object version with the
MinIO root and governance bypass, which must never reach the main project.

`check` (stdin: the seed JSON; stdout: a JSON report, exit 1 on a failed check) runs after the
restore: the owner's pre-backup refresh token is refused (sessions revoked), the analyst logs in
again, downloads an evidence item with the seeded sha256, reads the report version with a
valid signature and its content, gets `410 evidence_purged` on the tombstoned evidence, and
the viewer gets 403 on a write.
"""

import asyncio
import hashlib
import json
import os
import secrets
import sys
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from minio import Minio
from minio.deleteobjects import DeleteObject
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

API = "/api/v1"
LABEL = {"label": "drill"}
EVIDENCE_PER_ORG = 3
EVIDENCE_BYTES = 96 * 1024


DRILL_PROJECT = "cyberlab-drill"


class DrillError(Exception):
    pass


def require_drill(env: Mapping[str, str] | None = None) -> None:
    """Refuse (DrillError) unless this is the restore drill's one-off container: the drill
    marker and project from restore-drill.mjs, and the drill overlay's EVIDENCE_LOCK_DAYS=1
    (an independent signal: the compose model, not the caller's env)."""
    env = os.environ if env is None else env
    if env.get("CYBERLAB_DRILL") != "1":
        raise DrillError("refusing to run: CYBERLAB_DRILL=1 is not set (pnpm restore:drill only)")
    if env.get("CYBERLAB_DRILL_PROJECT") != DRILL_PROJECT:
        raise DrillError(f"refusing to run: CYBERLAB_DRILL_PROJECT is not {DRILL_PROJECT}")
    if env.get("EVIDENCE_LOCK_DAYS") != "1":
        raise DrillError(
            "refusing to run: EVIDENCE_LOCK_DAYS is not 1 (not the drill overlay's api env)"
        )


@dataclass
class Session:
    """One user's cookies, sent by hand: the prod drill sets Secure cookies over plain HTTP
    inside the network, which a cookie jar would not send back."""

    client: httpx.Client
    cookies: dict[str, str] = field(default_factory=dict)

    def _headers(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        headers = dict(extra or {})
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            if "cl_csrf" in self.cookies:
                headers["X-CSRF-Token"] = self.cookies["cl_csrf"]
        return headers

    def request(
        self, method: str, path: str, *, expect: int | None = None, **kw: Any
    ) -> httpx.Response:
        headers = self._headers(kw.pop("headers", None))
        # The client is shared by the drill users: its own jar must never add another
        # user's cookies to this request.
        self.client.cookies.clear()
        response = self.client.request(method, path, headers=headers, **kw)
        for name, value in response.cookies.items():
            self.cookies[name] = value
        if expect is not None and response.status_code != expect:
            raise DrillError(f"{method} {path}: HTTP {response.status_code} {response.text[:300]}")
        return response

    def json(self, method: str, path: str, expect: int, **kw: Any) -> Any:
        return self.request(method, path, expect=expect, **kw).json()


def _client() -> httpx.Client:
    return httpx.Client(base_url=os.environ.get("DRILL_API_URL", "http://api:8000"), timeout=60)


def _register(client: httpx.Client, role: str, tag: str) -> tuple[Session, dict[str, Any]]:
    session = Session(client)
    email = f"drill-{role}-{tag}@example.com"
    password = secrets.token_urlsafe(18)
    body = session.json(
        "POST",
        f"{API}/auth/register",
        201,
        json={
            "email": email,
            "password": password,
            "display_name": f"Drill {role}",
            "organization_name": f"Drill {role} {tag}",
        },
    )
    user = {"id": body["user"]["id"], "email": email, "password": password}
    return session, {**user, "home_org": body["memberships"][0]["organization_id"]}


def _payload(org: str, index: int) -> bytes:
    head = f"cyberlab restore drill evidence {org} #{index}\n".encode()
    return head + secrets.token_bytes(EVIDENCE_BYTES - len(head))


def _upload(owner: Session, org: str, case: str, index: int) -> dict[str, Any]:
    data = _payload(org, index)
    out = owner.json(
        "POST",
        f"{API}/orgs/{org}/investigations/{case}/evidence",
        201,
        params={"filename": f"drill-{index}.bin", "description": "restore drill"},
        content=data,
        headers={"Content-Type": "application/octet-stream"},
    )
    sha = hashlib.sha256(data).hexdigest()
    if out.get("hashes", {}).get("sha256") != sha:
        raise DrillError("upload: the API reported another sha256")
    return {"id": out["id"], "org": org, "case": case, "sha256": sha, "bytes": len(data)}


def _seed_api(tag: str) -> dict[str, Any]:
    client = _client()
    owner, owner_user = _register(client, "owner", tag)
    analyst, analyst_user = _register(client, "analyst", tag)
    _viewer, viewer_user = _register(client, "viewer", tag)
    org_a = owner_user["home_org"]
    org_b = owner.json("POST", f"{API}/orgs", 201, json={"name": f"Drill second {tag}"})["id"]
    for user, role in ((analyst_user, "analyst"), (viewer_user, "viewer")):
        owner.json(
            "POST", f"{API}/orgs/{org_a}/members", 201, json={"email": user["email"], "role": role}
        )
    cases = {}
    for org in (org_a, org_b):
        cases[org] = owner.json(
            "POST",
            f"{API}/orgs/{org}/investigations",
            201,
            json={"title": "Restore drill case", "severity": "high", "description": "drill"},
        )["id"]
    case_a, case_b = cases[org_a], cases[org_b]
    evidence = [
        _upload(owner, org, cases[org], i)
        for org in (org_a, org_b)
        for i in range(1, EVIDENCE_PER_ORG + 1)
    ]
    owner.json(
        "PATCH",
        f"{API}/orgs/{org_a}/investigations/{case_a}",
        200,
        json={"tlp": "green", "acknowledge_tlp_downgrade": True},
    )
    owner.json(
        "POST",
        f"{API}/orgs/{org_a}/investigations/{case_a}/notes",
        201,
        json={"body": "Restore drill note."},
    )
    collection = owner.json(
        "POST",
        f"{API}/orgs/{org_a}/investigations/{case_a}/ioc-collections",
        201,
        json={"name": "Drill collection"},
    )["id"]
    owner.json(
        "POST",
        f"{API}/orgs/{org_a}/ioc-collections/{collection}/items",
        200,
        json={"items": [{"type": "domain", "value": "drill.example.com", "note": "drill"}]},
    )
    hold = owner.json(
        "POST",
        f"{API}/orgs/{org_b}/legal-holds",
        201,
        json={"scope": "investigation", "investigation_id": case_b, "reason": "restore drill"},
    )["id"]
    owner.json(
        "PUT",
        f"{API}/orgs/{org_a}/retention/policy",
        200,
        json={
            "ti_results_days": 365,
            "ai_runs_days": 365,
            "closed_case_days": 3650,
            "enforce": False,
            "acknowledge_destruction": True,
        },
    )
    report = owner.json(
        "POST",
        f"{API}/orgs/{org_a}/investigations/{case_a}/reports",
        201,
        json={"title": "Restore drill report", "tlp": "green", "profile": "internal"},
    )
    detail = owner.json(
        "PATCH",
        f"{API}/orgs/{org_a}/reports/{report['id']}",
        200,
        json={
            "revision": report["revision"],
            "distribution": "Restore drill",
            "draft": {
                "sections": {"executive_summary": "Restore drill report."},
                "include": {"iocs": {"case_iocs": False}},
            },
        },
    )
    version = owner.json(
        "POST",
        f"{API}/orgs/{org_a}/reports/{report['id']}/finalize",
        201,
        json={"revision": detail["report"]["revision"]},
    )
    render = owner.json(
        "POST",
        f"{API}/orgs/{org_a}/reports/{report['id']}/versions/{version['version']}/renders",
        200,
        json={"format": "pdf"},
    )
    return {
        "orgs": {"a": org_a, "b": org_b},
        "cases": {"a": case_a, "b": case_b},
        "users": {
            "owner": {k: owner_user[k] for k in ("id", "email", "password")},
            "analyst": {k: analyst_user[k] for k in ("id", "email", "password")},
            "viewer": {k: viewer_user[k] for k in ("id", "email", "password")},
        },
        # The owner's pre-backup session: `check` proves the restore revoked it.
        "owner_session": {k: owner.cookies.get(k, "") for k in ("cl_refresh", "cl_csrf")},
        "evidence": evidence,
        "collection_id": collection,
        "legal_hold_id": hold,
        "report": {"id": report["id"], "version": version["version"], "org": org_a},
        "render_id": render["id"],
    }


async def _seed_owner_rows(seed: dict[str, Any]) -> None:
    """Synthetic TI / AI rows (no provider runs in the drill) and the purge tombstone."""
    require_drill()
    url = os.environ.get("DRILL_OWNER_DATABASE_URL")
    if not url:
        raise DrillError("DRILL_OWNER_DATABASE_URL is not set")
    org, owner_id, case = seed["orgs"]["a"], seed["users"]["owner"]["id"], seed["cases"]["a"]
    purged = seed["evidence"][EVIDENCE_PER_ORG - 1]  # the last upload of org A
    now = datetime.now(UTC)
    ti_run, ai_run, retention_run = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    label = json.dumps(LABEL)
    engine = create_async_engine(url, poolclass=NullPool, hide_parameters=True)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "SELECT set_config('app.org_id', :o, true), set_config('app.user_id', :u, true)"
                ),
                {"o": org, "u": owner_id},
            )
            await conn.execute(
                text(
                    "INSERT INTO ti_enrichment_runs (id, organization_id, scope, requested_by, "
                    "providers, status, summary, deadline_at, started_at, finished_at) VALUES "
                    "(:id, :org, 'manual', :user, '[\"mock\"]'::jsonb, 'completed', "
                    "CAST(:label AS jsonb), :deadline, :now, :now)"
                ),
                {
                    "id": ti_run,
                    "org": org,
                    "user": owner_id,
                    "label": label,
                    "deadline": now + timedelta(hours=1),
                    "now": now,
                },
            )
            await conn.execute(
                text(
                    "INSERT INTO ti_results (organization_id, run_id, provider, ioc_type, "
                    "value_norm, ioc_key, status, found, summary, expires_at) VALUES "
                    "(:org, :run, 'mock', 'domain', 'drill.example.com', :key, 'ok', false, "
                    "CAST(:label AS jsonb), :expires)"
                ),
                {
                    "org": org,
                    "run": ti_run,
                    "label": label,
                    "key": hashlib.sha256(b"drill:domain:drill.example.com").hexdigest(),
                    "expires": now + timedelta(days=30),
                },
            )
            await conn.execute(
                text(
                    "INSERT INTO ai_runs (id, organization_id, task, scope, investigation_id, "
                    "provider, model, prompt_version, output_schema, status, context_sha256, "
                    "context_stats, requested_by, deadline_at, started_at, finished_at) VALUES "
                    "(:id, :org, 'incident_summary', 'investigation', :case, 'mock', 'mock-1', "
                    "'m5.1', 'ai.v1', 'completed', :ctx, CAST(:label AS jsonb), :user, "
                    ":deadline, :now, :now)"
                ),
                {
                    "id": ai_run,
                    "org": org,
                    "case": case,
                    "user": owner_id,
                    "label": label,
                    "ctx": hashlib.sha256(b"drill context").hexdigest(),
                    "deadline": now + timedelta(hours=1),
                    "now": now,
                },
            )
            await conn.execute(
                text(
                    "INSERT INTO ai_outputs (organization_id, run_id, body) "
                    "VALUES (:org, :run, CAST(:label AS jsonb))"
                ),
                {"org": org, "run": ai_run, "label": label},
            )
            row = (
                await conn.execute(
                    text(
                        "SELECT storage_bucket, storage_key, storage_version_id FROM evidence "
                        "WHERE id = :id"
                    ),
                    {"id": purged["id"]},
                )
            ).one()
            await conn.execute(
                text(
                    "INSERT INTO retention_runs (id, organization_id, mode, trigger, status, "
                    "policy, counts, started_at, finished_at) VALUES (:id, :org, 'enforce', "
                    "'schedule', 'completed', CAST(:label AS jsonb), CAST(:label AS jsonb), "
                    ":now, :now)"
                ),
                {"id": retention_run, "org": org, "label": label, "now": now},
            )
            await conn.execute(
                text(
                    "INSERT INTO evidence_purges (evidence_id, organization_id, run_id, "
                    "object_version_id, sha256) VALUES (:e, :org, :run, :v, :sha)"
                ),
                {
                    "e": purged["id"],
                    "org": org,
                    "run": retention_run,
                    "v": row[2],
                    "sha": purged["sha256"],
                },
            )
    finally:
        await engine.dispose()
    _delete_locked_version(str(row[0]), str(row[1]), str(row[2]))
    purged["purged"] = True
    seed["tombstoned_evidence"] = purged["id"]
    seed["synthetic"] = {
        "ti_run": str(ti_run),
        "ai_run": str(ai_run),
        "retention_run": str(retention_run),
    }


def _delete_locked_version(bucket: str, key: str, version_id: str) -> None:
    """The drill's only governance bypass (RT17): the tombstoned version, with the drill root."""
    user, password = (
        os.environ.get("DRILL_MINIO_ROOT_USER"),
        os.environ.get("DRILL_MINIO_ROOT_PASSWORD"),
    )
    if not user or not password:
        raise DrillError("DRILL_MINIO_ROOT_USER / DRILL_MINIO_ROOT_PASSWORD are not set")
    client = Minio(os.environ["MINIO_ENDPOINT"], access_key=user, secret_key=password, secure=False)
    errors = list(
        client.remove_objects(bucket, [DeleteObject(key, version_id)], bypass_governance_mode=True)
    )
    if errors:
        raise DrillError(f"could not delete the tombstoned version: {errors[0].code}")


def seed() -> dict[str, Any]:
    tag = secrets.token_hex(4)
    data = _seed_api(tag)
    asyncio.run(_seed_owner_rows(data))
    return data


def _login(client: httpx.Client, user: Mapping[str, str]) -> Session:
    session = Session(client)
    session.request(
        "POST",
        f"{API}/auth/login",
        expect=200,
        json={"email": user["email"], "password": user["password"]},
    )
    return session


def check(seed_data: Mapping[str, Any]) -> dict[str, Any]:
    client = _client()
    results: list[dict[str, Any]] = []

    def record(name: str, ok: bool, **detail: Any) -> None:
        results.append({"check": name, "ok": ok, **detail})

    old = Session(client, dict(seed_data["owner_session"]))
    refreshed = old.request("POST", f"{API}/auth/refresh")
    record("old_session_revoked", refreshed.status_code == 401, status=refreshed.status_code)

    org = seed_data["orgs"]["a"]
    analyst = _login(client, seed_data["users"]["analyst"])
    record("analyst_login", True)
    live = next(e for e in seed_data["evidence"] if e["org"] == org and not e.get("purged"))
    download = analyst.request("GET", f"{API}/orgs/{org}/evidence/{live['id']}/download")
    digest = hashlib.sha256(download.content).hexdigest()
    record(
        "evidence_download_sha256",
        download.status_code == 200 and digest == live["sha256"],
        status=download.status_code,
    )
    report = seed_data["report"]
    base = f"{API}/orgs/{org}/reports/{report['id']}/versions/{report['version']}"
    version = analyst.request("GET", base)
    body = version.json() if version.status_code == 200 else {}
    record(
        "report_signature_valid",
        body.get("signature_valid") is True and body.get("snapshot_ok") is True,
        status=version.status_code,
    )
    content = analyst.request("GET", f"{base}/content")
    record("report_content", content.status_code == 200, status=content.status_code)
    purged = analyst.request(
        "GET", f"{API}/orgs/{org}/evidence/{seed_data['tombstoned_evidence']}/download"
    )
    code = purged.json().get("error", {}).get("code") if purged.status_code == 410 else None
    record(
        "purged_evidence_410",
        purged.status_code == 410 and code == "evidence_purged",
        status=purged.status_code,
    )
    viewer = _login(client, seed_data["users"]["viewer"])
    write = viewer.request(
        "POST",
        f"{API}/orgs/{org}/investigations",
        json={"title": "viewer write", "severity": "low"},
    )
    record("viewer_write_forbidden", write.status_code == 403, status=write.status_code)
    return {"ok": all(r["ok"] for r in results), "checks": results}


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in ("seed", "check"):
        print(json.dumps({"error": "usage: drill_seed seed|check"}))
        return 2
    try:
        require_drill()
        if argv[0] == "seed":
            print(json.dumps(seed()))
            return 0
        result = check(json.loads(sys.stdin.read()))
    except (DrillError, httpx.HTTPError, KeyError, ValueError) as exc:
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
        return 1
    print(json.dumps(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
