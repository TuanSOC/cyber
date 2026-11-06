"""RLS trusts app.org_id: only vetted call sites may open a tenant session for a concrete org.

Any new `tenant_session(<org>, ...)` call outside this allowlist must be reviewed: the org id
must either be verified by require()/org_session() first, or be freshly generated (new org).
"""

import ast
from pathlib import Path

APP = Path(__file__).resolve().parents[2] / "app"

ALLOWED = {
    "core/rbac.py": "require()/org_session(): membership verified inside the same session",
    "modules/auth/service.py": "register(): org id freshly generated",
    "modules/organizations/service.py": "create_org(): org id freshly generated",
    "workers/ingest.py": "org from the non-tenant job index; message org must match + job token",
    # Also hosts the TI fallback reaper (M4 phase 2): org from the non-tenant ti_run_index,
    # and the AI one (M5 `reap_ai_runs`, filled by phase 2): org from ai_run_index.
    "workers/reaper.py": "org from the non-tenant job index (system data, no request input)",
    "workers/enrich.py": "org from the non-tenant ti_run_index; the message org must match",
    "workers/analyst.py": "org from the non-tenant ai_run_index; the message org must match",
    # M6 phase 4: the trusted `report.rendered` ingest (org from report_render_index).
    "modules/reports/render_ingest.py": "org from the non-tenant report_render_index + token",
    # M7: the retention worker opens per-org tenant sessions only through tenant_session, with
    # the org taken from the non-tenant retention_policy_index (RT3) or a message org that must
    # have a policy row there; phase 3 implements it.
    "workers/retention.py": "org from the non-tenant retention_policy_index (system lookup)",
    # M7: the correlation indexer (phase 4): org from the non-tenant analysis_job_index.
    "modules/correlation/indexer.py": "org from the non-tenant analysis_job_index",
    # M11 (phase 1 entries, filled by phases 3, 7 and 8).
    "modules/invitations/service.py": "org from the non-tenant invitation_index (token hash)",
    "modules/identity/sso/flow.py": (
        "org from the server-side SSO state, itself set from the non-tenant sso_domain_index"
    ),
    "modules/invitations/admin_bootstrap.py": "operator script: the org it creates",
    "modules/identity/admin_domains.py": "operator script: org from the CLI or verified domains",
}
# Allowlisted ahead of their implementation (M6 phase 1 stubs): exempt from the "still
# needed" check until the owning phase lands. Phase 9 asserts this set is empty.
# M7 phase 1: the retention worker (phase 3) and the correlation indexer (phase 4); phase 11
# asserts the set is empty again.
# M11 phase 1: the invitation flows (phase 3), the operator scripts (phases 3, 7) and the SSO
# callback (phase 8); phase 13 asserts the set is empty again.
PENDING_ALLOWED: frozenset[str] = frozenset(
    {
        "workers/retention.py",
        "modules/correlation/indexer.py",
        "modules/invitations/service.py",
        "modules/identity/sso/flow.py",
        "modules/invitations/admin_bootstrap.py",
        "modules/identity/admin_domains.py",
    }
)


def _org_argument_is_set(call: ast.Call) -> bool:
    org = (
        call.args[0]
        if call.args
        else next((k.value for k in call.keywords if k.arg == "org_id"), None)
    )
    if org is None:  # **kwargs or missing: treat as org-scoped (must be vetted)
        return True
    return not (isinstance(org, ast.Constant) and org.value is None)


def _org_scoped_calls(path: Path) -> list[int]:
    lines = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if (
            isinstance(node, ast.Call)
            and "tenant_session" in str(getattr(node.func, "id", getattr(node.func, "attr", "")))
            and _org_argument_is_set(node)
        ):
            lines.append(node.lineno)
    return lines


def test_org_scoped_tenant_sessions_only_in_vetted_modules() -> None:
    offenders = []
    for path in APP.rglob("*.py"):
        rel = path.relative_to(APP).as_posix()
        if rel in ALLOWED or rel == "core/tenancy.py":
            continue
        offenders += [f"{rel}:{line}" for line in _org_scoped_calls(path)]
    assert offenders == [], f"unvetted tenant_session(org, ...) calls: {offenders}"


def test_allowlist_entries_still_exist() -> None:
    for rel in ALLOWED:
        if rel in PENDING_ALLOWED and not _org_scoped_calls(APP / rel):
            continue  # a phase-1 stub; its phase adds the vetted call
        assert _org_scoped_calls(APP / rel), f"{rel} no longer needs an allowlist entry"
