"""The OIDC authorization-code flow (M11 phase 8; phase 1 placeholder).

Phase 8 implements `start` (home realm discovery through `sso_domain_index`, the Redis state,
the `cl_sso` binding) and `callback` (state GETDEL, `iss` check, token exchange through the
egress proxy, ID-token validation, account resolution and JIT, the session with `amr` `sso`).
Its `tenant_session(org, ...)` takes the org from the server-side state (the vetted entry of
`tests/unit/test_tenant_session_guard.py`).
"""
