"""The egress proxy (M11 phase 7): HTTP CONNECT to public hosts on 443 for the api only.

Run as `python -m app.egress_proxy` (`PROCESS_ROLE=egress_proxy`). It reads
`app.core.config.EgressProxySettings` only and refuses to start when any variable of
`EGRESS_PROXY_FORBIDDEN_ENV` is set (it holds no secret, DB, Redis, broker or MinIO access).
Phase 1 ships the entry point only.
"""
