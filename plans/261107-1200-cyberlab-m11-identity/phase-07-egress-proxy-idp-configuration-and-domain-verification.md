---
phase: 7
title: "Egress proxy IdP configuration and domain verification"
status: pending
priority: P2
effort: "12h"
dependencies: [1]
---

# Phase 7: Egress proxy, IdP configuration and domain verification (group B, 2f, lane 7; OIDC cut line 2, RT16)

## Overview
The infrastructure SSO needs without giving the API an internet route: an SSRF-hardened CONNECT proxy, the per-org OIDC configuration with its sealed client secret and cached discovery / JWKS, and DNS-verified domains that gate JIT provisioning and home realm discovery. Design: plan.md "Egress proxy" and "SSO".

**Owns:** `app/egress_proxy/**`, `identity/{domains,idp_config,discovery,dns,admin_domains,router_sso_admin}.py`, the SSO-admin section of `tests/security/idor_cases_identity.py`, `tests/unit/test_egress_proxy.py`, `tests/integration/test_egress_proxy_tunnel.py`, `test_idp_config.py`, `test_domains.py`.

## Requirements
- **Egress proxy** (`app/egress_proxy/server.py`, asyncio streams, `python -m app.egress_proxy`):
  - accepts only `CONNECT host:443 HTTP/1.1` with a request head ≤ 4 KiB read within 5 s; anything else → `405` / `400` and close;
  - host: IDNA-normalized name (≤ 253, ≥ 2 labels, not special-use) or a literal that is global; port 443 only (`403`);
  - resolution through `threat_intel/ssrf.resolve_pinned` (every answer global; the dev/test-only `IDENTITY_ALLOW_PRIVATE_ISSUER_HOSTS` allows the named mock hosts, refused when `ENV=prod`); the proxy builds the `ValidatedBase` itself and always passes `allow_private` explicitly (true only for an allowlisted host name), so `TI_MISP_ALLOW_PRIVATE` / `TI_MISP_ALLOWED_PORTS` never affect it (RT25; a unit test sets both and still gets refusals); connect to the first validated address (10 s);
  - `200 Connection Established`, then a byte pump with caps (1 MiB per direction, 30 s idle, 60 s total), 32 concurrent tunnels, 60 new tunnels / min (token bucket), all limits from `EGRESS_PROXY_*`;
  - no TLS termination, no credentials, no logging of hosts (counters only: accepted, refused by reason);
  - `PROCESS_ROLE=egress_proxy` (phase-1 refusals); container `read_only`, `cap_drop: ALL`, 64 MB, non-root, networks `idp` + `egress` only.
- **IdP configuration** (`idp_config.py`, `router_sso_admin.py`):
  - `GET /orgs/{org}/sso` (`org.read`: issuer, client id, `secret_last4`, enabled, JIT settings, metadata status; never the secret);
  - `PUT` (`security.manage`, step-up `sso_config_update`): validate the issuer with the TI `validate_base_url` rules (https, no userinfo / query / fragment, public host, port 443), normalized without a trailing slash; `client_secret` optional on update (8–256 printable ASCII) sealed with `IDENTITY_DOMAIN`, provider `oidc`, `base_url_norm = issuer` (changing the issuer without a new secret → `422 secret_required_for_new_issuer`); `jit_default_role` viewer / analyst only; bump `config_version`; an issuer change leaves existing `user_identities` rows unreachable (they are keyed with the old issuer, RT11) and the response says members must sign in again to re-link; fetch discovery and JWKS (below) before saving `enabled=true` (`422 issuer_invalid` with a fixed reason code on failure); audit `org.sso_updated` (never the secret); mail `new_owner_security_change`; update `sso_domain_index` rows for the org's verified domains;
  - `DELETE /orgs/{org}/sso/secret` (step-up) disables the IdP; `POST /orgs/{org}/sso/refresh-metadata` re-fetches (5 / hour).
- **Discovery** (`discovery.py`): via `identity/egress.egress_client()`: `{issuer}/.well-known/openid-configuration` (≤ 64 KiB JSON); require `issuer` equal to the configured value, `authorization_endpoint`, `token_endpoint`, `jwks_uri` https on public hosts, `response_types_supported` ∋ `code`, `code_challenge_methods_supported` ∋ `S256` when present (absent → allowed, PKCE is sent anyway), `id_token_signing_alg_values_supported` ∩ {RS256, PS256, ES256} non-empty; JWKS ≤ 64 KiB, keys of kty RSA (≥ 2048 bits) / EC P-256 only, `use` sig or absent; store both with `fetched_at`; implement the phase-1 stub `refresh_jwks_if_unknown_kid(session, config, kid) -> bool` (≤ 1 per minute per org; signature frozen, RT17) for phase 8.
- **Domains** (`domains.py`, `dns.py`):
  - `POST /orgs/{org}/domains {domain}` (`security.manage`, step-up `domain_change`): IDNA-normalize; refuse special-use, single-label and public-suffix-only names (a small bundled list of common suffixes is enough: `com`, `co.uk`, …; documented limitation); create `pending` with a 32-byte challenge; response includes the TXT name `_cyberlab-challenge.<domain>` and value `cyberlab-domain-verification=<challenge>`;
  - domains are compared exactly everywhere (no parent or subdomain inheritance: verifying `corp.com` admits neither `eng.corp.com` emails nor the reverse, RT27);
  - `POST …/{id}/verify` (10 / hour per org): DoH JSON query (`IDENTITY_DOH_URL`, default `https://cloudflare-dns.com/dns-query`, `accept: application/dns-json`) through the egress client; match any TXT string exactly; on success `verified` (global unique index: `409 domain_claimed`), `sso_domain_index` upsert, audit `org.domain_verified`;
  - `DELETE` (step-up): the app role has no DELETE grant, so the row goes to status `removed` (a phase-1 check value; phase 1 adds it to the status check) and its `sso_domain_index` row is disabled; audit `org.domain_removed`;
  - **re-check (decision):** no beat task. Only the api (and the egress proxy) can reach DoH, and giving a worker the `idp` network or a tenant-session guard entry for a weekly check is not worth it. `pnpm identity:admin recheck-domains` (one-off api container, through the proxy) re-queries every verified domain; DEPLOYMENT documents a weekly host cron line. The verify route stays the online path. A vanished record → `failed`, index disabled, audit `org.domain_lost`, mail to the owners.
  - `pnpm identity:admin approve-domain --org <id> --domain <d> --yes` (`admin_domains.py`): method `operator`, same index updates, audit with the operator marker.
- **Tests:** unit tests of the CONNECT parser (methods, ports, oversized head, slowloris head, IDNA, private / loopback / link-local / metadata / IPv4-mapped literals, special-use names); an integration tunnel test with `egress-proxy-test` to `idp-mock` over TLS (the mock's self-signed CA trusted by the test client only) and the refusals; IdP config validation, sealing bound to the issuer (an issuer change makes the old secret unopenable: `UnsealError`), discovery mismatches (wrong `issuer`, http endpoint, private host, `none`-only algs, oversized document); domain flow with a fake DoH server in the test profile (`idp-mock` serves `/dns-query` too), claimed-elsewhere conflict, operator approval; IDOR for the SSO-admin routes.

## Implementation Steps
1. Proxy server and its unit tests; container wiring check in the test profile (heavy-lite: one container).
2. IdP config, sealing and discovery; tests (direct to `idp-mock` in the lane; the tunnel test separately).
3. Domains, DoH, operator script, re-check script; tests.

## Success Criteria
- [ ] The API reaches IdPs and DoH only through `egress-proxy`, which refuses non-443 ports, non-global addresses and other methods, and enforces its caps.
- [ ] IdP configuration validates the issuer and discovery, seals the secret bound to the issuer, and never returns it.
- [ ] A domain becomes verified only through a matching TXT record or the operator, is unique across orgs, and feeds `sso_domain_index`.

## Risk Assessment
- **A compromised API can still reach any public host on 443 through the proxy** (research open question 3): recorded; an issuer allowlist pushed from the DB is a red-team option.
- **DoH resolver trust:** a single public resolver could lie; configurable; the operator path exists.
- **Public-suffix handling** is approximate (bundled list): a claim of `co.uk`-like suffixes outside the list is possible but gives no users (JIT requires `email_verified` addresses in that exact domain and only inside the claiming org).
