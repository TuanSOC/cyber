---
phase: 4
title: "MISP SSRF client and ATT&CK index"
status: pending
priority: P1
effort: "8h"
dependencies: [2]
---

# Phase 4: MISP SSRF client and ATT&CK index

## Overview
Two providers that differ from the fixed-host ones. MISP has an org-supplied URL, so it needs
the full SSRF hardening. MITRE ATT&CK is an offline, pinned, committed T-id index, plus a small
read route used to label ATT&CK ids in the UI.

## Requirements
- **`threat_intel/ssrf.py`:** phase 2 already provides the syntactic `validate_base_url(url) -> ValidatedBase` (https only, no userinfo / query / fragment, port 443 or `TI_MISP_ALLOWED_PORTS` (default `443,8443`), IDNA host, literal IPs checked, path prefix ≤ 256 characters, `base_url_norm`). This phase adds `resolve_pinned(validated) -> list[IP]` and the pinned transport; it does not change `validate_base_url`.
  - **Resolution (worker only, RT5):**
    - `getaddrinfo` runs in a thread with a 2 s timeout;
    - **every** returned address must be global (the same rules as `normalize`); otherwise `MispUrlNotPublic` → `verify_status=invalid`, `last_error_code=misp_url_not_public` on verify, or an `error` row with that code at request time;
    - `TI_MISP_ALLOW_PRIVATE` (dev only, refused in prod) allows private addresses, but loopback, link-local (including `169.254.169.254`) and the unspecified address stay refused.
  - The API never resolves (it has no egress). The worker resolves in `ti.verify` (queued automatically after every save, phase 5) and again before every request, and connects to the first validated address (pinned; IPv6 literals bracketed).
- **Pinned connection:** the request URL uses the pinned IP. `Host` is the hostname, and `extensions={"sni_hostname": host}` makes TLS verify the certificate against the hostname.
  - Settings: `verify=True` with the system CAs, or `ssl.create_default_context(cafile=TI_MISP_CA_FILE)`.
  - No `verify=False` in prod. A dev-only `TI_MISP_INSECURE_TLS` logs a loud warning at startup and is refused in prod.
  - Redirects off; `trust_env=False`; body cap 2 MiB.
- **`providers/misp.py`** (the key is unsealed with the stored `base_url_norm` in the AAD, so it only opens for that URL, RT1):
  - `POST {base}/attributes/restSearch` with the body from the provider report (`limit` 50, `enforceWarninglist` true, `includeEventTags` true, `deleted` false);
  - `Authorization: <key>` (no Bearer), JSON accept and content type;
  - allowed paths `{prefix}/attributes/restSearch` (POST) and `{prefix}/servers/getVersion` (GET, used by verify);
  - IOC type mapping to MISP types, including `email-src` / `email-dst` for email (MISP only);
  - not found is `{"response":{"Attribute":[]}}`.

  The summary (the frozen `MispSummary` from `summaries.py`) keeps up to 20 attributes: `type`, `category`, `to_ids`, `first_seen`, `last_seen`, `timestamp`, `event_id`, `Event.info` (capped), `Event.uuid`, and the tag names. TLP tags are kept and shown, and ATT&CK galaxy tags become `attack_ids`. `permalink` = `{base_url_norm}/events/view/{event_id}` for the first event; `event_id` is validated as numeric.
  - MISP data never becomes an IOC source and is never forwarded to another provider. A TLP:RED or TLP:AMBER tag shows a badge in the UI.
- **ATT&CK builder `scripts/build_attack_index.py`** (stdlib only; run by a maintainer on the host, never in CI or in a `backend` container, which have no egress):
  - inputs: a pinned version and URL of `mitre-attack/attack-stix-data` `enterprise-attack/enterprise-attack-<ver>.json` and its expected sha256;
  - it downloads the bundle, checks the hash, and emits `apps/api/app/modules/attack/data/attack_enterprise_v<ver>.json`;
  - output fields: `{meta: {version, source_url, source_sha256, built_at, attack_spec}, techniques: {T-id: {name, tactics[], is_subtechnique, parent, deprecated, revoked_by, url}}, tactics: {shortname: name}}`;
  - tactics come from `kill_chain_phases` (mitre-attack) and the tactic objects;
  - `revoked_by` follows `relationship_type == "revoked-by"`;
  - expected size is about 300 KB.

  Verify the latest version when the phase starts (the report says v20, 2026-10-13, to be verified) and note the v19 split of Defense Evasion into Stealth and Defense Impairment.
- **`modules/attack/`** (fills the router stub registered in phase 1; no `main.py` edit):
  - `index.py` loads the committed JSON once (`lru_cache`, schema validated at import);
  - `label(tid) -> AttackLabel | None` resolves revoked ids to their replacement and marks deprecated ones;
  - route `GET /api/v1/attack/techniques?ids=T1055,T1059.001` (any authenticated user, at most 100 ids, ids validated by pattern) → labels plus `meta` (version and notice). No separate `about` route (RT15); `ids` may be empty to fetch `meta` only.

  The license notice ("© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.") is part of `meta`, so the UI always shows it.
- **Tests:**
  - **SSRF** (resolution half; the syntactic cases are phase 2's). A fake resolver returns, each case being refused:
    - private, loopback and metadata addresses;
    - a mixed public and private answer;
    - IPv4-mapped IPv6;
    - a DNS-rebinding sequence (public on verify, private on request);
    - a redirect response;
    - an oversize body.

    Plus the SNI/Host check on the outgoing request, the prod refusal of the allow-private and insecure flags, and a MISP key sealed for URL A failing to open for URL B.
  - **MISP adapter:** fixtures for hit, empty, 401/403, 5xx, bad JSON, oversize and timeout, plus the allowlist test.
  - **ATT&CK builder:** a tiny committed fixture STIX bundle (techniques, a sub-technique, deprecated, revoked-by, multiple tactics) gives the expected index. A sha256 mismatch aborts.
  - **Committed index:** schema-valid; `T1055` and `T1059.001` resolve; meta and version present.

## Implementation Steps
1. `ssrf.resolve_pinned` with the resolver injected, and its tests.
2. The pinned httpx connection (URL with IP plus `sni_hostname`) and a TLS test against a local test server with a CA-signed certificate for a fake hostname, run in `api-test` (no real internet).
3. The MISP adapter with fixtures and the verify path.
4. The ATT&CK builder with the fixture bundle; run it once for real and commit the index with the version recorded.
5. The `modules/attack` loader and the route, plus auth tests (unauthenticated → 401).

## Success Criteria
- [ ] Every SSRF case is refused at verify time and at request time (syntactic cases also at save time). TLS verifies the hostname while connecting to the pinned IP.
- [ ] MISP lookups work against the fixtures, including email. TLP tags are carried through.
- [ ] The committed ATT&CK index is reproducible from the pinned bundle (same sha256 of the output for the same input), and `/attack/techniques` labels capa ids.
