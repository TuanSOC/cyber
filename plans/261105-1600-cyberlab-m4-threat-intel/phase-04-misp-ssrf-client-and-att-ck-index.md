---
phase: 4
title: MISP SSRF client and ATT&CK index
status: completed
priority: P1
effort: 8h
dependencies:
  - 2
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
- [x] Every SSRF case is refused at verify time and at request time (syntactic cases also at save time). TLS verifies the hostname while connecting to the pinned IP. — `test_ti_ssrf_resolve.py::test_non_public_answers_are_refused`, `test_verify_marks_a_non_public_host_invalid`, `test_dns_rebinding_public_on_verify_private_on_request`, `test_redirect_is_refused_and_not_followed`, `test_tls_verifies_the_hostname_while_connecting_to_the_pinned_ip`, `test_tls_refuses_a_certificate_for_another_name`; `test_ti_ssrf.py::test_refused_urls` (913023d, 5376596).
- [x] MISP lookups work against the fixtures, including email. TLP tags are carried through. — `test_ti_misp.py::test_lookup_fixture` (42 cases), `test_email_hit_searches_email_types_and_keeps_tlp_red`, `test_tlp_cap_never_hides_red` (913023d).
- [x] The committed ATT&CK index is reproducible from the pinned bundle (same sha256 of the output for the same input), and `/attack/techniques` labels capa ids. — `test_build_attack_index.py::test_output_is_compact_sorted_and_reproducible`, `test_sha256_mismatch_aborts`; `test_attack_index.py::test_committed_index_is_valid_and_pinned`, `test_committed_index_labels_capa_ids`; `test_attack_route.py::test_labels_and_meta_for_authenticated_users` (b83d6f2).

## Implementation Notes (2026-11-05)
- **Commits and order (deviation):** the ATT&CK builder, index and route landed early, in b83d6f2 (before phase 2), together with the MISP fixtures. 913023d holds the MISP adapter, resolution and pinning, and the phase 3–5 worker review fixes.
- **Resolution** (`ssrf.resolve_pinned`):
  - `getaddrinfo` runs in a bounded pool of 4 resolver threads with a 2 s timeout.
  - **Review (bounded DNS pool):** when every thread is busy, the lookup fails at once with `dns_busy` instead of queueing behind stuck lookups (`test_system_resolver_fails_fast_when_every_dns_thread_is_stuck`).
  - **Every** answer must be global after unwrapping mapped, 6to4, NAT64 and Teredo addresses, otherwise `misp_url_not_public` (`test_non_public_answers_are_refused`). An IP literal is re-checked without DNS.
- **`PinnedTransport`:**
  - It re-resolves before every request and connects to the first validated address, with `Host` and `sni_hostname` set to the hostname. IPv6 is bracketed, an IP-literal base sends no SNI, and any other origin is refused before resolving.
  - Tests: `test_request_goes_to_the_pinned_ip_with_host_and_sni_of_the_hostname`, `test_dns_rebinding_public_on_verify_private_on_request`, `test_redirect_is_refused_and_not_followed`, `test_oversize_body_is_refused_at_the_misp_cap` (2 MiB), `test_transport_refuses_any_other_origin_before_resolving`.
- **TLS against a pinned IP:** a local server with a CA-signed certificate for a fake hostname, run in api-test (`test_tls_verifies_the_hostname_while_connecting_to_the_pinned_ip`, `test_tls_refuses_a_certificate_for_another_name`).
  - `TI_MISP_CA_FILE` is supported. `TI_MISP_INSECURE_TLS` logs a warning and is refused in prod (`test_tls_verify_settings`, `test_prod_refuses_allow_private_and_insecure_tls`).
- **Review (IDN punycode compare):** the allowlist and the pin compare IDN hosts in punycode (`test_idn_host_is_pinned_and_allowed_in_punycode`, `test_org_host_paths_compare_an_idn_in_punycode`).
- **`TI_MISP_ALLOW_PRIVATE`** (dev only) allows private ranges, but never loopback, link-local/metadata or the unspecified address (`test_dev_allow_private_never_allows_loopback_metadata_unspecified`).
- **MISP adapter** (`providers/misp.py`):
  - Only `POST {prefix}/attributes/restSearch` (`limit` 50, `enforceWarninglist`, `includeEventTags`, `deleted` false) and `GET {prefix}/servers/getVersion` (`test_allowlist_is_restsearch_post_and_getversion_get_only`, `test_allowlist_enforced_before_sending`).
  - The raw key goes in `Authorization`. Email searches the `email-src` / `email-dst` types.
  - 42 manifest cases (`test_lookup_fixture`, `test_verify_fixture`, `test_verify_errors`).
- **Summary:**
  - Up to 20 attributes plus `attribute_count`; ATT&CK galaxy tags become `attack_ids`.
  - TLP markings are sorted most restrictive first and capped at 4, so RED and AMBER are never cut (`test_tlp_cap_never_hides_red`, `test_email_hit_searches_email_types_and_keeps_tlp_red`).
  - `event_id` must be numeric. The permalink is `{base_url_norm}/events/view/{id}` for the first valid event, keeping the port and path prefix (`test_permalink_uses_base_url_norm_with_port_and_prefix`, `test_event_id_must_be_numeric`).
  - Hostile attributes are sanitized and produce no permalink.
- **Key binding:** `test_misp_key_sealed_for_url_a_does_not_open_for_url_b`; the worker opens MISP only through the pinned transport (`test_worker_opens_misp_through_the_pinned_transport`).
- **ATT&CK builder** (`scripts/build_attack_index.py` + `modules/attack/build.py`, stdlib only):
  - Pinned to Enterprise **v20.0**, sha256 `81113ba9…`.
  - Output: `attack_enterprise_v20.0.json` with 867 techniques, about 173 KB (the estimate was about 300 KB).
  - Tests: `test_fixture_bundle_gives_expected_index`, `test_output_is_compact_sorted_and_reproducible`, `test_sha256_mismatch_aborts`, `test_version_must_match_the_bundle`, `test_rejects_non_bundles_and_unknown_tactics`.
- **Index loader:**
  - Validated at load; a dangling reference is rejected.
  - Revoked ids follow their chain to the replacement; deprecated ids are flagged.
  - Tests: `test_committed_index_is_valid_and_pinned`, `test_committed_index_labels_capa_ids`, `test_committed_index_resolves_revoked_ids`.
- **Route** `GET /api/v1/attack/techniques?ids=`:
  - at most 100 ids, `422 invalid_attack_ids` otherwise;
  - `meta` carries the version and the MITRE notice;
  - anonymous callers get 401 (`integration/test_attack_route.py`).
- **Worker review fixes in 913023d:**
  - TaskGroup lanes and the lease renewer (see phase 2), and verify dedupe;
  - **VT quota escalation:** 3 consecutive 429s are taken as a spent daily quota. A burst of in-flight requests counts once, and a real answer resets the count (`test_consecutive_429s_are_taken_as_a_spent_daily_quota`, `test_a_real_answer_resets_the_429_strikes`, `test_429_strikes_count_a_burst_once_and_reset`).
- **Residuals:** TLP is shown, not enforced. MISP answers never become IOC sources and are never forwarded to another provider.
