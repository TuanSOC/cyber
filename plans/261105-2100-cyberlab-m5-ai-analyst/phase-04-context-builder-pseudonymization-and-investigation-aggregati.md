---
phase: 4
title: "Context builder pseudonymization and investigation aggregation"
status: pending
priority: P1
effort: "12h"
dependencies: [1]
---

# Phase 4: Context builder pseudonymization and investigation aggregation (group B, 2c)

## Overview
The deterministic context builder that the API runs in the requester's RLS session. It covers:
- per-kind selectors with priorities and caps;
- sanitization, defanging and pseudonymization;
- label assignment, the token estimate and truncation records;
- canonical JSON with its sha256;
- the incident map-reduce plan and the reduce-stage context.

It also adds the server-side reads that investigation-level analysis and the citation deep links need: analyses by investigation, the merged investigation timeline, and `ref=` row filters on the pcap and static result routes.

**Owns:**
- `app/modules/ai/context/**` (it fills the phase-1 stubs `builder.py` / `reduce.py` and adds `select.py`, `pseudonymize.py`, `estimate.py`, `encode.py`, `fields.py`);
- `app/modules/investigations/timeline.py`, plus the timeline route in `investigations/router.py` and its schema in `investigations/schemas.py`;
- `analysis/{repository,router,schemas}.py` (investigation filter);
- `pcap_analysis/{router,repository}.py` and `static_analysis/{router,repository}.py` (`ref` filters);
- `tests/security/idor_cases_reads.py` (the IDOR case for the timeline route, RT11);
- tests `unit/test_ai_context_*.py`, `integration/test_ai_context_builder.py`, `test_investigation_timeline.py`, `test_analyses_by_investigation.py`, `test_result_ref_filters.py`.

## Requirements
- **`build_run(session, org_id, user_id, req, settings_row) -> BuiltRun`** (frozen signature), inside the caller's `require()` session. It never opens its own session and never bypasses RLS.
  - **Validation:** the target exists in the org (job `succeeded`, with the right analyzer for the task; the finding or alert belongs to the job; the investigation exists). Errors are the frozen `ContextBuildError(code)` (`job_not_ready`, `target_not_found`, `task_not_applicable`, `context_empty`) for phase 7 to map.
  - **Selectors** (`select.py`), one per `RefKind`, as in the architecture report's table:
    - repository sort keys + `id` for determinism;
    - default caps: F 40, A 30 (grouped by sid with counts), I 50, T latest per provider for the chosen I only (`include_ti`), S 50, C 60, E 100, N named by the chosen F refs + top 10 by bytes, R records on those flows + aggregates (top domains, hosts, SNI), X ≤ 30 FLOSS-decoded strings only with `include_strings`, P summary, M sample facts, J summary, K evidence + custody summary, V title/description only with `include_case_text`.
    - The per-task cores follow plan.md's task table. `explain_finding` / `explain_alert` put the target first and add its related rows.
  - **Field allowlist per kind** (`fields.py`, internal to this phase). The verifier does not import it: a citation's `field` is valid iff it is a key of that item's `ContextItem.fields` as sent. Examples: finding `type, title, severity, confidence, detection_method, summary, attributes.*` (flattened, capped); alert `signature, sid, category, severity, src, dst, ts`; record `kind, qname, qtype, rcode, host, method, uri_path, uri_query_keys, status, user_agent, sni, cert_cn`.
    - **Never selected:** Authorization, Cookie, Set-Cookie, basic-auth, NTLM/Kerberos user fields, raw payload bytes, TI keys, analyst notes.
    - **Attribute keys (RT4):** flattened `attributes.*` keys are written by the untrusted analyzers; a key that does not match `^[a-z0-9_]{1,32}(\.[a-z0-9_]{1,32}){0,2}$` drops the attribute and is counted in `context_stats.dropped_keys`. Field names never appear outside the evidence block.
  - **Value transforms**, in this order:
    1. `text.sanitize` (counts recorded), then neutralize pseudonym-shaped tokens already present in the raw value (`INT_IP_7` → `INT-IP-7`, `USER_2` → `USER-2`; counted, RT15);
    2. URL query values replaced (`?a=…&b=…`, keys kept) and fragments dropped;
    3. pseudonymize;
    4. `text.defang` for URLs and domains (IPs stay plain);
    5. `text.truncate(256)` with `…[truncated n]`, recording per-kind counts of truncated fields (the marker itself stays inside the value; no field names in `context_stats`, RT4).
  - **Pseudonymization** (`pseudonymize.py`; default on, org-configurable):
    - internal IPs: RFC 1918, 100.64/10, loopback, link-local, ULA, IPv4-mapped forms and org `internal_cidrs`;
    - hostnames: single-label names, special-use TLDs (`local`, `lan`, `internal`, `corp`, `home.arpa`, `localdomain`, `intranet`, `private`, `home`), PTR names under `arpa` and org `internal_suffixes`;
    - usernames: `C:\Users\<x>\`, `/home/<x>/`, PDB paths, and the email local part when the domain is internal.
    - Replacements are stable per run tree (`INT_IP_n`, `INT_HOST_n`, `USER_n`, numbered in first-appearance order of the deterministic selection) and applied inside larger strings too (URIs, qnames, paths).
    - The reverse map (`{pseudonym: original}`) goes only into `ai_run_inputs.pseudonym_map`.
    - Public IOCs are untouched. Counts per category go in `context_stats.pseudonymized`.
  - **Labels:** prefix + per-kind counter in selection order (`F1…`). `ContextRef` holds kind, table, `ref_id` (uuid text, or the Zeek uid for N), `job_id` (always set; N refs are identified by (`job_id`, `flow_ref`), never by the uid alone, RT16) and `fields_sha256` (the sha256 of the rendered fields).
  - **Budget** (`estimate.py`): a conservative estimate (`ceil(len(canonical_json) / 3)`). Fill kinds in priority order until `AI_MAX_INPUT_TOKENS` minus the prompt overhead constant (exported for phase 5 to assert against). Record per-kind `{included, total}`, `omitted` and `est_tokens`; `truncated=true` whenever anything was left out.
  - **Canonical JSON** (`encode.py`): sorted keys, no whitespace, NFC, ensure_ascii false; `sha256` over `{version, task, items}`. The same DB state gives the same hash (property test).
  - **Incident** (`task=incident_summary`):
    - children are one `job_digest` context per latest succeeded job per evidence in the investigation (newest first, ≤ `AI_MAX_JOBS_PER_INCIDENT`; the rest counted as omitted);
    - the root base context holds V (opt-in text), K and the merged timeline E (≤ 100, from `investigations/timeline.py`), with child labels prefixed `J{n}`;
    - one shared pseudonymizer across all children and the root;
    - `BuiltRun = {root: FrozenContext, children: [FrozenContext…]}`.
- **`build_reduce_context(base, digests)`** (pure):
  - adds `D` items per child (`J{n}:D{k}`) carrying only the **supported** claim texts and hypotheses (marked `kind: digest_claim`, `untrusted: model_output`, plus the child's `flags`, RT23), each with its verified citations rewritten to `J{n}:<label>`;
  - copies those cited child items (`J{n}:F3` …) into the reduce context with their original field values, so the verifier can check quotes;
  - same caps, estimate and hash rules.

  `D` labels are never valid as evidence (the verifier, phase 5, enforces this; this phase marks the kind).
- **`preview(...)`:** same as `build_run`, without children for an incident (it previews the root and the first child), never persisted.
- **Investigation reads:**
  - `GET /orgs/{org}/analyses?investigation_id=&latest_per_evidence=true|false` (`evidence.read`; existing paging and filters kept; index check with `EXPLAIN`).
  - `GET /orgs/{org}/investigations/{inv}/timeline?cursor&limit` (`evidence.read`):
    - merges evidence uploads and custody events, analysis job requested / succeeded / failed events, `analysis_timeline` rows of the latest succeeded pcap job per evidence, alerts by ts, and static findings at job finish time (`ts_source: analysis_time`);
    - each entry `{ts, ts_source, kind, title, severity?, evidence_id, job_id?, ref_kind, ref_id}`, sorted (ts, kind, id), cursor-paged, ≤ 500 per page.
  - `ref=<row id>` on `…/analyses/{job}/findings|alerts|iocs|records|timeline` and the static `signatures|capabilities|strings|imports` routes: returns a page with just that row (404 if it is not in the job). It is a filter only, with no new data exposure (same permission, same job scope). The flows route keeps its existing `ref` (always scoped by the job in the path).
- **No route of this phase reaches a provider.** The builder is pure DB plus transforms.

## Implementation Steps
1. `fields.py`, `encode.py`, `estimate.py`, `pseudonymize.py` with unit and property tests (hypothesis):
   - a private IP inside any field never survives unpseudonymized when the setting is on;
   - stable numbering;
   - no credential field is ever selected;
   - sanitize removes every listed code point;
   - the hash is stable under row insertion order.
2. Selectors per kind against the existing seeded result helpers (`tests/pcap_results.py`, `tests/static_results.py`); per-task cores; caps and truncation records.
3. `build_run` / `preview` / incident children; `reduce.py`.
4. `investigations/timeline.py` + route; the analyses filter; the `ref` filters. Tests for each, including cross-org 404. Add the timeline route's case to `tests/security/idor_cases_reads.py` (path frozen in phase 1) so `test_idor_routes.py` passes in this lane (RT11).
5. Integration test `test_ai_context_builder.py`:
   - for a seeded pcap job and a static job: labels, refs, stats and the hash are deterministic;
   - a second org's rows never appear;
   - the pseudonym map round-trips;
   - field caps are honoured;
   - the target-first ordering for explain tasks;
   - no field name, title or filename appears in `context_stats` (only kinds and counts), and hostile attribute keys are dropped (RT4).

## Success Criteria
- [x] The same DB state gives byte-identical canonical context and sha256; the selection order is documented. — `test_ai_context_builder.py::test_summarize_pcap_is_deterministic_and_pseudonymized`, `test_ai_context_fields.py::test_hash_is_stable_under_row_insertion_order`, `test_canonical_json_matches_the_frozen_context`, `test_ai_context_pseudonymize.py::test_numbering_is_deterministic`, `test_ai_eval_invariants.py::test_contexts_do_not_depend_on_the_org` (83f24a1); order in docs/AI_ANALYST.md "Tasks" and "Labels and selection" (0f776a3).
- [x] With pseudonymization on, no RFC 1918 / ULA / org-CIDR address, internal hostname or username from the seeded cases appears in the context (property and fixture tests). — property `test_ai_context_pseudonymize.py::test_no_internal_value_survives` (hypothesis, 200 examples), `test_internal_addresses_are_replaced`, `test_org_cidrs_are_internal_and_garbage_is_ignored`, `test_special_use_hostnames_are_replaced`, `test_usernames_in_paths`, `test_schemeless_query_values_never_leave` (83f24a1); through the real worker `test_ai_pipeline.py::test_nothing_internal_leaves_with_pseudonymization_on` (6b52742).
- [x] Credentials and payload bytes are never selected; every truncation and omission is recorded in `context_stats`. — `test_ai_context_fields.py::test_allowlists_hold_no_credential_field`, `test_no_credential_or_hostile_key_is_ever_selected`, `test_record_fields_never_carry_query_values_or_referrer`, `test_stats_never_carry_field_names_titles_or_keys`; `test_ai_context_pseudonymize.py::test_truncation_is_counted_and_marked`; `test_ai_context_builder.py::test_caps_are_honoured`, `test_budget_fill_stops_in_priority_order`, `test_incident_jobs_over_the_cap_are_counted` (83f24a1).
- [x] The investigation timeline, the analyses-by-investigation filter and the `ref` filters are tested, including cross-org isolation. — `test_investigation_timeline.py` (5 tests, including `test_errors_and_isolation`, `test_cursor_pages_cover_everything_once`), `test_analyses_by_investigation.py::test_foreign_or_unknown_investigation_is_404`, `test_investigation_filter_uses_the_indexes`, `test_result_ref_filters.py::test_ref_never_crosses_organizations`, `test_flows_are_referenced_by_flow_ref_within_the_job`; the timeline IDOR case is in `idor_cases_reads.py` (83f24a1).

## Risk Assessment
- **The token estimate is wrong for hash-heavy or non-ASCII content.** It is conservative by construction, and the worker's `count_tokens` preflight catches overshoot (`context_too_large`).
- **Pseudonymization is pattern-based** and misses internal names outside the listed patterns. The org settings for CIDRs and suffixes and the preview UI make this visible; the docs state the residual.
- **Context too thin to be useful** after the caps. The caps are settings; the eval (phase 6) measures golden recall to tune them.

## Implementation Notes (2026-11-06)
- **Commit:** 83f24a1 (lane run, see phase 2). It adds:
  - `context/{builder,select,fields,transform,pseudonymize,assemble,encode,estimate,reduce}.py` and `investigations/timeline.py`;
  - the analyses filter and the `ref` filters in the analysis, pcap and static repositories and routers.
- **Caps** (`select.py`):
  - F 40, A 30 groups (by sid), I 50, S 50, C 60, E 100, R 50, X 30, K 50, related rows 20;
  - N: the flows the findings name (≤ 40) plus the top 10 by bytes;
  - scan limit 500 rows.
- **Budget:**
  - The estimate is `ceil(len(canonical JSON) / 3)`, against `AI_MAX_INPUT_TOKENS` (60 000) minus 4 000 tokens of prompt overhead.
  - The first item that does not fit ends the fill and rolls back its pseudonyms (`test_budget_stops_at_the_first_item_that_does_not_fit_and_rolls_back_names`).
  - Nothing fitting is `422 context_empty` (`test_nothing_fits_is_context_empty`).
- **Ordering:** the explain tasks put the target first (`test_explain_finding_puts_the_target_first`, `test_explain_alert_puts_the_target_first`); strings are opt-in (`test_explain_static_with_and_without_strings`).
- **Attribute keys (RT4):**
  - grammar `^[a-z0-9_]{1,32}(\.[a-z0-9_]{1,32}){0,2}$`, at most 16 per finding, field names ≤ 64 characters;
  - anything else is dropped and counted in `dropped_keys`;
  - tests: `test_attribute_key_grammar`, `test_attribute_count_is_capped`, `test_nested_attributes_flatten_with_depth_and_name_limits`.
- **Transform order:**
  1. sanitize;
  2. neutralize planted pseudonym-shaped tokens (RT15: `test_planted_pseudonyms_are_neutralized`, `test_transform_order_planted_tokens_cannot_collide`);
  3. replace URL query values;
  4. pseudonymize;
  5. defang;
  6. truncate to 256 characters with a marker.
- **Pseudonymization:**
  - IPs: RFC 1918, CGNAT, loopback, link-local, ULA, IPv4-mapped forms (`test_ipv4_mapped_form_shares_the_pseudonym`) and the org CIDRs (≤ 50).
  - Hostnames: special-use TLDs, PTR names under `arpa`, the org suffixes, and single-label names in hostname fields only.
  - Usernames: profile paths, where `Public` and `Default` stay; the local part of an internal email.
  - `INT_IP_n` / `INT_HOST_n` / `USER_n` are numbered in first-appearance order. One pseudonymizer serves the whole incident tree (`test_incident_children_root_and_shared_pseudonyms`).
- **Review (Medium), schemeless URL query leakage:** queries in free text without a scheme (`host/path?a=b`, `GET /login.php?user=…`) leaked their values.
  - Now any `?` directly followed by `key=` is redacted, together with its fragment.
  - URI-typed attributes (`uri`, `url`, `path`, `uri_path`, `request`, `referrer`, `location`) lose even a bare query.
  - Tests: `test_schemeless_query_values_never_leave`, `test_uri_and_host_attributes`.
  - HTTP records select only `uri_path` and `uri_query_keys`.
- **Eval-found bug:** the pseudonymizer treated structural values such as `detection_method: heuristic:dns_anomaly@1` as email addresses and rewrote them.
  - Now structural fields (types, methods, ids, hashes) are never pseudonymized, and `x@1`-shaped values are not emails.
  - Tests: `test_not_an_email`, `test_structural_fields_are_never_pseudonymized`, `test_structural_registry_covers_known_kinds`.
- **Reduce** (`reduce.py`):
  - The child's digest claims become `J{n}:D{k}` items, marked untrusted and carrying the child's flags (RT23).
  - The child's cited items are copied as `J{n}:F3`, with their original values.
  - The budget cuts copied items before claims (`test_budget_cuts_copies_after_claims`, `test_copied_items_keep_the_child_values_and_refs`).
- **Investigation surfaces:**
  - `GET /orgs/{org}/investigations/{id}/timeline`: cursor-paged; merges every source in order; only the latest pcap job contributes (`test_only_the_latest_pcap_job_contributes`);
  - `GET …/analyses?investigation_id=&latest_per_evidence=true`;
  - `ref=<row id>` on the pcap findings, alerts, IOCs, records and timeline, and on the static tabs;
  - flows are keyed by (`job_id`, `flow_ref`) (RT16).
- **Deviation:** the API only estimates tokens (it has no egress). The precise `count_tokens` preflight runs in the worker (phase 2), as planned. No separate selection-order document was written: it lives in AI_ANALYST.md.
