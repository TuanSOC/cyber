# M5 AI Security Analyst — architecture research

Based on code at `feat/m4-threat-intel`. Paths are relative to `apps/api/app`.

## 1. Where the LLM call runs

**Use a new `analyst-worker`, not the enrich-worker.**
- `threat_intel/http.py` caps a call at 20 s total, 10 s read and a 1 MiB body. LLM calls take 30–120 s.
- The enrich-worker runs a solo pool with 20 s slices (`TI_SLICE_S`), so one LLM call would starve TI for every org.

Clone the M4 isolation:
- Process role and env:
  - `PROCESS_ROLE=analyst`, added to `ProcessRole`, with the same forbidden-settings guard as enrich (`ENRICH_FORBIDDEN`).
  - `x-analyst-env`, never merged with `*api-env`.
- Celery:
  - Own app, `workers/analyst_app.py`.
  - Queue `analyst` (`Queues.analyst`), tasks `ai.run` / `ai.resume` / `ai.verify`.
  - `ingest-beat` sends `ai.resume` every 30 s; the reaper gains `reap_ai_runs`.
- Broker: ACL user `analyst` with `~analyst* ~test.analyst*` (copy `enrich_keys()` in `infra/redis-broker/entrypoint.sh`).
- Container:
  - Networks `[enrich, egress]` (`enrich` already means "Postgres + broker only").
  - Same hardening as enrich: uid 10001, read-only rootfs, `cap_drop: ALL`.

**Keys go in a separate table, not the TI catalog.** `ProviderName` is baked into the `ti_*` CHECKs and `seal.check_context`, and LLM providers need a model allowlist, token budgets and data-use terms rather than IOC types.
- Add `ai_provider_configs` (`anthropic`, `gemini`, `mock`), mirroring `ti_provider_configs` (sealed columns, `key_version` trigger, no DELETE, terms ack, verify status, limits) plus `model`.
- Parametrize `seal.py` with the scheme (`cyberlab.ai.v1`) and a provider validator.
- Use a separate key pair (`ai_seal_private` secret), so enrich can't open LLM keys and the analyst can't open TI keys.
- Add an AST import guard for `ai/unseal` and `ai/http`.

**Platform key: dev and test only.**
- Delivered as a compose secret file (`AI_PLATFORM_KEY_FILE`), never as an env var.
- Accepted only with `PROCESS_ROLE=analyst`; `_prod_guards` refuses it.
- Prod stays bring-your-own-key. Dev and e2e default to `mock` + `ai-mock`.

## 2. Data consumed

Cite by row `id` (UUID). `analysis_findings.finding_id` is also unique per job; use the row id anyway.

| Pfx | Source | Id | Cap (config) | Default selection |
|---|---|---|---|---|
| J | `analysis_jobs.summary` (counts, truncation, engine errors) | job id | 1 | always |
| F | `analysis_findings` (type, severity, confidence, `detection_method`, `evidence_refs` ≤ 50 flow uids, attributes) | row id | 5 000 pcap / 1 000 static | top 40 by `_SEVERITY_RANK` desc, ts, id |
| A | `network_alerts` (sid, signature, category, sev 1–4) | row id | record caps | top 30 by severity, ts, id; group repeats by sid |
| N | `network_flows` | `flow_ref` (Zeek uid, not an FK) | 100 000 | flows named in the chosen F's refs + top 10 by bytes |
| R | `network_records` dns/http/tls | row id | 100 000 / kind | records on N's flows + aggregates (top domains, hosts, SNI) |
| I | `iocs` | row id | 5 000 | top 50 by count |
| T | `ti_results`, latest per provider (`latest_by_key`) | result id | ≤ 6 / IOC | for the chosen I only; attributed; **never sole evidence** |
| M | `malware_samples` (hashes, type, entropy, pe/elf) | job id | 1 | always (static) |
| S | `malware_signature_matches` | row id | 1 000 | 50 |
| C | `malware_capabilities` + ATT&CK labels (`attack/index.py`) | row id | 1 000 | 60 |
| P | imports/sections summary (reuse `static_analysis/report.py`) | job id + name | — | summary only |
| E | `analysis_timeline` | row id | ≈ F + A + 102 | pcap only (static jobs have no timeline) |
| K | `evidence` + `evidence_custody_events` | row id | small | investigation scope |
| V | `investigations` title / description | inv id | 1 | investigation scope |

`malware_strings` (20 000 rows) is excluded by default. A flag adds at most 30 FLOSS-decoded strings.

**Context strategy:**
- **The API builds and freezes the context**, like `ti_run_items`. It runs in the requester's `require()` session (RLS applies) and stores the result in `ai_run_inputs` with a sha256 and a label→ref map. The worker reads only `ai_*` rows (mitigates RT17).
- **Labels:** short per-run labels (`F1`, `A3`), never UUIDs, so the model can't fabricate an id. Ordering uses the repository sort keys plus `id`, so the same data gives the same hash (cacheable).
- **Budget:** about 60 k characters, filled J/M → F → A/S/C → I+T → E → N/R. `context_stats` records included/total, and the prompt says what was cut.
- **Investigation scope is map-reduce:** per-job digests first (reused when `context_sha256` matches), then the incident summary over V, K and the digests, with labels like `J2:F3`.
- **All text is untrusted** (DNS, URIs, YARA meta, filenames, case description, TI summaries). It goes in a sanitized JSON data block (`summaries.py` stripper).

## 3. Data model (migration `0011`)

Same conventions as M4:
- RLS ENABLE + FORCE;
- composite tenant FKs;
- SELECT and INSERT grants, UPDATE per column;
- `forbid_mutation()` on append-only tables.

Tables:
- **`ai_provider_configs`** (see §1) and **`ai_org_settings`** (`ai_enabled`, `default_provider`, `include_strings`, `redact_internal`).
- **`ai_runs`**
  - Task and target:
    - `task`: `explain_finding`, `explain_alert`, `summarize_pcap`, `explain_static` or `incident_summary`.
    - `scope`: `job` / `investigation`.
    - Targets: `job_id` and `investigation_id` (composite FKs), plus `target_kind` and `target_id`.
  - Provenance: `provider`, `model`, `prompt_version`, `output_schema`.
  - Status: `queued` → `running` ⇄ `waiting` → `completed` / `failed`, plus `error_code`.
  - Context and cost: `context_sha256`, `context_stats` ≤ 16 KiB, `usage` (tokens), `cost_micros`, `price_version`.
  - `requested_by`, `supersedes_run_id`, deadline and timestamps.
  - Add a transition trigger copied from `ti_run_transition`. A regenerate is a new run.
- **`ai_run_index`**: same columns and RLS pattern as `ti_run_index` (lease, resume, deadline, dispatched).
- **`ai_run_inputs`** (append-only): `run_id` PK, `context` jsonb ≤ 512 KiB (the redacted payload actually sent).
- **`ai_context_refs`** (append-only): `run_id`, `label`, `kind`, `ref_id` (uuid, or text for `flow_ref`). Unique (`run_id`, `label`); index (org, kind, ref_id) so M6 can find "which outputs cite finding X".
- **`ai_outputs`** (append-only): `body` jsonb ≤ 64 KiB, pydantic-validated (observations, interpretations, hypotheses, next steps, limitations), plus `validation` (`ok` / `citations_dropped` / `invalid`).
  - Every observation needs ≥ 1 citation.
  - Hypotheses carry a confidence and supporting / contradicting citations.
  - Next steps contain no host commands.
  - Raw model text is never stored.
- **`ai_citations`** (append-only): `output_id`, `claim_path`, `label`, `kind`, `ref_id`, `valid`.

## 4. API and UI

**API** (`modules/ai/`):

| Endpoint | Permission | Notes |
|---|---|---|
| `POST /orgs/{org}/ai/runs` `{task, job_id?, investigation_id?, target?, provider?}` | `evidence.write` | 202 for a new run, 200 when deduplicated; 10 per user per 10 min |
| `GET …/ai/runs?job_id&investigation_id`, `GET …/ai/runs/{id}` | `evidence.read` | `{id}` returns the output plus resolved citations |
| `…/ai/integrations/{provider}` (PUT, DELETE key, verify) | `integrations.manage` | M4 schemas and terms acknowledgement |

Also missing today: `GET /analyses?investigation_id=`. `investigation-analyses.tsx` currently filters the newest 100 org jobs on the client.

**UI:**
- **`pcap/[jobId]`:**
  - Add an "AI Analyst" entry to `RESULT_TABS` (`lib/pcap-results.ts` / `analysis-results.tsx`) for "Summarize capture".
  - Add row "Explain" actions in `findings-tab.tsx` and `alerts-tab.tsx`, opening a `ui/sheet.tsx` drawer.
- **`malware/[jobId]`:** add the tab via `staticTabs()` (`static-results.tsx`) for "Explain static findings", with the same row action on the static `FindingsTab`.
- **`investigations/[invId]`:** add a card under `<InvestigationAnalyses>` with Incident summary, Timeline and Recommendations.
- **`/o/{org}/ai-analyst`:** replace the M5 placeholder with a runs list (clone `ti/recent-runs.tsx`).
- **`settings/integrations`:** add "AI providers" (reuse `integration-card.tsx`, `terms-ack.tsx`).
- **Citations:** chips deep-link to `?tab=…&ref=<id>`; only Flows supports `ref` today.

## 5. M4 reuse

- **HTTP:**
  - Extract `egress_client(allowed_paths, timeouts, cap)` from `ti_client`.
  - Keep `KeyAuth`, the path-guard hook, identity encoding with bounded inflate, strict JSON and the cause-free errors.
  - LLM limits: 120 s total, 2 MiB, no streaming.
  - Allowlist: Anthropic `POST /v1/messages`; Gemini `POST /v1beta/models/{model}:generateContent`, model checked against the catalog.
- **Limiter:** reuse the Lua token bucket, cooldown, `Retry-After` handling and fail-closed behaviour under `analyst.ai:*`. Add an INCRBY daily token budget per org and provider.
- **Lifecycle:** reuse the lease, resume, deadline and fallback reaper from `workers/enrich.py` and `threat_intel/lifecycle.py`. One message = one LLM step; deadline 10 min. Run 2 replicas (the lease keeps that safe).
- **Terms and privacy:** use the catalog `tos_note` / `privacy_note`. The note says that evidence excerpts (IPs, hostnames, URLs, file facts) are sent, and flags tiers that may train on the data.
- **`infra/ai-mock/server.py`** (`test`/`e2e` profiles, `egress` only, uid 65534). A marker in the context selects the answer: valid or malformed JSON, a fabricated label, an injection echo, 429 (with or without `Retry-After`), 529, slow, oversize, refused, or a wrong-key error.
- **Tests:** clone the enrich ACL, network, key-leak and import-guard tests and the TI e2e spec. Add a prompt-injection corpus as the M5 metric.

## 6. Risks and gaps

1. **No investigation-level aggregation.** There is no server-side job filter and no merged timeline: `analysis_timeline` is per pcap job only, and static jobs and custody have none. `latestPerEvidence` exists only in the web app. Build `investigation_timeline()` on the server; M6 needs it too.
2. **No `reports` table** (deferred since M3; reports are built on demand). Keep `ai_outputs` and `ai_context_refs` stable so M6 can embed AI sections.
3. **Privacy inverts M4:** an LLM context carries the private IPs, internal names and URLs that TI never sends. Needs a per-provider ack, an org `ai_enabled` switch, optional pseudonymization and an `ai.run_requested` audit with `context_sha256`. Still no TLP (RT26).
4. **Prompt injection** can come from captures, samples, provider text, filenames and the case description. Defenses: schema-only output, label validation, no tools, text-only rendering, and AI never creates findings or changes severity.
5. **Full app DB role** (RT17), mitigated by API-built snapshots.
6. **No cost controls.** Add per-org daily token caps, `usage` / `cost_micros` and an operator ceiling override (like `TI_CEILINGS`).
7. **Fragile citations:** `flow_ref` isn't an FK, findings have two ids, and TI results go stale. Show stale or missing markers.
8. **`seal.check_context` and the TI CHECK constraints hard-code `ProviderName`.** Refactor them before reuse.
