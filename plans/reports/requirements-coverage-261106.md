# Requirements coverage audit — requirement.txt vs code (2026-11-06)

Scope: branch `feat/m6-reports` (M1–M5 complete, M6 nearly complete). Read-only audit: code was grepped and read; no tests, docker or git were run.
Legend: **Done** (with evidence) · **Partial** (what is missing) · **Missing** · **Deferred** (a recorded decision, with where it is recorded).

## Headline

- The six MVP priorities (§2) are all built and tested: case management, PCAP, malware static, TI, AI analyst and reports.
- Planned gaps are memory, disk and RE forensics, dynamic analysis, OpenSearch, backup/restore and retention. Most are recorded in ROADMAP, PRD or THREAT_MODEL.
- Three gaps are real and not recorded anywhere:
  1. `docs/SANDBOX_SECURITY.md` (required by §15) does not exist, and neither does any §7 sandbox design.
  2. Five §11 tables (`analysis_results`, `threat_intelligence`, `attack_techniques`, `investigation_timeline`, `api_keys`) are not mapped to the tables that implement them.
  3. Autopsy and the `correlation` module are not mentioned in any doc.

---

## §3 Technology stack

| Item | Status | Evidence / note |
|---|---|---|
| Next.js, TypeScript | Done | `apps/web/package.json` (next 16.4.5, TS 5) |
| Tailwind CSS, shadcn/ui | Done | `@tailwindcss/turbopack`, `components.json`, `apps/web/components/ui/*` |
| React Query | Done | `@tanstack/react-query` ^5, used throughout (e.g. `app/(app)/o/[orgId]/page.tsx`) |
| Python, FastAPI, SQLAlchemy, Pydantic, Alembic | Done | `apps/api/app`, `apps/api/alembic/versions/0001…0013` |
| PostgreSQL | Done | `docker-compose.yml` `postgres:17.11-alpine`, RLS (`tests/integration/test_rls.py`, `test_rls_coverage.py`) |
| **OpenSearch** | **Deferred** | No code, compose service or dependency (grep: none). Recorded in ROADMAP M2 ("Postgres suffices at this scale") and PRD non-goals. Not mentioned in ARCHITECTURE.md. Effect: there is no cross-case or org-wide search (see §12). |
| Redis, Celery | Done | `redis` + `redis-broker` with per-component ACLs (`infra/redis-broker`); Celery apps in `apps/api/app/workers/*_app.py` and each worker |
| MinIO | Done (with a caveat) | object-locked, versioned buckets (`infra/minio/init.sh`). Uses the frozen `bitnamilegacy/minio` image, which gets no security patches (THREAT_MODEL known gap). |
| Docker, Docker Compose | Done | `docker-compose.yml`, `docker-compose.prod.yml`, `docker-compose.ai-platform.yml` |
| TShark | Done (narrow) | `pcap_worker/engines/capture_info.py`: capinfos plus `tshark -z io,phs` (protocol hierarchy only). Flows and app-layer parsing come from Zeek. |
| Zeek | Done | `engines/zeek.py` (conn, dns, http, ssl, x509, files) |
| Suricata | Done | `engines/suricata.py`, ET Open baked at build (`pcap/Dockerfile`) |
| YARA, capa, FLOSS, pefile | Done | `static/Dockerfile`, `probe/yarascan.py`, `engines/capa.py`, `engines/floss.py`, `probe/pe.py` |
| **Detect It Easy** | **Deferred** | Not installed. Recorded in ROADMAP M3 deferrals and MALWARE_ANALYSIS.md §"Not done". Packer detection uses capa rules, section entropy and names instead. |
| CAPE Sandbox | Deferred (gated) | ROADMAP "Gated". This matches §7 ("later isolated integration"). |
| Volatility 3, Plaso, The Sleuth Kit | Deferred | ROADMAP "Later"; the nav pages are honest placeholders (`lib/nav.ts` `plannedFor`) |
| **Autopsy** | **Missing (undocumented)** | Not mentioned in any doc or ROADMAP |
| Ghidra / headless, radare2 | Deferred | ROADMAP "Later" |
| Claude API, Gemini API, provider abstraction, structured JSON | Done (offline) | `modules/ai/providers/{anthropic,gemini,registry}.py`, `output_schema.py` (`ai.v1`). No live model run has been recorded (`plans/reports/ai-metric-261105.md`). |

## §4 Core architecture

| Item | Status | Evidence / note |
|---|---|---|
| Modular monolith + separate workers | Done | `apps/api/app/modules/*`; pcap, static and report workers are untrusted; ingest, enrich and analyst workers are trusted (ARCHITECTURE.md) |
| authentication | Done | `modules/auth` (register/login/refresh rotation/logout, auth_events) |
| users | Done (thin) | `modules/users` (models + repository only). No password change/reset, MFA or email verification (PRD "Later"). |
| organizations | Done | `modules/organizations` (orgs, members, storage quota) |
| investigations, evidence, audit | Done | `modules/investigations`, `modules/evidence`, `modules/audit` |
| pcap_analysis | Done | `modules/pcap_analysis` + `apps/workers/pcap` |
| malware_analysis / static_analysis | Done (merged) | `modules/static_analysis` + `apps/workers/static`. One module covers both names. |
| dynamic_analysis | Deferred (gated) | ROADMAP "Gated". There is no module, interface stub or design doc (see §7 and §15). |
| memory_forensics, disk_forensics, reverse_engineering | Deferred | ROADMAP "Later" |
| threat_intelligence, ai_analyst, reports | Done | `modules/threat_intel`, `modules/ai`, `modules/reports` (+ notes, ioc_collections, case_attack, case_timeline) |
| **correlation** | **Partial (undocumented)** | No `correlation` module. Correlation is spread across features: AI `ioc_correlation` (`ai/context/builder.py:315`), case-wide IOCs (`ioc_collections/case_iocs.py`), the TI join on `ioc_key`, ATT&CK suggestions and `cited-by`. There is no deterministic cross-job or cross-case correlation (shared IOC across cases, flow ↔ sample hash). |
| Clear engine interface | Done | `modules/analysis/analyzers.py`, `dispatch.py`, `lifecycle.py`; worker kit `packages/py-worker-kit` |
| Versioned job schemas | Done | `packages/py-jobs/src/cyberlab_jobs`: `pcap.v1`, `static.v1`, `report.render.v1`, `report.rendered.v1`, `cyberlab.report.v1`, ingest messages; `tests/unit/test_job_contracts.py` |
| API never executes untrusted files | Done | The API only hashes and sniffs (libmagic on 8 KiB, metadata only, `evidence/uploads.py:_sniff`). Parsing runs in workers on the internal `analysis` network. |

## §5 PCAP analysis engine

| Item | Status | Evidence / note |
|---|---|---|
| PCAP/PCAPNG upload | Done | `analysis/service.py:auto_choice` (magic detection), 512 MiB cap |
| File integrity hashing | Done | MD5/SHA-1/SHA-256 at upload (`core/hashing.py`). The worker re-verifies sha256 and size of the exact version (`test_analysis_pipeline.py`). |
| TShark parsing | Partial | Used only for the protocol hierarchy (`capture_info.py:75`). Per-packet parsing is Zeek. This is acceptable, but "TShark parsing" overstates what TShark does. |
| Zeek log ingestion | Done | `analyzer.py` (conn/dns/http/ssl/x509) → `network_flows`, `network_records` |
| Suricata alert ingestion | Done | `engines/suricata.py` → `network_alerts` |
| Protocol stats; src/dst IP stats | Done | job summary (`analysis-overview.tsx`), flows tab filters (`ip`, `port`) |
| DNS / HTTP / TLS metadata | Done | Zeek records + JA3/JA3S from Suricata eve (`analyzer.py:145 JA3Lookup`). JA4 deferred (ROADMAP M2). |
| TCP conversations | Done | conn-level flows with community id |
| Flow reconstruction | Partial | Flows are 5-tuple sessions. There is no TCP stream reassembly or "follow stream" payload view. Zeek `files` gives file hashes only, with no carving. Not recorded as a deferral. |
| Beaconing, suspicious traffic, scan, DNS anomaly | Done | `detections/flow_detectors.py` (BeaconDetector, ScanDetector), `record_detectors.py` (DnsDetector, SuspiciousTraffic) |
| IOC extraction | Done | `detections/iocs.py` → `iocs` |
| Network timeline | Done | `analysis_timeline`, `GET …/analyses/{job}/timeline` |
| Normalized finding fields | Done | `analysis_findings` (`pcap_analysis/models.py:132`): `finding_id`, job→evidence, ts/last_seen, endpoints (src/dst), protocol, severity, confidence, `evidence_refs`, `detection_method` |
| Never malicious on IP reputation alone | Done | Detectors never read TI. TI is source-attributed and verdict-free (THREAT_INTEL.md; web `ti-wording.test.ts`). |

## §6 Malware static analysis

| Item | Status | Evidence / note |
|---|---|---|
| SHA256/SHA1/MD5 (+ssdeep, imphash, rich hash) | Done | `probe/facts.py`, `probe/pe.py:108-136` |
| File identification | Done | libmagic in `probe/facts.py` (as the tool uid) |
| PE metadata, ELF metadata | Done | `probe/pe.py` (pefile), `probe/elf.py` (pyelftools) |
| Sections, imports/exports, resources | Done | `malware_sections`, `malware_imports`, `malware_exports`, `malware_resources` |
| Strings, entropy, packer indicators | Done | `probe/strings.py`, `common.entropy`, packer finding (`detections/structure.py`; `packed_like` sample) |
| YARA, capa, FLOSS | Done | engines as above; `malware_signature_matches`, `malware_capabilities`, `floss_*` string encodings |
| Suspicious API indicators | Done | `detections/apis.py` |
| IOC extraction | Done | `detections/iocs.py` |
| Structured analysis report | Done | `GET …/analyses/{job}/report` (`static_analysis/report.py`), web `malware/[jobId]/report` |
| Not proof of malware | Done | verdict-free findings (MALWARE_ANALYSIS.md; benign near-misses in `samples/generate.py:447`) |
| Mach-O | Deferred (not required) | §6 does not ask for it. Recorded in MALWARE_ANALYSIS.md:20/105 and ROADMAP M3. |
| Authenticode chain validation, archive extraction | Deferred | ROADMAP M3. Presence only (`has_authenticode`). |

## §7 Dynamic analysis architecture

| Item | Status | Evidence / note |
|---|---|---|
| Separate sandbox integration designed | **Missing** | §7 asks for a design now and an enabled sandbox later. The repo only says "Gated … not enabled until isolation is tested" (ROADMAP) and "Sandbox escape assumptions ⏳" (TESTING.md:76). Nothing covers disposable VMs, snapshot rollback, egress control, the clipboard or job contracts. `docs/SANDBOX_SECURITY.md` does not exist. |
| Disposable VMs, isolation, snapshot rollback, resource limits, no host FS/clipboard, controlled egress, time limits, sample integrity, audit | Deferred (gated), not designed | Enabling it later is deliberate. The missing design is a §15 gap. Integrity verification of samples and per-job audit already exist in the M2/M3 pipeline and can be reused. |
| Never execute on host / shared API containers | Done (by absence) | Nothing executes samples. The static worker "never executes" (static `README.md`). |

## §8 Threat intelligence

| Item | Status | Evidence / note |
|---|---|---|
| VirusTotal, AbuseIPDB, URLhaus, OTX, MalwareBazaar, MISP | Done | `threat_intel/providers/{virustotal,abuseipdb,abusech,otx,misp}.py`; fixtures `test_ti_provider_adapters.py`. No live run recorded (TESTING.md). |
| MITRE ATT&CK | Done (as an offline index, not a provider) | `modules/attack/index.py` (Enterprise v20, pinned), `GET /api/v1/attack/techniques`. ICS/Mobile deferred (ROADMAP M4). |
| IOC lookup, reputation enrichment | Done | `POST …/ti/lookups`, `POST …/analyses/{job}/enrichments` |
| Source attribution, cache, history | Done | `ti_results` append-only history used as the cache (`cache.py`, `test_ti_cache.py`) |
| Rate limit handling | Done | `threat_intel/ratelimit.py` (broker-side, time-sliced, waiting/resume), `test_ti_ratelimit.py` |
| API key management, encrypted, never sent to the browser | Done | sealed per-org keys (`core/sealbox.py`, `threat_intel/seal.py`; the API encrypts only), write-only UI, sentinel crawl `test_ti_key_leak.py` |
| Auto-enrichment after ingest | Deferred | ROADMAP M4 (consent model) |

## §9 AI security analyst

| Item | Status | Evidence / note |
|---|---|---|
| Explain alerts / findings, summarize PCAP, explain static, correlate IOC, ATT&CK mapping, incident summary + timeline + recommendations | Done | `AiTask` in `ai/contracts.py` (explain_finding/alert, summarize_pcap, explain_static, ioc_correlation, attack_mapping, incident_summary + job_digest) |
| Reports with evidence citations | Partial (by design) | Reports cite rows with `[Cn]` and include verified AI runs, but "AI never drafts analyst sections in M6" (REPORTS.md:127). AI does not generate the report text. |
| Observed / interpretation / hypothesis / confidence / next step | Done | `ai/output_schema.py:106-111` (+ `limitations`) |
| AI must not invent evidence | Done (detected, not prevented) | deterministic verifier `ai/verify.py` re-queries every cited row; `test_ai_verify.py`, `test_ai_verify_db.py` |
| No arbitrary commands / no host access | Done | no tools for the model; command-like steps flagged; analyst-worker has least-privilege egress (`tests/container/test_analyst_network.py`) |
| Live quality | Partial | Citation accuracy is measured only against Fake and Hostile providers. Live Anthropic/Gemini: none recorded (`ai-metric-261105.md`). |

## §10 Investigation case management

| Item | Status | Evidence / note |
|---|---|---|
| Case creation, case status | Done | `modules/investigations`; status reasons + append-only `investigation_status_events` (`test_case_status.py`) |
| Evidence upload, hashing, chain of custody | Done | `evidence_hashes`, `evidence_custody_events`, `GET …/custody`; `test_evidence.py` |
| Analysis jobs, findings | Done | `analysis_jobs`, `analysis_findings` |
| IOC collections | Done | `modules/ioc_collections` (CSV formula-safe / JSON / STIX 2.1), `test_case_ioc_collections.py`, `test_stix_export.py` |
| Analyst notes | Done | versioned `analyst_notes` + `analyst_note_versions` (`test_case_notes.py`) |
| Timeline | Done | merged case timeline `investigations/timeline.py` + export `case_timeline/` (`test_timeline_export.py`) |
| ATT&CK mapping | Done | `modules/case_attack` (confirmed/suspected/rejected, suggestions, matrix) |
| Report generation | Done | `modules/reports` + report-worker (PDF/A-3a, HTML, MD; signed snapshot) |
| Preserve original evidence + analysis history | Done | object lock GOVERNANCE + `evidence_immutable` trigger; append-only versions (`test_append_only.py`, `test_report_finalize.py`) |
| Immutable metadata + auditable access logs | Partial | Downloads and report downloads are audited. **Metadata/custody views are not logged** (THREAT_MODEL known gap). Custody records download *requests*, not completed downloads. Viewers can download any report (ROADMAP M6 deferral, audited). |

## §11 Database

| Required table | Status | Implemented as |
|---|---|---|
| users, organizations, organization_members, investigations, evidence, evidence_hashes, analysis_jobs, network_flows, network_alerts, malware_samples, iocs, analyst_notes, reports, audit_logs | Done | same names (`__tablename__` grep) |
| malware_findings | Done (mapped) | `analysis_findings` of static jobs. Documented in DATABASE.md:140. |
| analysis_results | Done (unmapped) | per-type result tables + `analysis_jobs.summary`. **The mapping is not documented.** |
| threat_intelligence | Done (unmapped) | `ti_results` (+ `ti_enrichment_runs`, `ti_run_items`, `ti_provider_configs`) |
| attack_techniques | Partial (unmapped) | a committed JSON index (`modules/attack/data/attack_enterprise_v20.0.json`), not a table; `case_attack_mappings` holds case links. Workable, but not a DB table and not documented as a substitute. |
| investigation_timeline | Done (unmapped) | computed: `analysis_timeline` + status/custody/note events merged in `investigations/timeline.py` |
| api_keys | Partial (unmapped) | Provider keys are sealed in `ti_provider_configs` / `ai_provider_configs`. **There are no platform API keys** (programmatic or service-account access for users or integrations). |
| forensic_artifacts, memory_findings | Deferred (implicit) | They belong to the forensics/memory modules ("Later"). ROADMAP does not list the tables themselves. |
| UUIDs, indexes, migrations, FKs, timestamps | Done | DATABASE.md:155; composite same-org FKs (`0013_m6_same_org_fks.py`); `test_migrations.py` |
| Strict tenant isolation | Done | RLS + `NOBYPASSRLS` app role; `test_rls.py`, `test_rls_coverage.py`, `test_tenant_session_guard.py`, IDOR suite |

## §12 Frontend

| Item | Status | Evidence / note |
|---|---|---|
| Professional dark dashboard | Done | `app/layout.tsx` forces `dark`; `components/shell` |
| Overview | Done | `o/[orgId]/page.tsx` (open/in-progress counts, recent audit activity, modules) |
| Investigations, PCAP Analyzer, Malware Lab, Threat Intelligence, AI Analyst, Reports, Integrations, Settings | Done | pages under `app/(app)/o/[orgId]/…` (investigations, pcap, malware, intel, ai-analyst, reports, settings/integrations, settings + members + audit) |
| Forensics, Memory Analysis, Reverse Engineering | Deferred | `[module]/page.tsx`: placeholder "Planned for a later milestone", no fake data |
| Clear severity indicators | Done | `components/severity-badge.tsx` |
| Large tables, filters, technical details, evidence navigation | Done | server-side paging (`components/pager.tsx`), per-tab filters, citation chips and deep links |
| Search | Partial | Only per-table text filters and an IOC lookup page. There is no global or cross-case search, which is the job OpenSearch was meant to do. |

## §13 Security

| Item | Status | Evidence / note |
|---|---|---|
| Authentication | Done | argon2, JWT access + rotating refresh with reuse detection (`test_auth.py`). MFA/SSO/invitations: ROADMAP "Later". |
| RBAC | Done | `core/rbac.py`; `test_rbac.py::test_role_permission_matrix` |
| Tenant isolation | Done | see §11 |
| Secure file uploads | Done | octet-stream only, early 413, upload slots, no leftovers (`test_evidence.py`, `test_malicious_filenames.py`) |
| File type verification | Partial (deliberate) | Detection by magic: pcap/PE/ELF magic routes analysis (`auto_choice`). libmagic is recorded as metadata and "never used to reject" (`uploads.py:51`). There is no declared-type vs actual-type mismatch check or warning. |
| File size limits | Done | 2 GiB evidence, 512 MiB pcap, 64 MiB static, 1 MiB body elsewhere (Caddy; gate probe in `verify.mjs:59`) |
| Malware scanning of uploads | Partial (documented) | ClamAV + YARA on every non-empty upload ≤ 64 MiB (`test_analysis_static.py::test_auto_run_matrix`). Uploads > 64 MiB and pcaps get no AV scan (THREAT_MODEL:118). |
| Rate limiting | Partial | Targeted limits: login, failures, register, org create, member add, analysis auto-runs, AI per-user, TI per-provider. There is no global per-user API limiter. |
| API key encryption | Done | sealed boxes per domain (TI, AI); report signing keys separate. KMS/HSM deferred. |
| Audit logging | Done | `audit_logs` append-only (`test_append_only.py`) |
| Evidence integrity | Done | hashes, re-verify, exact-version pins, object lock |
| Secure object storage | Partial | object lock, scoped MinIO user, presigned exact versions. No server-side encryption at rest is configured, and the MinIO image is frozen and unpatched (THREAT_MODEL). |
| Data retention | Deferred | Only the GOVERNANCE lock (`EVIDENCE_LOCK_DAYS`). No purge or expiry anywhere (`ti_results`, `ai_*`, reports, notes). TESTING.md "⏳ later"; ROADMAP "Later". |
| Backup and restore | **Deferred / missing** | THREAT_MODEL:66 "No backups / restore procedure — later milestone". DEPLOYMENT.md:94 gives backup advice for reports only. There is no script or tested restore. |
| Test: IDOR | Done | `tests/security/test_idor_routes.py`. It enumerates every org-scoped route; all `PENDING_ROUTES` are empty and no `not_implemented()` stub remains. |
| Test: cross-tenant | Done | `test_rls.py`, `test_m6_schema.py::test_children_cannot_point_at_another_orgs_rows`, `test_ti_schema.py` |
| Test: unauthorized evidence download | Done | IDOR cases for `/evidence/{id}/download` (401/404); viewer RBAC in `test_evidence.py` |
| Test: malicious file upload | Done | `test_malicious_filenames.py`, EICAR scenario, hostile result streams |
| Test: archive bombs | Done | `static/tests/evaluation/test_detection_quality.py::test_zip_bombs_are_flagged`, `test_archive.py`, gzip-bomb ingest tests (`test_pcap_results.py:354`, `test_static_results.py:415`, `test_ti_http.py:402`) |
| Test: parser vulnerabilities | Done (posture) | fuzz-lite in both workers, sandbox and container isolation suites. Upstream fuzzing is not replicated. |
| Test: prompt injection | Done (detected, not prevented) | P1–P8 twins, HostileProvider (`ai_eval/test_ai_eval_invariants.py`) |
| Test: sandbox escape assumptions | Partial | Worker sandbox escapes are tested (`py-worker-kit test_sandbox.py`, `report/tests/test_isolation.py`, `tests/container/test_egress.py`). Dynamic-analysis VM escape is ⏳ with §7. |

## §14 Testing and metrics

| Item | Status | Evidence / note |
|---|---|---|
| Anonymized, controlled dataset; no real malware | Done | `apps/workers/pcap/dataset/` (RFC 5737/1918, example.*), `apps/workers/static/samples/` (generated, EICAR assembled at runtime) |
| PCAP: normal web, DNS, TLS, beacon, DNS anomalies, port scans | Done | dataset README scenarios + `mixed`, `suspicious_http` |
| Malware: benign PE, packed PE, suspicious imports, known signatures, EICAR | Done | `samples/generate.py` (benign_pe32/64, packed_like, injector, eicar) |
| Parsing success rate | Done (synthetic) | M2 8/8, M3 1.0 (TESTING.md:97, :112) |
| Analysis latency | Done (synthetic) | M2 1.2–1.4 s/scenario; M3 slowest 42.7 s; M4 virtual p95; M6 PDF p50/p95 3.9 s |
| Detection precision/recall | Done (synthetic only) | 1.0/1.0 on a dataset built to the detectors' own spec. There is no real-world or third-party labeled capture set. |
| IOC enrichment success | Done (synthetic faults) | 0.978 over 600 lookups (`plans/reports/ti-metric-261105.md`). TESTING.md:85 still marks it "⏳ placeholder" (stale). No live provider run. |
| AI evidence citation accuracy | Partial | Fake 1.000; Hostile 0 floor violations but ASR 0.290 (canary leaks detected). **No live model measured.** |
| Worker failure rate | Partial | Only the fuzz-lite outcome distribution (TESTING.md:105). There is no runtime metric: no counter of failed/timed-out jobs per analyzer, no Prometheus or OTel (grep: none). |

## §15 Documentation (all files under `docs/`)

| File | Status | Note |
|---|---|---|
| PRD.md (5.2 KB) | Partial | Titled "Milestone 1". The non-goals table is stale (ClamAV, CSP, Celery listed as deferred although they are done). M5/M6 are appended as stories. |
| ARCHITECTURE.md (23 KB) | Done | |
| THREAT_MODEL.md (64 KB) | Done | |
| DATABASE.md (33 KB) | Done | missing the §11 name mapping above |
| API.md (30 KB) | Done | |
| PCAP_ANALYSIS.md (9 KB) | Done | |
| MALWARE_ANALYSIS.md (8 KB) | Done | |
| **SANDBOX_SECURITY.md** | **Missing** | Not present and never referenced. Requirement §15 lists it explicitly. |
| AI_ANALYST.md (54 KB) | Done | |
| DEPLOYMENT.md (30 KB) | Done | no backup/restore runbook |
| TESTING.md (42 KB) | Done (with stale rows) | see the overclaims section |
| ROADMAP.md (7 KB) | Done | |
| (extra) THREAT_INTEL.md, REPORTS.md | Done | |

## §16 Development workflow

| Item | Status | Evidence |
|---|---|---|
| Inspect, spec, architecture, contracts, milestones, security risks | Done | `plans/2611*/plan.md` + phase files per milestone, researcher reports, RT-numbered red-team items in the plans |
| One module at a time | Done | M1→M6 sequence, one branch per milestone |
| Unit + integration tests, type safety, security review, docs after each milestone | Done | `pnpm verify` (`scripts/verify.mjs`): lint, mypy/tsc, API + worker + web tests, contracts drift, headers, key-leak crawls, Playwright on dev and prod |
| No production-ready claims without tests | Mostly done | THREAT_MODEL and PRD avoid "production-ready". See the overclaims section. |
| No mock results as real findings | Done | `ti-mock` / `ai-mock` refused in prod (`config.py`, `verify.mjs` env checks); FakeProvider labelled "pipeline only" |
| Plan bookkeeping | Partial | `status: pending` in M5 `plan.md` and in every M6 phase file, while ROADMAP marks both ✅ |

## §17 First milestone

All Done: monorepo (pnpm workspace), Compose, PostgreSQL, Redis, MinIO, FastAPI, Next.js, auth, org management, case management, evidence upload with SHA-256 verify. Then PCAP (M2), then malware static (M3) after PCAP integration tests, in the required order. Each milestone has a prod-like gate (`verify.mjs --prod`).

---

## Conflicts with decisions taken

| Requirement | Decision | Documented? |
|---|---|---|
| §3 OpenSearch for searchable results | Deferred; Postgres only | Yes: ROADMAP M2 and PRD. Not in ARCHITECTURE, and nobody owns the "search" gap it leaves (§12). |
| §3/§6 Detect It Easy | Deferred | Yes: ROADMAP M3, MALWARE_ANALYSIS |
| §6 Mach-O | Deferred | Yes, and it is not actually required |
| §7 dynamic analysis | Gated | Enabling it: yes (ROADMAP). The design §7 asks for and `SANDBOX_SECURITY.md`: **no**. |
| §3 Autopsy | Absent | **No** |
| §4 `correlation` module | Absorbed into AI / IOC features | **No** |
| §11 analysis_results / threat_intelligence / attack_techniques / investigation_timeline / api_keys | Renamed or replaced | **Only `malware_findings` is mapped** |
| §9 "generate reports" by AI | AI never drafts report sections | Yes (REPORTS.md:127) |
| §13 malware scan of uploads | Only ≤ 64 MiB | Yes (THREAT_MODEL:54/118) |
| §13 backup/restore, retention | Later | Yes (THREAT_MODEL:66, TESTING.md, ROADMAP) |

---

## (1) Prioritized gaps for M7

| # | Gap | Why it matters | Effort |
|---|---|---|---|
| 1 | **Backup and restore**: `pg_dump` plus a MinIO all-versions mirror of evidence/reports/results, a restore runbook, and a test that restores and re-verifies hashes, report signatures and RLS | §13 hard requirement; data-loss risk; "commercially viable" | 16–24 h |
| 2 | **Data retention and purge**: per-org policy for `ti_results`, `ai_*`, results, notes and reports; lock-aware evidence expiry; audited purge job | §13; it is deferred in five places | 24–32 h |
| 3 | **SANDBOX_SECURITY.md plus a §7 design**: VM provider, snapshot rollback, egress (sinkhole/INetSim), no shared FS/clipboard, a `dynamic.v1` contract, gating tests (no VM work) | §15 hard requirement; it blocks any honest "Later" for dynamic analysis | 8–12 h (doc + contract) |
| 4 | **Search**: start with Postgres FTS/trigram across flows, records, IOCs, findings and strings per org, with a global search page; record a decision on whether OpenSearch is ever needed | §3 and §12; an analyst cannot pivot across cases | 24–40 h |
| 5 | **Deterministic correlation**: shared IOC / hash / JA3 / domain across jobs and cases, with an "also seen in" panel; reuse the `(org, ioc_key)` indexes | §4 `correlation` module; it is currently only AI-mediated | 16–24 h |
| 6 | **Operational metrics**: per-analyzer job outcome counters, failure rate and latency histograms (Prometheus/OTel endpoint or a DB-backed admin view) | §14 "worker failure rate" is otherwise synthetic only | 8–16 h |
| 7 | **Live verification**: one recorded live Anthropic/Gemini eval run (cassettes) and one live TI smoke run | §14 AI citation accuracy and enrichment are unmeasured on real providers | 4–8 h plus keys and budget |
| 8 | **Security hardening backlog**: replace the frozen MinIO image, SSE at rest, custody logging of metadata views, a global per-user API rate limit, a declared-type mismatch flag | §13 Partials | 16–24 h |
| 9 | First forensics module: memory (Volatility 3) on the existing worker kit and contract pattern, with a `memory_findings` table | §2 lists it after the MVP; the biggest remaining product gap | 60–80 h (its own milestone) |

## (2) Quick wins (< 2 h each)

1. Add the full §11 name → table mapping to DATABASE.md (analysis_results, threat_intelligence, attack_techniques, investigation_timeline, api_keys, forensic_artifacts, memory_findings).
2. Stub `docs/SANDBOX_SECURITY.md` with the gating criteria, the threat list from §7 and "not enabled". The full design remains M7 #3.
3. TESTING.md: change row 85 "IOC enrichment success metric ⏳ placeholder" to ✅ 0.978, delete the stale row 72 "Parser vulnerabilities ⏳ (no parsers yet)", and next to "HostileProvider 0 violations" add the ASR 0.290 figure.
4. Rewrite the PRD.md non-goals table and title so they describe the current scope rather than "Milestone 1" (ClamAV, CSP and Celery are no longer deferred).
5. Add the missing deferrals to ROADMAP "Later": Autopsy, platform API keys, a `correlation` module, TCP stream reassembly / file carving, global search.
6. ARCHITECTURE.md: one paragraph on OpenSearch being deferred, and on where correlation lives today.
7. Plan bookkeeping: set M5 `plan.md` and the M6 phases to `completed` once the gate passes, and write `plans/reports/report-metric-YYMMDD.md`, which TESTING.md:263 promises.
8. Delete the empty stray directory `scripts;C/` at the repo root (a Windows path accident).
9. PCAP_ANALYSIS.md: say plainly that TShark covers the protocol hierarchy only, and that flows are conn-level with no stream reassembly.

## (3) Docs that overclaim vs code

- **ROADMAP/README mark M6 ✅ "done"**, while every M6 phase file says `status: pending`, the phase-9 metric report does not exist yet, and the branch is unmerged. The M5 `plan.md` also still says `pending`.
- **"PDF/A-3a"** (ROADMAP, README): conformance is a local veraPDF check only and does not gate (TESTING.md M6 table). It is claimed without a gating test.
- **README AI Analyst** ("Claude or Gemini explain …") reads as verified behaviour. No live model run was ever recorded, and model ids and prices are unverified (ROADMAP M5 deferrals say this; README does not).
- **TESTING.md "HostileProvider 0 violations"**: true for the floors only. The same run has ASR 0.290 (84 canary leaks, 28 external URLs, 20 forbidden verdicts), which were detected but not prevented.
- **"Detection precision/recall 1.0"** (M2/M3): measured on synthetic data generated to match the detectors. TESTING.md does caveat this, but README/ROADMAP readers may not see the caveat.
- **"TShark parsing"** (README: "analyzed by Zeek, TShark and Suricata"): TShark contributes only `io,phs` protocol stats.
- **Understated, not overclaimed**: TESTING.md:85 still lists the IOC enrichment metric as a placeholder although it was recorded (0.978).
