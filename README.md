# CyberLab AI

Defensive cybersecurity investigation platform (DFIR, PCAP, malware static analysis, memory forensics, threat intel, AI analyst).
**Status:** M1–M5 are complete; M6 (reports and case management) is merged, with its gate-run metric report still to write; **M7 (platform operations and correlation) is implemented and pending its gate** (`pnpm verify:prod` with the restore drill); **M8 (memory forensics) is in progress** (phase 1 foundation only, untested). This is a learning-grade, single-node platform, not production-ready (see the known gaps in `docs/THREAT_MODEL.md`).
- **PCAP Analyzer (M2):** captures uploaded as evidence are analyzed automatically in an isolated worker: Zeek produces the flows (connection-level, no TCP stream reassembly or file carving), DNS / HTTP / TLS records and file hashes, Suricata the signature alerts and JA3, and TShark only the capture's protocol hierarchy. Findings, alerts, flows, records, IOCs and timeline. Detector precision / recall is 1.0 on a **synthetic** dataset built with the detectors, not a real-world measure. See [docs/PCAP_ANALYSIS.md](docs/PCAP_ANALYSIS.md).
- **Malware Lab (M3):** PE/ELF uploads are analyzed statically (never executed) by ClamAV, YARA, pefile / pyelftools, capa and FLOSS in a second isolated worker; every other upload up to 64 MiB gets a ClamAV + YARA scan. Sample facts, sections, imports/exports, strings, signatures, capabilities, verdict-free findings, IOCs and a JSON / printable report. Precision / recall figures come from a synthetic sample set. See [docs/MALWARE_ANALYSIS.md](docs/MALWARE_ANALYSIS.md).
- **Platform (M3):** nonce-based CSP, per-org storage quotas.
- **Threat Intel (M4):** IOC lookups at VirusTotal, AbuseIPDB, URLhaus, MalwareBazaar, AlienVault OTX and your own MISP, per org with your own keys (sealed, write-only), through an enrich-worker that is the only service with internet egress. Source-attributed, verdict-free results with a per-org cache and history, rate limits, and ATT&CK technique names from an offline index. VirusTotal's public API and abuse.ch's free tier are non-commercial: a commercial deployment needs paid tiers. See [docs/THREAT_INTEL.md](docs/THREAT_INTEL.md).
- **AI Analyst (M5):** an LLM provider (Anthropic Claude or Google Gemini adapters, bring your own key) is asked to explain a finding or alert, summarize a capture, explain static findings, correlate IOCs, map possible ATT&CK techniques and summarize an incident, always separating observed evidence, interpretation, hypotheses, confidence and next steps. Every claim cites the records it rests on and a deterministic verifier checks each citation; unsupported claims are hidden, nothing is a verdict, the model has no tools and nothing is acted on automatically. **Off by default:** an org admin opts in with a privacy acknowledgement, because evidence excerpts leave the platform for the chosen provider (internal IPs, hostnames and usernames are pseudonymized by default; you can preview exactly what is sent). Provider keys are BYOK (sealed, write-only); Gemini only with paid-tier keys. **No live model run has been recorded:** the adapters are tested against fixtures and a mock, and the quality numbers come from offline Fake / Hostile providers (prompt injection is detected, not prevented), so model ids, prices and real answer quality are unverified. See [docs/AI_ANALYST.md](docs/AI_ANALYST.md).
- **Reports and case management (M6):** versioned analyst notes, IOC collections (CSV / JSON / STIX 2.1 exports, formula-safe and TLP-marked), status reasons and history, analyst-confirmed ATT&CK mapping, and a timeline export. Every case has a **TLP 2.0** label and "do not send to AI / TI" flags (also per evidence; TLP:RED implies both) that the AI analyst and threat intel refuse. A report draft is **finalized** into an immutable, **Ed25519-signed** version whose every claim cites `[Cn]` rows of the case; an isolated, sandboxed WeasyPrint worker (no network, no database, no secrets) renders it to PDF/A-3a (structurally checked; veraPDF runs locally only and does not gate) with the signed snapshot embedded, HTML and Markdown. Recipients verify a PDF offline with `scripts/verify_report.py` and the public keys at `/api/v1/report-signing-keys`. An `external` profile pseudonymizes internal hosts, IPs and users (pattern-based: review the preview). DOCX and PAdES are not supported. See [docs/REPORTS.md](docs/REPORTS.md).
- **Platform operations (M7):** `pnpm backup` / `pnpm restore` (offline, quiesced: Postgres plus the MinIO volume with its version ids, object lock and legal holds; a verified restore and a restore drill). Per-org **retention** of TI history, AI runs and the bulk data of closed cases (nothing is purged without a policy; dry run by default; every loosening waits 7 days) with **legal holds**, executed by a least-privilege retention worker that leaves tombstones, custody and audit. Deterministic **correlation** inside an org ("also seen in", related cases) and **org-wide search** on Postgres (the query is never logged; OpenSearch deferred with criteria). Runtime job **metrics** (Prometheus text for operators, an org page). Hardening: a global per-user rate limit, audited evidence views, a declared-vs-detected type flag, SSE-S3 at rest. Dynamic analysis is designed but **not enabled** ([docs/SANDBOX_SECURITY.md](docs/SANDBOX_SECURITY.md)).
- **Memory Analysis (M8, in progress):** memory images uploaded with the memory option will be analyzed on request (never automatically) by Volatility 3 (pinned 2.28.2) in a third isolated, offline worker: processes, connections, private executable regions, modules, services, registry hives and bash history, with verdict-free triage findings and IOCs. Symbols come only from a local store that an operator fills with `pnpm memory:symbols` (Windows kernel PDBs fetched over verified HTTPS on request, Linux ISFs built elsewhere). Memory images are **TLP:RED by default** (no AI or TI until an admin releases them). Limits: Windows is replay-tested, not validated on a real image in CI; no macOS, ARM64, hiberfil or compressed uploads; no file extraction. **Today only the foundation exists**: every memory job fails `not_implemented` and the memory routes answer 501. See [docs/MEMORY_ANALYSIS.md](docs/MEMORY_ANALYSIS.md).

Plans are in `plans/`.

## Prerequisites

- Docker Desktop (Compose v2.24+)
- Node 22 + pnpm 10 (only for workspace scripts and lockfile; everything runs in containers)
- No host Python needed — the API toolchain (Python 3.12 + uv) lives in the image.

## Quick start

```bash
cp .env.example .env      # then replace every change-me value
pnpm dev                  # docker compose up --build --renew-anon-volumes
```

| URL | What |
|---|---|
| http://localhost:8080 | Web app (through the Caddy gateway) |
| http://localhost:8080/api/v1/health | API health (db / redis / minio) |
| http://localhost:8080/api/docs | Swagger UI (dev only) |

**Reports in five steps:** open a case → set its TLP (Overview) → add notes, IOC collections and ATT&CK mappings → Reports tab → *New report*, fill the sections, pick the evidence, findings, IOCs and verified AI runs, check the preview (size and render budget) → *Finalize* (change note, acknowledgements). The PDF renders in the background; download it from the version viewer and verify it offline:

```bash
curl -s http://localhost:8080/api/v1/report-signing-keys > keys.json
docker run --rm -v "$PWD:/repo" -w /repo cyberlab/api:dev \
  python scripts/verify_report.py --pdf CASE-00001_v1_TLP-AMBER.pdf --keys keys.json
```

## Scripts

| Command | Does |
|---|---|
| `pnpm dev` / `pnpm down` | Start / stop the dev stack (hot reload) |
| `pnpm test:api` | API tests in the `api-test` container (test DB, test bucket, Redis db 1), incl. the threat-intel pipeline through the `ti-mock` sink and the AI analyst suites and offline evaluation |
| `pnpm lint:api` | ruff + format check + mypy --strict |
| `pnpm lint:web` | Next typegen + tsc + eslint |
| `pnpm test:web` | Web unit tests (vitest) |
| `pnpm test:workers` | PCAP worker, static worker, report worker, memory worker (M8) and worker-kit tests, each inside the real worker image (sandbox, isolation, engines, detection quality, fuzz-lite) |
| `pnpm gen:contracts` | Regenerate `packages/contracts` from the API's OpenAPI schema |
| `pnpm e2e` | Playwright: M1 golden path, PCAP upload → findings, PE upload → Malware Lab + report, nonce CSP, threat intel, AI analyst (mock), reports |
| `pnpm verify` | Full gate: lint, types, all tests, build, contract drift, headers, e2e |
| `pnpm verify:prod` | `verify` + prod stack health / headers / HSTS |
| `pnpm prod:up` / `pnpm prod:down` | Prod-like stack (built images, TLS) at https://localhost:8443 |
| `pnpm backup` / `pnpm restore -- --from <dir> --replace-empty-stack` | Offline backup and restore (M7; the backup is TLP:RED, see `docs/DEPLOYMENT.md`) |
| `pnpm restore:drill` | End-to-end backup / restore proof in a throwaway compose project (heavy; run alone) |
| `pnpm memory:symbols -- <list\|fetch-windows\|import\|reindex\|verify>` | M8: the operator's memory symbol tool (profile `tools`, its own egress network; pending phase 5, exits 2 today); `--store test` for the test store |
| `pnpm ops:metrics` / `pnpm live:run` | Replay the synthetic datasets for runtime metrics; budgeted live TI / AI runs with your own keys (never in the gate) |

## Layout

```
apps/api            FastAPI (Python 3.12, uv) — modular monolith
apps/web            Next.js 16 App Router, Tailwind
packages/contracts  Generated API types (openapi-typescript)
apps/workers/pcap   PCAP analyzer worker (Zeek, Suricata, TShark for protocol stats; untrusted, sandboxed) + synthetic dataset
apps/workers/static Static malware analyzer worker (ClamAV, YARA, pefile, capa, FLOSS; untrusted, sandboxed) + synthetic samples
apps/workers/memory Memory analyzer worker (Volatility 3 2.28.2, offline; untrusted, sandboxed) + the trusted memory-symbols tool; VSL notice in NOTICE.md (M8, in progress)
apps/workers/report Report renderer (WeasyPrint → PDF/A-3a, HTML, Markdown; untrusted, sandboxed, deny-all fetcher)
packages/py-jobs    Versioned job/result contracts shared by the API and workers
packages/py-worker-kit  Sandbox, transfer and result writer shared by the analyzers and the renderer
infra/              Caddy, Postgres init, MinIO init, Redis broker ACL, dev seal keys (infra/ti, infra/ai), the dev report signing pair (infra/reports), ti-mock and ai-mock sinks
docs/               Product, architecture, API, database, threat model, deployment, testing, roadmap
plans/              Brainstorm reports + implementation plans
scripts/verify.mjs  The verify gate
scripts/gen_ti_seal_keys.py, gen_ai_seal_keys.py, build_attack_index.py  Prod seal keys; the pinned ATT&CK index
scripts/ai_eval.py, check_ai_models.py  AI evaluation tables (offline / live); catalog model check
scripts/gen_report_signing_keys.py, verify_report.py  Prod report signing keys; offline report verification
scripts/backup.mjs, restore.mjs, restore-drill.mjs  Backup, restore and the restore drill (M7)
```

## Docs

[PRD](docs/PRD.md) · [Architecture](docs/ARCHITECTURE.md) · [API](docs/API.md) · [Database](docs/DATABASE.md) · [PCAP analysis](docs/PCAP_ANALYSIS.md) · [Malware analysis](docs/MALWARE_ANALYSIS.md) · [Memory analysis](docs/MEMORY_ANALYSIS.md) · [Threat intel](docs/THREAT_INTEL.md) · [AI analyst](docs/AI_ANALYST.md) · [Reports](docs/REPORTS.md) · [Sandbox security](docs/SANDBOX_SECURITY.md) · [Threat model](docs/THREAT_MODEL.md) · [Deployment](docs/DEPLOYMENT.md) · [Testing](docs/TESTING.md) · [Roadmap](docs/ROADMAP.md)

## Third-party software and licenses

**Not legal advice.** The repository itself has **no licence file yet**; choosing one is the owner's decision.

- **Volatility 3** (M8): `volatility3==2.28.2` is installed unmodified into the memory worker image under the [Volatility Software License (VSL) v1.0](https://www.volatilityfoundation.org/license/vsl-v1.0); the image keeps its `LICENSE.txt` and our [NOTICE](apps/workers/memory/NOTICE.md). Under the VSL, software that executes Volatility and parses its results is an "Addition", and Additions made available to others, by copies or over the Internet, must be published under the VSL. Running CyberLab for your own use creates no such obligation. Every Volatility-specific line is therefore kept in `apps/workers/memory/`, Volatility is never patched, the rest of the platform is tool-agnostic, and the docs link to upstream instead of reproducing its source.
- **Open decision:** before CyberLab is offered to anyone else, including as a hosted service, decide whether to publish `apps/workers/memory/` under the VSL (recommended in the M8 plan, alongside whatever licence the rest of the repository gets). Also recorded in [ROADMAP](docs/ROADMAP.md) and [THREAT_MODEL](docs/THREAT_MODEL.md#m8-memory-forensics).
- Deliberately not installed in the memory worker: `leechcorepyc` (GPLv3), `pycryptodome`, `pysmb` and the YARA engines. Its other dependencies: `pefile` (MIT), `capstone` (BSD-3-Clause), `jsonschema` (MIT).
- Other third-party data and terms: the ATT&CK notice ([THREAT_INTEL.md](docs/THREAT_INTEL.md)), the provider terms of the TI and AI integrations (above), the ET Open rules and ClamAV DB baked into the analyzer images.

## Notes

- **Init scripts run only on empty volumes.** After changing `infra/postgres/init` or bucket setup: `docker compose down -v`.
- The API connects only as the RLS-bound `cyberlab_app` role. Owner DB credentials are given to `migrate` and the test profile only.
- Since M4 the `backend` network is `internal`: only the enrich-worker and (M5) the analyst-worker can reach the internet. `uv run` never syncs at runtime and the MinIO console is not published (see `docs/DEPLOYMENT.md`).
- Prod needs its own threat-intel and AI seal key pairs (`scripts/gen_ti_seal_keys.py`, `scripts/gen_ai_seal_keys.py`), its own report signing pair (`scripts/gen_report_signing_keys.py`), `BROKER_ANALYST_PASSWORD` and `BROKER_REPORT_PASSWORD` (M8: `BROKER_MEMORY_PASSWORD`), and since M7 the retention passwords, the purge MinIO secret, `.secrets/minio_kms_key` and `.secrets/metrics_token`; the committed dev keys are refused when `ENV=prod`. Back up `.env` and `.secrets/` separately and encrypted: they are not in `pnpm backup`, and without the KMS key MinIO cannot read its own users.
- MinIO upstream archived its community edition. Since M7 the object store is the maintained fork `pgsty/silo` (digest-pinned, built locally as `localhost/cyberlab/silo:<release>` on the first `docker compose up`), which fixes CVE-2025-62506 and SN-2026-015/016 of the former `bitnamilegacy/minio` default (`docs/DEPLOYMENT.md`, Object-store image).
- Windows: bind mounts don't forward file events, so dev uses polling (`NEXT_WATCH_POLL_MS`, `WATCHFILES_FORCE_POLLING`). For faster I/O, clone inside WSL2.
- Orphan check (report-only, DB rows vs. stored object versions, M7: purged and unexplained missing versions): `apps/api/app/scripts/reconcile_orphans.py` (runs as the Postgres superuser; usage in its docstring).
- Not production-ready: see the known gaps in `docs/THREAT_MODEL.md`.
