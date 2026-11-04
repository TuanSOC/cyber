# Threat Model (Milestone 1)

Scope: the M1 stack (gateway, web, API, Postgres, Redis, MinIO) handling untrusted evidence for multiple organizations. This document is the honest record of what M1 protects against and what it does not.

## Assets

- Evidence bytes and their integrity (hashes, custody chain).
- Tenant data separation (cases, evidence, members, audit).
- Sessions and credentials.
- The audit trail itself.

## Trust boundaries

1. Browser ↔ gateway (untrusted clients, untrusted uploads).
2. Gateway ↔ API (trusted network segment; the API trusts `X-Forwarded-For` only because nothing else can reach it).
3. API ↔ data stores (API uses an RLS-bound Postgres role and a scoped MinIO user; owner/root credentials never reach it).
4. Operators (DB owner, MinIO root) — trusted administrators.
5. (M2) pcap-worker ↔ everything: the parser processes attacker-controlled captures and is treated as compromisable. It holds only a broker URL (ACL user confined to its own queue keys), runs tools as an unprivileged uid with seccomp (no inet sockets), and sits on an internal network without egress. Its output is untrusted data, validated by the trusted ingest worker before anything reaches the database.

## STRIDE summary

| Threat | Component | Mitigation in M1 | Tested by |
|---|---|---|---|
| **Spoofing** session | API | argon2id passwords; 15-min JWT bound to refresh family; opaque refresh tokens stored hashed, atomic rotation, reuse detection revokes the family and its access tokens; 30-day absolute session lifetime | `test_auth.py`, `test_security.py` |
| Spoofing client IP | gateway/API | Caddy overwrites `X-Forwarded-For`; API network isolated | manual gateway check |
| **Tampering** with evidence | MinIO | content addressed by version id; GOVERNANCE retention; scoped MinIO user without bypass; re-verification against stored hashes | `test_storage_minio.py`, `test_evidence.py` |
| Tampering with audit/custody/hashes | Postgres | grants (no UPDATE/DELETE) + triggers; evidence identity columns immutable | `test_append_only.py` |
| Cross-tenant access (IDOR) | API/Postgres | `require()` checks membership; every query filters by org; RLS forced on every tenant table; per-command membership policies | `test_idor_routes.py` (every org route), `test_rls*.py` |
| CSRF | API | SameSite=Strict + double-submit token | `test_auth.py` |
| **Repudiation** | API | audit row in the same transaction as every mutation; custody events for upload, download, verify and archive (metadata/custody *views* are not logged); auth events (incl. failures) | `test_audit.py`, `test_evidence.py` |
| **Information disclosure** | API | 404 for non-members; no storage keys exposed; error envelope without input echo; secrets redacted from audit details | IDOR + error tests |
| Malicious file content | API | never parsed or executed (only 8 KiB libmagic sniff); stored opaque; served as attachment with `nosniff` + `CSP: sandbox` | `test_malicious_filenames.py`, EICAR test |
| Hostile filenames | API/web | sanitized (basename, control/bidi chars removed, length capped); RFC 5987 headers; rendered as text | `test_malicious_filenames.py`, `test_filenames.py` |
| Open redirect | web | same-origin URL check on `next` | `safe-next.test.ts` |
| **Denial of service** | gateway/API | 1 MiB body cap except uploads (2 GiB); early 413; read timeouts; rate limits (login per IP, failures per email+IP, register, org create, member add); per-user upload/verify slots; DB pool never held during transfers | `test_auth_rate_limit.py`, `test_upload_slots.py` |
| **Elevation of privilege** | API | permission matrix; only owners grant/remove owner; org-row lock + role re-read for membership changes; no self-modification | `test_rbac.py`, `test_members_hardening.py` |

## Known gaps (accepted for M1)

| Gap | Risk | Planned |
|---|---|---|
| No email verification, no MFA | account takeover via password reuse; fake sign-ups | later milestone |
| Members are added without consent (by email) | spam into orgs; mitigated by showing org name/role prominently and opening the user's own org by default | invitation flow later |
| Add-member responses reveal whether an email is registered | enumeration; rate limited (30/10 min per user) | invitation flow later |
| Register 409 reveals existing emails | enumeration; rate limited per IP | later |
| No per-org storage quota; uploads get a 30-day governance lock | open registration could fill MinIO with undeletable data | quotas re-deferred to M3 |
| No malware scanning of uploads | stored malware is inert (never executed/parsed) but undetected | ClamAV in M3 |
| `'unsafe-inline'` scripts in CSP | weaker XSS defence; React escaping + HttpOnly cookies limit impact (M2 renders many packet-derived strings, always as text) | nonce CSP re-deferred to M3 |
| libmagic runs in the API on 8 KiB of untrusted input | parser bug in libmagic | re-deferred: M2 detects captures by magic number in pure Python; libmagic stays for the `detected_mime` metadata only |
| MinIO image is frozen `bitnamilegacy/minio` (upstream stopped community images) | no security patches | dev/learning only; replace before any real deployment |
| DB owner and MinIO root are trusted | an admin can TRUNCATE/DROP TRIGGER or bypass governance | operational controls; credentials never in the API |
| RLS trusts `app.org_id` | any code that sets it from request input without `require()/org_session()` bypasses membership | AST guard test restricts where it can be set |
| Custody records download *requests*, not completed transfers; no Range/resume | aborted downloads still logged as `downloaded` | later |
| A just-rotated refresh token presented within 10 s gets `stale_refresh` (no tokens issued) instead of revoking the family | if an attacker with a stolen refresh token rotates first, the victim's refresh in that window does not trigger reuse detection; the attacker keeps the session until the victim's next refresh after the window, which then revokes it | accepted trade-off for multi-tab use |
| Metadata and custody views are not logged in the custody chain | read access to evidence details is not attributable (downloads are) | later, if required |
| Email addresses on special-use domains (`.local`) rejected | internal-domain users cannot register | revisit with SSO |
| uvicorn runs with `--forwarded-allow-ips='*'` | if anything other than the gateway could reach the API, it could spoof client IPs and dodge per-IP rate limits | relies on the `backend` network isolation; pin to the gateway address for real deployments |
| The `api-test` container (test profile only) holds MinIO root credentials to purge locked test objects | a compromised test run could bypass governance on the dev MinIO | test profile only, never in `api`/prod |
| No backups / restore procedure | data loss | later milestone |

## M2: analysis pipeline

| Threat | Mitigation | Tested by |
|---|---|---|
| Parser exploit reads secrets | Tools run as uid 10003 without capabilities, cannot read the worker's environ/memory; broker credentials only in the root Celery process | `apps/workers/pcap/tests/unit/test_sandbox.py` |
| Parser exploit pivots on the network | `analysis` network is internal; seccomp denies AF_INET/AF_INET6/AF_PACKET sockets to tools; app services unresolvable | `test_isolation.py`, `test_sandbox.py` |
| Parser exploit persists into another tenant's job | kill-by-uid after every engine and job (non-dumpable / setsid escapees included), `/work` wiped before every job, container stops itself if a process survives | `test_sandbox.py` |
| Tool output tricks the root process (symlinks, FIFOs, planted names, giant lines, hostile JSON) | `dir_fd` + `O_NOFOLLOW`, regular files only, `O_EXCL` creation, bounded line/file reads, per-record error isolation | `test_sandbox.py`, `test_parsers.py`, fuzz-lite |
| Forged or replayed reports for other jobs | per-job token (sha256 stored), org taken from the job index, guarded transitions, final states immutable in the DB | `apps/api/tests/integration/test_analysis.py` |
| Hostile result stream (bombs, wrong job, extra fields, NaN, NUL, oversize) | full validation (header/trailer/sha256/caps/contract) before one all-or-nothing transaction | `test_pcap_results.py`, `test_result_stream.py` |
| Evidence swapped before analysis | worker verifies sha256 and size of the exact version; presigned GET pins the version | `test_analysis_pipeline.py` |
| One tenant starves the analyzer | per-org (5) and global (50) active caps, auto-run rate limit, queue TTL | `test_analysis.py` |

Residual risks (accepted for M2):

| Gap | Risk | Planned |
|---|---|---|
| A compromised Celery root process (not just a tool) holds the broker credentials | it could push extra or forged reports onto the ingest queue (still rejected without the target job's token) or delete queued ingest messages | per-job signed reports / separate publisher later |
| MinIO is reachable from the analysis network (presigned URLs need it) | the frozen MinIO image is exposed to a compromised worker process (tools cannot open sockets) | replace MinIO image before any real deployment |
| Tools share the container network namespace | seccomp blocks inet sockets but not unix sockets | a no-network sidecar if it becomes necessary |
| Parsers are the upstream Zeek 8 / Debian 13 builds | vulnerabilities in them are contained, not prevented | rebuild the image to update; track versions in every result |
| ET Open rules are fetched at build time, unpinned | rule drift between builds | digest recorded in every result; pinning later |
| Single analyzer FIFO with concurrency 1 | fair scheduling between orgs is approximate | per-org queues later |
| Heuristic thresholds are static, no allow-lists | false positives (e.g. legitimate updaters beaconing) | analyst feedback / allow-lists later |
