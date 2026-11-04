# Threat Model

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
6. (M3) static-worker ↔ everything: same boundary and same controls as the pcap-worker, with its own broker ACL user (`static`). It parses attacker-controlled files of any type (see [MALWARE_ANALYSIS.md](MALWARE_ANALYSIS.md)).

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
| Malicious file content | API | never parsed or executed by the API (only 8 KiB libmagic sniff); stored opaque; served as attachment with `nosniff` + `CSP: sandbox`; parsed only inside the isolated analysis workers (M2/M3), never executed | `test_malicious_filenames.py`, EICAR test |
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
| Storage exhaustion; uploads get a 30-day governance lock | open registration could fill MinIO with undeletable data | **mitigated in M3, not closed:** per-org quota (default 20 GiB, archived evidence counts) checked under an org row lock, and at most 5 owned orgs per user. Registration stays open, so many accounts can still claim many quotas |
| Malware scanning of uploads | stored malware is inert (never executed) | **M3:** every non-empty upload ≤ 64 MiB gets at least a ClamAV + YARA scan (`av` profile; PE/ELF get every engine). Files above 64 MiB are not scanned (for an oversized PE/ELF the skipped run is audited as `analysis.skipped`) |
| `'unsafe-inline'` scripts in CSP | weaker XSS defence | **closed in M3:** per-request nonce with `'strict-dynamic'` on every HTML page (no `'unsafe-inline'` for scripts); styles keep `'unsafe-inline'`; gateway fallback `default-src 'none'` for responses without a CSP |
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
| Parser exploit reads secrets | Tools run as uid 10003 without capabilities, cannot read the worker's environ/memory; broker credentials only in the root Celery process | `packages/py-worker-kit/tests/test_sandbox.py` (run in both worker images) |
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

## M3: static analysis and platform hardening

The static-worker reuses every M2 control above through the shared worker kit (`packages/py-worker-kit`); its tests run in both worker images. Details: [MALWARE_ANALYSIS.md](MALWARE_ANALYSIS.md).

| Threat | Mitigation | Tested by |
|---|---|---|
| A sample is executed | nothing runs the sample; engines only parse or emulate it (capa, FLOSS via vivisect) | engine tests over the synthetic set (mingw samples are compiled, never run) |
| Parser exploit in a Python probe hijacks the root process | pefile, pyelftools, yara-python and libmagic run as `python -I -s` subprocesses under uid 10003, from the root-owned read-only input dir; root only hashes the sample and accepts contract-valid records of the kinds that probe may emit | `test_engines.py`, `test_hostile_output.py` |
| Compromised emulator hides an earlier match | capa and FLOSS run last, each engine in a fresh out dir created after kill-by-uid | `test_engines.py::test_each_engine_gets_a_fresh_tool_owned_dir` |
| Memory exhaustion kills the worker | `RLIMIT_AS` per tool and `oom_score_adj=1000` on tool children; per-engine size caps (capa ≤ 16 MiB, FLOSS ≤ 8 MiB, ssdeep ≤ 4 MiB); container limit 3 GiB | `test_size_caps_skip_capa_and_floss`, fuzz-lite |
| Archive bomb or encrypted archive reported as "clean" (RT2) | explicit ClamAV file/scan/recursion/time limits with alerts, zip pre-check; any limit hit, encrypted content, capped output or missing pre-check gives `av_not_fully_scanned`, a missing DB `av_unavailable`, never a silent clean | `test_archives_are_never_silently_clean`, `test_missing_archive_precheck_fails_closed`, `test_huge_clamav_output_counts_as_not_fully_scanned` |
| Hostile YARA rule meta inflates severity | rule severity defaults to `low`; only allowlisted (rule file sha256 + rule name) rules may go higher, up to a ceiling | `test_unlisted_yara_rule_is_capped_at_low` |
| Imports or entropy alone presented as a verdict | heuristic and capability findings are capped at `medium`; only signature engines reach `high`; templates never say "malicious" | `apps/workers/static/tests/unit/test_detections.py` |
| Worker forges the sample identity | ingest rejects a `sample` line whose hashes or size differ from the evidence record (`invalid_result`); UI and report show the trusted hashes | `test_static_results.py::test_sample_of_another_file_is_refused` |
| Oversized sample | 64 MiB cap at request time (`413 sample_too_large`) | `test_analysis_static.py` |
| App role raises its own quota | 0008 column grants: the app cannot write `storage_quota_bytes` | `test_storage_quota.py` |
| Concurrent uploads overshoot the quota | authoritative check under the org row lock in the insert transaction | `test_storage_quota.py::test_concurrent_uploads_cannot_overshoot_the_quota` |
| Inline script injection (XSS) | nonce CSP with `'strict-dynamic'`; fresh nonce per request | `apps/web/e2e/csp.spec.ts` |

Residual risks (accepted for M3):

| Gap | Risk | Planned |
|---|---|---|
| ClamAV, libmagic, pefile, pyelftools, YARA, capa and FLOSS parse hostile input | a parser vulnerability is contained (uid, seccomp, rlimits, kill-by-uid, read-only rootfs, no egress), not prevented | rebuild the image to update; versions are recorded in every result |
| ClamAV DB and capa rules are as fresh as the image build | stale signatures miss newer samples | rebuild regularly; the AV DB date is shown in the UI |
| Files above 64 MiB get no AV scan | large uploads stay unscanned | revisit with a streaming scanner |
| Archives are not extracted for analysis | only ClamAV looks inside archives; PE/ELF inside a zip get no structural analysis | archive extraction later |
| Authenticode is reported as present, not validated | a forged or revoked signature looks the same as a valid one | chain validation later |
| Quota is per org, registration is open | one person with many accounts can still claim many quotas | email verification / invitations later |
| Styles keep `'unsafe-inline'` | CSS injection remains possible (no script execution) | revisit if the UI drops inline styles |
