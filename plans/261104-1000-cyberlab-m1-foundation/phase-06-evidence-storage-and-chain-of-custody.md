---
phase: 6
title: Evidence storage and chain of custody
status: completed
priority: P1
effort: 14h
dependencies:
  - 5
---

# Phase 6: Evidence storage and chain of custody

## Overview
Evidence upload (spooled + hashed through API, stored in object-locked MinIO by version), secure download, re-verification, archive, custody chain. No DB connection held while bytes move. [RT#5, RT#12]

## Requirements
- Functional:
  - `POST /orgs/{org_id}/investigations/{inv_id}/evidence?filename=&description=` body = raw bytes (`application/octet-stream`) → 201 evidence + hashes.
  - `GET /orgs/{org_id}/investigations/{inv_id}/evidence?limit=&offset=` → `{items, total}`. [RT#13]
  - `GET /orgs/{org_id}/evidence/{id}` detail (+ hashes).
  - `GET /orgs/{org_id}/evidence/{id}/download` stream.
  - `POST /orgs/{org_id}/evidence/{id}/verify` → `{result: "ok"|"mismatch"|"missing", expected, actual}`.
  - `POST /orgs/{org_id}/evidence/{id}/archive`.
  - `GET /orgs/{org_id}/evidence/{id}/custody` ordered events.
- Non-functional: memory O(chunk); API never interprets content (except 8 KiB magic sniff); no orphan object versions on failure; no DB connection held during transfer.

## Architecture

### Decision: spool-to-temp, then `fput_object` [RT#12]
No async→sync streaming bridge. Request body is streamed to a size-capped temp file on the `upload_tmp` volume while hashing; then `fput_object` (known length) runs in a worker thread. Cost: temp disk ≥ `MAX_EVIDENCE_BYTES × MAX_CONCURRENT_UPLOADS_PER_USER × active users` (documented in DEPLOYMENT).

### Upload flow
```
1. authorize(org, user, "evidence.write") + investigation exists & not archived   [short session, closed]
2. Redis INCR uploads:{user_id} (TTL 1h safety) > MAX_CONCURRENT_UPLOADS_PER_USER → 429   [RT#5]
3. Content-Length present and > MAX → 413 immediately
4. async for chunk in request.stream():                 # no DB connection held
       total += len(chunk); total > MAX → 413
       md5/sha1/sha256.update(chunk); write chunk to temp file (anyio.open_file)
       first 8 KiB kept for python-magic sniff (recorded, never used to reject)
   ClientDisconnect → cleanup, stop
5. version_id = await to_thread(fput_object, bucket, key=f"{org_id}/{uuid4()}", temp_path).version_id
6. tenant_session(org, user): evidence(storage_version_id=version_id) + 3 hashes + custody(uploaded) + audit → commit
   failure → delete_version(key, version_id) (no lock set yet) → 500
7. EVIDENCE_LOCK_DAYS > 0 → set_retention(key, version_id, GOVERNANCE, now + days); failure → log ERROR + audit evidence.lock_failed (evidence still valid)
finally: delete temp file; Redis DECR uploads:{user_id}
```
- Filename: original kept as metadata only; sanitized (strip path separators/control chars, max 255). Never in key; RFC 5987-encoded in headers.

### Storage interface (`core/storage.py`)
```python
class EvidenceStorage(Protocol):
    async def put_file(self, key: str, path: Path) -> str            # returns version_id
    def iter_version(self, key: str, version_id: str) -> AsyncIterator[bytes]
    async def delete_version(self, key: str, version_id: str) -> None
    async def set_retention(self, key: str, version_id: str, until: datetime) -> None
```
- Every read/delete is **by version_id** → a later PUT to the same key (new version) can never replace what is served or verified. [RT#6]
- API uses scoped `cyberlab-api` MinIO user (no governance bypass) → locked versions cannot be deleted by the API.

### Download
- Short session: authorize `evidence.read`, load evidence, insert custody `downloaded` + audit → **commit** → close.
- Return `StreamingResponse(iter_version(key, version_id))` — no DB held. Headers: `application/octet-stream`, `Content-Disposition: attachment; filename*=UTF-8''…`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `Content-Security-Policy: sandbox`.
- Custody records the download *request* (documented: aborted transfers still logged as `downloaded`).

### Verify
- Short session: authorize `evidence.write`, load evidence + stored hashes → close.
- Stream version, recompute 3 hashes (no DB held). Missing version → `missing`.
- New short session: custody `verified_ok` | `verified_mismatch` (details include `reason: hash|missing`) + audit → commit.

## Related Code Files
- Create: `apps/api/app/core/{storage.py,hashing.py,filenames.py,upload_slots.py}`
- Create: `apps/api/app/modules/evidence/{schemas,repository,service,router}.py`
- Create: `apps/api/tests/unit/{test_hashing.py,test_filenames.py}`
- Create: `apps/api/tests/integration/{test_storage_minio.py,test_evidence_upload.py,test_evidence_download_verify.py}`
- Test fixtures generated at runtime (random bytes; EICAR string assembled in code — nothing committed).

## Implementation Steps
1. Hashing spooler (chunk → hashes + temp file + size cap) + unit tests vs `hashlib` incl. chunk boundaries.
2. Filename sanitizer + RFC 5987 encoder tests (unicode, `../`, `\r\n`, empty, 300 chars).
3. Storage impl + `test_storage_minio.py` against real MinIO `evidence-test`: put returns version_id; get by version; delete_version; set_retention then api-user delete of that version **fails**; teardown removes locked test objects with root creds + `bypass_governance_mode=True`.
4. Upload slots (Redis counter) + evidence service (upload/list/detail/download/verify/archive/custody) following flows above.
5. Router (`evidence.read` / `evidence.write`).
6. Tests:
   - 5 MB upload → hashes == hashlib; evidence row has `storage_version_id`; custody + audit rows.
   - MAX=1 MB (test setting) → 2 MB body → 413; `list_objects(prefix, include_version=True)` empty; no DB rows; temp dir empty.
   - Content-Length > MAX → 413 without reading body.
   - client disconnect mid-upload → temp dir empty, no object versions, slot released.
   - DB failure after put (inject failing repository insert) → object version deleted, 500.
   - 3rd concurrent upload by same user → 429.
   - overwrite attack: PUT different bytes to same key with admin client → download returns **original** bytes; verify `ok`.
   - mismatch: evidence row created by factory with wrong stored sha256 for a real object → verify `mismatch` + custody `verified_mismatch`.
   - missing: factory row pointing to non-existent version → verify `missing`.
   - download headers exact; body equals original; custody `downloaded` committed before body.
   - viewer upload → 403; other-org evidence → 404; unauthenticated download → 401.
   - EICAR accepted, stored, `detected_mime` recorded, never executed.

## Success Criteria
- [ ] All evidence tests green.
- [ ] Manual: 1 GB upload through gateway succeeds; API RSS stays flat (observed, not asserted); DB pool unaffected (login works during upload).
- [ ] No code path opens evidence content except the 8 KiB sniff.

## Implementation Notes (2026-11-04)
- Modules: `evidence/uploads.py` (spool → put → records), `evidence/locking.py` (retention + failed-upload cleanup), `evidence/transfer.py` (download/verify), `evidence/service.py` (metadata, custody, archive, `record_event` = custody + audit).
- After the evidence rows commit nothing changes the response: retention lock, its `evidence.lock_failed` audit and the slot release are best effort (shielded, logged). Before commit, any failure deletes exactly the stored version.
- Per-user slots (`upload`, `verify`) are Redis ZSET tokens with atomic Lua acquire + expiry pruning (6 h), released with ZREM — leaked slots expire, rejected attempts never extend leases.
- Blocking MinIO calls, spool writes and hashing run on a dedicated 16-thread `evidence_io_limiter` (never the shared anyio limiter used by argon2/health). Spool hashes in ~1 MiB batches off the event loop; verify reads + hashes inside one worker thread.
- minio-py parts 16 MiB × 2 parallel → 1 GiB upload ≈ 15 s, API RSS peak ≈ 225 MiB (was 430 MiB with 64 MiB × 3). Login during upload unaffected.
- Reads/verify/delete use the bucket stored on the row. Investigation row locked `FOR SHARE` while recording uploads/archives; archived cases reject upload and evidence archive (409 `investigation_archived`).
- Upload requires `Content-Type: application/octet-stream` (415 otherwise). Caddy 413s use the JSON error envelope.
- MinIO policy needs `s3:DeleteObject` in addition to `s3:DeleteObjectVersion` for versioned deletes (MinIO semantics). An unversioned delete would only add a delete marker; the app always reads by version.
- `api-test` receives MinIO root creds (test profile only) to simulate overwrite attacks and purge locked test versions.
- Accepted M1 risks → THREAT_MODEL: no per-org storage quota (open registration + 30-day governance lock can fill MinIO); aborted downloads still logged as `downloaded`; no Range/resume. `scripts/reconcile_orphans.py` delivered in phase 9.

## Risk Assessment
- Temp disk exhaustion → per-user slot limit + documented sizing; temp files always removed in `finally`; startup sweeps stale temp files older than 1h.
- python-magic parses untrusted bytes in API process (8 KiB) → accepted M1 risk; moves to workers in M2 (THREAT_MODEL).
- Crash between `fput_object` and commit → orphan version; `scripts/reconcile_orphans.py` (list versions under org prefixes w/o evidence row, report-only) documented as recovery.

## Security Considerations
- Object keys prefixed by org id; bucket private; scoped MinIO user.
- No presigned URLs in M1 → every byte access authorized + logged.
- Storage key / version id never returned to client.
