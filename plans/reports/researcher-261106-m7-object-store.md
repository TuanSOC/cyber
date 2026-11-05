# M7 object-store image path (phase 6)

Date: 2026-11-06. Scope: a maintained successor to the frozen `bitnamilegacy/minio:2025.5.24` /
`bitnamilegacy/minio-client:2025.5.21` that keeps the on-disk format (and so every pinned
version id), plus the conformance suite that proves a candidate. **The parent or user picks**;
the `MINIO_IMAGE` / `MC_IMAGE` / `MINIO_DATA_DIR` flip happens at the group-B merge, not here.

## Facts (re-verified on the web 2026-11-06)

- Upstream `minio/minio`: community distribution source-only since October 2025, maintenance
  mode 2025-12-03, **archived 2026-04-25** (plan.md said "February 2026": corrected). The last
  community release is `RELEASE.2025-10-15T17-29-55Z` (go.mod `go 1.24.0`, toolchain 1.24.8).
- bitnamilegacy receives nothing. Our build (2025-05-24) predates CVE-2025-62506 (IAM
  privilege escalation, CVSS 8.1) and every 2026 MinIO CVE listed below.
- **Pigsty's fork `pgsty/minio` was renamed `pgsty/silo` in Aug 2026** (RT28 named
  `pgsty/minio`; the last tag there is `RELEASE.2026-08-04T00-00-00Z`).
  <https://github.com/pgsty/silo>, <https://silo.pigsty.io/compatibility/migration/>,
  <https://pigsty.io/docs/minio/faq/>.

## Options

### (a) Maintained, on-disk-compatible fork images

**`pgsty/silo`** (AGPL-3.0-or-later, about 4.5k stars):
- **Base:** forked from `RELEASE.2025-10-15T17-29-55Z`.
- **Releases:** every 1–4 weeks. Latest is `RELEASE.2026-10-26T00-00-00Z`; the previous ones were 10-18, 10-15, 09-16, 09-03 and 08-06.
- **CVE fixes:** CVE-2026-33322 (critical, OIDC JWT forgery), -33419, -34204, -39414, -41145, -40344 and -42600. Release notes also list -34986, -39883, -24051, CVE-2025-10543 and -58181, plus 18 "SN-2026-*" hardenings.
- **GOVERNANCE bypass fix:** SN-2026-015/016 is a **GOVERNANCE retention bypass** through `PutObjectRetention` and in-place version overwrites. It is inherited from upstream code from 2020 and 2025 (so it is present in our bitnami build) and was fixed in 20261018. <https://silo.pigsty.io/blog/security/20260926-governance-retention-bypass/>
- **Supply chain:** Sigstore-signed manifests, SPDX SBOMs, GitHub build attestations, amd64 and arm64.
- **Images:**
  - The standard image is `ubi9/ubi-micro` and includes `curl`, so our compose healthcheck works unchanged.
  - The `-distroless` variant has no curl and no shell, and uses a built-in `silo healthcheck ready`.
- **Command:** ENTRYPOINT `docker-entrypoint.sh`, CMD `silo`. The service must pass `server /data --console-address :9001`; a leading `minio` argument is rewritten to `silo`.
- **Compatibility:**
  - All `MINIO_*` env vars are kept, including `MINIO_ROOT_*` and `MINIO_KMS_SECRET_KEY_FILE` (same default KMS master-key handling).
  - `.minio.sys`, `xl.meta` v1.3 and **version ids are preserved**, so existing drives mount without migration.
  - The console is restored (v2.5.1). It must stay unpublished; MinIO sits on internal networks only.
- **Breaking changes:**
  - (1) Deleting a version id requires `s3:DeleteObjectVersion`. Both our api and purge policies already grant it, and phase 1 found that the bitnami build also needs `s3:DeleteObject`, which is kept.
  - (2) `admin:EnableUser` and `admin:DisableUser` are split. We use neither.
  - (3) **No rollback** once the new IAM revocation history is written, so take a backup before switching (phase 2).
  - (4) The config dir defaults to `~/.silo` (irrelevant with env config).
- **Client:** `pgsty/mc:RELEASE.2026-10-26T00-00-00Z` (multi-arch). **Its binary is `mcli`**, and `infra/minio/init.sh` calls `mc`.

**Chainguard EmeritOSS** (`chainguard-forks/minio`, announced 2026-01-15; image `cgr.dev/chainguard/minio`):
- It ships security and dependency fixes only (latest `RELEASE.2026-10-23T20-06-51Z`, same CVE set).
- The SN-2026-015/016 fix is **not verified**.
- Only `:latest` is free, so it **cannot be pinned without a subscription**.
- There is no shell or curl (the `-dev` variants are paid).

OpenMaxIO is a console-only fork, stalled since 2025-06. No other maintained fork was found.

### (b) Our own pinned source build of the last upstream release

- **What it is:** `infra/minio/image/Dockerfile`, a multi-stage build from `golang:1.24.8` to `alpine:3.22` with curl. It runs as uid 1001 like bitnami, so a restored volume needs no chown, and it has a `--target vulncheck` govulncheck export.
- **Compatibility:** same format and env as upstream.
- **Why not recommended:** it gets **no future patches**. Every 2026 CVE above and the GOVERNANCE bypass stay open, and govulncheck only sees Go-database advisories, not the SN-* issues.
- **Cost:** the Go build needs about 2–3 GB of RAM, so run it alone.

### (c) RustFS, SeaweedFS, Ceph RGW

**None can read MinIO's on-disk format.** Moving to any of them means an S3-level copy and a re-architecture of the version-id pins (every pinned id changes).
- **RustFS 1.0 GA** (2026-09-16, Apache-2.0): Object Lock, GOVERNANCE/COMPLIANCE and legal hold. Alpha releases 56–82 ignored presigned-POST conditions, including `content-length-range`, which is exactly what our analyzers rely on.
- **SeaweedFS:** Object Lock, retention, legal hold and versioning are documented. POST `content-length-range` is not verified.
- **Ceph RGW:** full feature set, but a RADOS cluster is too heavy for this host.
- RAM figures were not found for any of the three.

## Recommendation

**(a) `pgsty/silo:RELEASE.2026-10-26T00-00-00Z` (standard, ubi-micro variant), pinned by digest after `cosign verify`.** It is the only maintained, pinnable and free drop-in. It keeps the on-disk format and version ids, the env names and the KMS key handling, and it fixes a WORM bypass that directly undermines our evidence-retention claim.

What changes for the parent at the group-B merge:
- `MINIO_IMAGE=pgsty/silo@sha256:<digest>` and `MINIO_DATA_DIR=/data`. The minio service gains `command: ["server", "/data", "--console-address", ":9001"]`, because bitnami's entrypoint supplied it. `MINIO_CONSOLE_PORT_NUMBER` is bitnami-only and is ignored. The healthcheck stays the same (curl is present).
- `MC_IMAGE`: keep `bitnamilegacy/minio-client:2025.5.21` for minio-init. It is a client on internal networks only, and it uses the S3 and admin APIs that Silo keeps. Alternatively, switch to `pgsty/mc:RELEASE.2026-10-26T00-00-00Z` once `init.sh` tolerates the `mcli` binary name (`mc` resolution is a phase-1 file).
- Take a backup before the switch (Silo cannot roll back after the IAM history is written). Then run phase 2's drill with `--target-minio-image pgsty/silo@sha256:<digest>`, which restores a bitnami volume into `/data`.
- Fallback: (b). Residual until the switch: bitnami carries CVE-2025-62506 and SN-2026-015/016 (record this in THREAT_MODEL, phase 10).

## Conformance suite (`apps/api/tests/integration/test_object_store_conformance.py`)

Each run creates fresh locked and versioned buckets, its own api and purge users with the template policies rendered for those buckets (root admin API, setup only), and SSE-S3 bucket defaults.

The suite asserts:
- versioning;
- lock configuration without a default retention;
- exact-version GET and `ListObjectVersions`, including delete markers;
- GOVERNANCE set, extend and refuse-to-shorten;
- a locked delete refused for api, purge and root without bypass, and for a bypass request by a user who lacks the permission; root with bypass succeeds;
- a real version delete by the purge user;
- the explicit `snapshot.json` Deny;
- legal hold ON / OFF by the purge user only (RT5), with every delete refused while it is ON, including root with bypass;
- presigned POST: key and `content-length-range` (results), and Content-Type in the locked reports bucket without Content-MD5;
- a presigned GET of a version, with a tampered version id refused;
- the SSE-S3 default and the KMS key status;
- app users hold no admin, bucket or encryption rights.

RT7 restart is a two-step `OBJECT_STORE_RESTART_PHASE=prepare|verify` around a restart.

**Results 2026-11-06, current dev MinIO (bitnami 2025.5.24, lane 6):** 13 passed and 1 skipped (the RT7 restart step, which needs a restart of the shared dev MinIO; phase 1's rehearsal already proved RT7 on a volume copy). The shorten-retention vector tested here is refused on bitnami; the SN-2026-015/016 bypass uses another path and is not reproduced.

**Not run (heavy, deferred by instruction):** the pull of `pgsty/silo` and the suite against it. Use `infra/minio/image/docker-compose.candidate.yml` (its own project, joins `cyberlab_backend` under the alias `objstore-candidate`, no published port, 512 MB) and then `lane-test.sh 6 env OBJECT_STORE_CANDIDATE_URL=http://objstore-candidate:9000 ... pytest tests/integration/test_object_store_conformance.py`. Also not run: the option (b) build.

## Unverified

The first Silo release date, RAM footprints, whether Chainguard backported the GOVERNANCE fix, and the exact Dockerfile lines of Silo (from release pages). Re-check the digest, the `cosign` identity and the entrypoint behaviour on pull.
