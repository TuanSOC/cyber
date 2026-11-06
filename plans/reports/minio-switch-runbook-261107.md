# Runbook: switch the object store to pgsty/silo (prepared, not executed)

Date: 2026-11-07. Branch: `feat/m7-platform-ops`. Follows from
`plans/reports/researcher-261106-m7-object-store.md`, recommendation (a).

**Status:** the files are new only, and nothing has been pulled, built, started or switched. The
switch happens only if three gates all pass: the backup, the isolated conformance suite and the
restore drill into the new image.

## Facts re-verified on 2026-11-06 (registry HTTP API and GitHub API; no `docker pull`)

### Release

- **Latest release:** `RELEASE.2026-10-26T00-00-00Z`. The GitHub releases API shows it published
  2026-10-26T18:13:26Z. The previous releases are 10-18 and 09-16.
- **No newer tag:** on Docker Hub, `latest` has the same digest as this release.

### Image digests

Both digests come from `registry-1.docker.io/v2/pgsty/silo/manifests/...`, and the sha256 of the
bytes that came back was recomputed locally.

| Manifest | Digest |
| --- | --- |
| Multi-arch OCI index (tag `RELEASE.2026-10-26T00-00-00Z`) | `sha256:7bb2aff6b89efe1cb1303c10fc21d579447434ed06649ac9ec05a5e2dbf30ad7` |
| linux/amd64 image manifest | `sha256:003925ecebdcd659494621de84984f20aac2ca0ce88684ba23bb1e38b8e0db3c` |

The amd64 config blob is `sha256:43b73672…`. It records image revision `c3ad836a`.

### Signing

There is **no classic `cosign sign` signature**: no `sha256-….sig` tag exists.
- **What is signed:** Sigstore-signed GitHub attestations, which the referrers API lists:
  - SLSA provenance v1 on the index digest;
  - SPDX SBOM attestations on each per-arch digest (from the workflow file).
- **Signer:** `https://github.com/pgsty/silo/.github/workflows/docker-release.yml@refs/tags/RELEASE.2026-10-26T00-00-00Z`,
  issuer `https://token.actions.githubusercontent.com`, recorded in the Rekor transparency log.
- **Verified here, exit 0, with gh 2.92.0:**

  ```sh
  gh attestation verify oci://index.docker.io/pgsty/silo@sha256:7bb2aff6b89efe1cb1303c10fc21d579447434ed06649ac9ec05a5e2dbf30ad7 \
    --repo pgsty/silo --signer-workflow pgsty/silo/.github/workflows/docker-release.yml \
    --source-ref refs/tags/RELEASE.2026-10-26T00-00-00Z --deny-self-hosted-runners
  ```

- **cosign is not installed on this host.** The equivalent command is below and was **not run**.
  It needs cosign 2.4 or later for `--new-bundle-format`.

  ```sh
  cosign verify-attestation --new-bundle-format --type https://slsa.dev/provenance/v1 \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity https://github.com/pgsty/silo/.github/workflows/docker-release.yml@refs/tags/RELEASE.2026-10-26T00-00-00Z \
    index.docker.io/pgsty/silo@sha256:7bb2aff6...
  ```

### Image config

- **Base:** `ubi9/ubi-micro` 9.8.
- **Entrypoint and command:** ENTRYPOINT `/usr/bin/docker-entrypoint.sh`, CMD `["silo"]`.
  - The entrypoint prefixes `server`, `healthcheck` or a leading `minio` argument with `silo`.
  - With **no arguments it runs a bare `silo`**, which prints its help: it does not start a server.
- **No `USER`:** the image runs as root. `MINIO_USERNAME` with `MINIO_GROUPNAME` triggers a
  chroot user switch, which is deprecated.
- **Defaults:** `HOME=/tmp`, `VOLUME /data`.
- **Bundled tools:** `/usr/bin/curl`, plus `/usr/bin/mcli` and an `mc -> mcli` symlink.

### Environment variables

- **Image defaults:** `MINIO_ROOT_USER_FILE=access_key` and `MINIO_KMS_SECRET_KEY_FILE=kms_master_key`.
  Both are resolved under `/run/secrets/` and ignored when the file is missing.
- **Our values:** our absolute `MINIO_KMS_SECRET_KEY_FILE=/run/secrets/minio_kms_key` overrides
  the default. `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` work unchanged.
- **Migration guide:** "`MINIO_*` environment variables and existing server CLI flags remain
  unchanged" (silo.pgsty.com/compatibility/migration).

### Data, rollback and breaking changes

- **On-disk format:** "Object layouts, erasure formats, and the `.minio.sys` metadata directory
  remain unchanged", and version ids persist.
- **Ownership:** a migration keeps running as the existing data owner. Bitnami wrote the data as
  uid 1001.
- **Rollback:**
  - "releases with persistent IAM revocations do not support rolling downgrades".
  - Startup can rewrite `.minio.sys`.
  - The only rollback is to restore the pre-upgrade volume backup.
- **Breaking changes since 20260806, checked against our files:**
  - `s3:DeleteObjectVersion` is now required to delete a version. Both of our templates grant it.
  - Tighter policy validation: no bare ARN prefixes, and no `Resource` combined with
    `NotResource`. Our templates use neither.
  - Unknown checksum algorithms are rejected (400). We use none.
  - `admin:EnableUser` / `admin:DisableUser` are split. We use neither.
- **Healthcheck:** curl is present, so `curl -fsS http://localhost:9000/minio/health/live` keeps
  working. The native probe is `silo healthcheck ready`.
- **mc:** keep `MC_IMAGE=bitnamilegacy/minio-client:2025.5.21`. `pgsty/mc` ships the binary as
  `mcli`, and `init.sh` calls `mc`.

## Design: a local wrapper image, not just an overlay with `command:`

The drill and the backup and restore scripts build their own compose models, and they would
ignore an overlay. Two facts make that matter:
- `scripts/lib/stack.mjs` `composeFiles()` is a fixed list, and the drill's `--target-minio-image`
  only sets the `MINIO_IMAGE` / `MINIO_DATA_DIR` environment variables.
- `pgsty/silo@sha256:…` with no command **exits at once**.

So `pnpm restore:drill -- --target-minio-image pgsty/silo@sha256:… --target-minio-data-dir /data`
fails at "minio exited". `pnpm backup`'s restart and `pnpm restore` would also start a dead MinIO
after the switch.

**The fix:** `infra/minio/silo/Dockerfile` builds a local wrapper image,
`localhost/cyberlab/silo:RELEASE.2026-10-26T00-00-00Z`:
- It is built `FROM pgsty/silo:RELEASE.2026-10-26T00-00-00Z@sha256:7bb2…`.
- It adds `USER 1001:1001` and a `chown 1001:1001 /data`.
- Its CMD is `server /data --console-address :9001 --certs-dir /tmp/minio-certs`.

With the wrapper:
- `.env` needs only `MINIO_IMAGE=<wrapper>` and `MINIO_DATA_DIR=/data`, and every model starts a
  real server.
- The existing volume and every restored bitnami tar (uid 1001, `--numeric-owner`) stay usable
  with no chown, and the on-disk ownership stays as bitnami left it.
- The `localhost/` prefix means a missing image fails to pull and is never fetched from Docker Hub.

**The pin:** the base digest is pinned in the Dockerfile, in the overlay's build argument and in
`SILO` in the script. A unit test asserts that all three agree.

**The overlay:** `infra/minio/silo/docker-compose.silo.yml` adds the build, `pull_policy: never`,
the explicit `command`/`user`, `/data`, `read_only` with a `/tmp` tmpfs, `cap_drop: [ALL]`,
`no-new-privileges` and the same healthcheck.

## Exact switch sequence

Run from PowerShell, or from Git Bash with `MSYS_NO_PATHCONV=1`: Git Bash rewrites a bare `/data`
argument into `C:/Program Files/Git/data`, which was observed here.

Before you start:
- The main stack is up and healthy (`pnpm dev`, or the test profile's dependencies for api-test).
- `gh` is logged in.
- No heavy analyzer or worker runs.

```sh
node scripts/minio-switch.mjs preflight            # read-only: model, files, pin, gh attestation, plan
node scripts/minio-switch.mjs run [--lane 6] [--prod]
```

`run` does the following, in order:
1. **Preflight checks:**
   - The model is bitnami on `/bitnami/minio/data`.
   - No `COMPOSE_PROJECT_NAME` / `COMPOSE_FILE` variable is set.
   - The overlay, the Dockerfile and the candidate compose file exist.
   - The candidate equals the pin.
   - The attestation verifies, with `gh`, else `cosign`, else a refusal unless `--skip-attestation`.
2. **Build the wrapper:** `docker compose -f docker-compose.yml -f infra/minio/silo/docker-compose.silo.yml build minio`.
   This pulls the base by digest. Then it asserts that `Config.User` is `1001:1001`.
3. **Back up:** `runBackup` (`pnpm backup`) writes into a new Docker volume,
   `cyberlab-switch_pre-silo-<utc>`, labelled `cyberlab.switch=pre-silo`. This volume is the
   rollback anchor and is kept. The backup runs with `restart: false`, so the writers stay
   stopped until activation and the backup stays current.
4. **Start only the suite's dependencies:** `up -d --no-deps postgres redis minio`. MinIO is still
   bitnami here, because the suite also runs against the configured store.
5. **Conformance**, holding every lane slot:
   - The project is `docker compose -p cyberlab-objstore --env-file .env -f infra/minio/image/docker-compose.candidate.yml`.
   - The candidate is `pgsty/silo@sha256:7bb2…`, with a random throwaway root password and the
     lane 6 DB and Redis.
   - It runs `up -d --wait candidate`, then `run --rm conformance`, then the RT7 `prepare`, a
     `restart candidate` and `verify`.
   - It always ends with a guarded `down -v`: the model must resolve to `cyberlab-objstore` and
     every volume must be `cyberlab-objstore_*`.
6. **Stop the main project:** `docker compose stop`, which frees RAM for the drill.
7. **Restore drill:** `runDrill({ targetMinioImage: "localhost/cyberlab/silo:RELEASE.2026-10-26T00-00-00Z", targetMinioDataDir: "/data" })`.
   This is the same as `pnpm restore:drill -- --target-minio-image localhost/cyberlab/silo:RELEASE.2026-10-26T00-00-00Z --target-minio-data-dir /data`.
   It seeds bitnami, backs up, restores into the wrapper and verifies.
8. **Only when steps 1 to 7 pass:** write `infra/minio/silo/.env.silo` (gitignored by `.env.*`)
   and print the activation and rollback steps. `.env` itself is never edited.

If any step fails, nothing has switched: bring the stack back with `docker compose up -d --no-build`.

**Activation (the parent's decision):**

```sh
# merge infra/minio/silo/.env.silo into .env: MINIO_IMAGE=localhost/cyberlab/silo:RELEASE.2026-10-26T00-00-00Z, MINIO_DATA_DIR=/data
docker compose -f docker-compose.yml -f infra/minio/silo/docker-compose.silo.yml up -d --no-build --no-deps --wait minio
docker compose -f docker-compose.yml -f infra/minio/silo/docker-compose.silo.yml run --rm minio-init
docker compose -f docker-compose.yml -f infra/minio/silo/docker-compose.silo.yml up -d --no-build
scripts/lane-test.sh 6 uv run pytest -q -p no:cacheprovider tests/integration/test_object_store_conformance.py
pnpm verify
```

For prod, add `-f docker-compose.prod.yml` before the overlay.

**Rollback:** Silo cannot be downgraded in place, so roll back by restoring the pre-switch backup
onto bitnami. Every write made after the backup is lost.

```sh
docker compose -f docker-compose.yml -f infra/minio/silo/docker-compose.silo.yml stop
# remove MINIO_IMAGE / MINIO_DATA_DIR (and COMPOSE_FILE) from .env
docker compose -p cyberlab -f docker-compose.yml down -v      # DELIBERATE: removes the current volumes
node scripts/minio-switch.mjs rollback --backup-volume cyberlab-switch_pre-silo-<utc>
docker volume rm cyberlab-switch_pre-silo-<utc>              # only after verification
```

`rollback` restores from the Docker volume, which the `pnpm restore` CLI cannot do because it
reads only a host directory. It refuses in three cases:
- the volume lacks the label;
- the model is not bitnami;
- the stack is not empty (in that case `runRestore` prints the `down -v` command).

## For the parent at merge (existing files, not touched here)

- **Fold the overlay into `docker-compose.yml`** once Silo becomes the default: the default image
  becomes the wrapper, the data dir becomes `/data`, and the hardening applies to every model,
  including backup, restore and the drill. Until then, scripts that ignore the overlay run the
  wrapper without `read_only` and `cap_drop`. That works, but it is less hardened.
- **Update the comments that name the bitnami build:** `.env.example` lines 156–161 and
  `docker-compose.yml` lines 316–319.
- **Update `docs/THREAT_MODEL.md`:** the switch closes CVE-2025-62506 and SN-2026-015/016, and the
  record of that closure needs this runbook's verification command.

## Risks

1. **The overlay alone fails in the drill and in the backup restart.** The parent's literal
   `--target-minio-image pgsty/silo@sha256:…` drill would fail. Use the wrapper.
2. **No in-place rollback.** A rollback is a full restore, of the database too. Writes made after
   the backup are lost, and the stack has downtime from the backup until activation.
3. **The suite and the drill test different users.** The conformance suite tests the upstream
   image as root, with `cap_drop ALL` and a fresh volume. The drill tests the wrapper as uid 1001
   on bitnami data. The S3 behaviour comes from the same binary.
4. **The suite writes to the live store after the backup.** It also runs against the current
   bitnami MinIO, creating fresh buckets and then removing them.
5. **Fresh-volume ownership relies on BuildKit keeping the `chown` of the VOLUME path.** Docker
   Desktop uses BuildKit by default. On the legacy builder, run
   `docker run --rm -v <vol>:/data postgres:17.11-alpine chown 1001:1001 /data`.
6. **Prod KMS key file:** it must be readable by uid 1001, which is no change from bitnami.
7. **Git Bash rewrites `/data` arguments.** The script passes it internally, so it is unaffected.
8. **Unverified:**
   - cosign verification (not installed);
   - the Silo migration-guide claims, which come from the docs (fetched on 2026-11-06) and were
     not run;
   - BuildKit behaviour on this host;
   - whether `cyberlab_b6_test` exists (`lane-test.sh` uses it).
9. **Memory:** the run is heavy. It needs about 512 MB for the candidate plus an api-test
   container, then about 1.2 GB for the drill, one after the other. Run it alone.
10. **A newer Silo release may appear.** Re-check the tag before `run`, and bump `SILO`, the
    Dockerfile and the overlay together. A unit test enforces that they agree.

## Files (all new)

- `infra/minio/silo/Dockerfile`: the wrapper.
- `infra/minio/silo/docker-compose.silo.yml`: the overlay.
- `scripts/minio-switch.mjs`: the `preflight` / `run` / `rollback` commands.
- `scripts/minio-switch.test.mjs`: 15 tests, run with `node --test`, all passing.

**Checks run:**
- `node --check` passes for both scripts.
- `docker compose -f docker-compose.yml -f infra/minio/silo/docker-compose.silo.yml config`
  passes, and so does the same with the prod file.
- The drill model with `MINIO_IMAGE=<wrapper>` / `MINIO_DATA_DIR=/data` resolves `/data` and uses
  the image's CMD.
- The candidate model resolves `pgsty/silo@sha256:7bb2…`.
