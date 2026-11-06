# CyberLab's Silo image (M7 phase 6 switch): pgsty/silo pinned by digest, with only two changes.
#
#  1. It runs as uid 1001, gid 0 (exactly as the bitnami build did: uid 1001, group root), so the
#     existing `miniodata` volume and every restored bitnami tar (--numeric-owner) are used as
#     they are, with no chown. The bitnami volume root is root:root 0775: bitnami creates new
#     buckets there through its group 0 write bit, so gid 0 is required (a 1001:1001 wrapper read
#     every existing bucket but got AccessDenied creating a new one, 2026-11-06). A fresh volume
#     copies /data from this image (1001:0 0770). BuildKit keeps changes to a path declared as a
#     VOLUME in the base image (the legacy builder drops them; on a fresh volume that is not
#     writable by 1001 or gid 0, see the runbook).
#  2. It has a server CMD. Without one, the upstream image runs a bare `silo` that prints its
#     help and exits. Bitnami's entrypoint used to supply the command. With the CMD baked in,
#     every compose model, including the restore drill's `--target-minio-image` (which only
#     sets MINIO_IMAGE / MINIO_DATA_DIR), starts a server without a `command:` override.
#
# Verify the base before building. The release workflow attests SLSA provenance on the
# multi-arch index:
#   gh attestation verify oci://index.docker.io/pgsty/silo@sha256:7bb2aff6b89efe1cb1303c10fc21d579447434ed06649ac9ec05a5e2dbf30ad7 \
#     --repo pgsty/silo --signer-workflow pgsty/silo/.github/workflows/docker-release.yml \
#     --source-ref refs/tags/RELEASE.2026-10-26T00-00-00Z --deny-self-hosted-runners
# Build it with `docker compose build minio` (docker-compose.yml has the build section since the
# fold), the overlay, or `node scripts/minio-switch.mjs run`.
# The tag lives under `localhost/`, so a missing local image fails to pull and is never
# fetched from Docker Hub.
ARG SILO_BASE=pgsty/silo:RELEASE.2026-10-26T00-00-00Z@sha256:7bb2aff6b89efe1cb1303c10fc21d579447434ed06649ac9ec05a5e2dbf30ad7
FROM ${SILO_BASE}

# The tag compose gives this build (docker-compose.yml interpolates it from MINIO_IMAGE): a
# bitnami MINIO_IMAGE (the rollback) must fail the build, never become the tag of a Silo image.
ARG TARGET_IMAGE=localhost/cyberlab/silo:RELEASE.2026-10-26T00-00-00Z
USER root
RUN case "${TARGET_IMAGE}" in \
      localhost/cyberlab/silo:*) ;; \
      *) echo "refusing to build the Silo wrapper as ${TARGET_IMAGE} (MINIO_IMAGE is not the wrapper)" >&2; exit 1 ;; \
    esac
RUN mkdir -p /data && chown 1001:0 /data && chmod 0770 /data
USER 1001:0
ENV HOME=/tmp

# The entrypoint prefixes `server` with `silo`. The certs dir lives under /tmp, so the root
# filesystem can be read-only (overlay).
CMD ["server", "/data", "--console-address", ":9001", "--certs-dir", "/tmp/minio-certs"]
