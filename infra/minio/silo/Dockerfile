# CyberLab's Silo image (M7 phase 6 switch): pgsty/silo pinned by digest, with only two changes.
#
#  1. It runs as uid/gid 1001 (as the bitnami build did), so the existing `miniodata` volume and
#     every restored bitnami tar (--numeric-owner, uid 1001) are used as they are, with no chown.
#     A fresh volume copies /data from this image, which is owned by 1001. BuildKit keeps changes
#     to a path declared as a VOLUME in the base image (the legacy builder drops them; on a fresh
#     volume that is not 1001-owned, see the runbook).
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
# Build it with the overlay (`docker compose -f docker-compose.yml -f
# infra/minio/silo/docker-compose.silo.yml build minio`) or `node scripts/minio-switch.mjs run`.
# The tag lives under `localhost/`, so a missing local image fails to pull and is never
# fetched from Docker Hub.
ARG SILO_BASE=pgsty/silo:RELEASE.2026-10-26T00-00-00Z@sha256:7bb2aff6b89efe1cb1303c10fc21d579447434ed06649ac9ec05a5e2dbf30ad7
FROM ${SILO_BASE}

USER root
RUN mkdir -p /data && chown 1001:1001 /data && chmod 0750 /data
USER 1001:1001
ENV HOME=/tmp

# The entrypoint prefixes `server` with `silo`. The certs dir lives under /tmp, so the root
# filesystem can be read-only (overlay).
CMD ["server", "/data", "--console-address", ":9001", "--certs-dir", "/tmp/minio-certs"]
