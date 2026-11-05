# syntax=docker/dockerfile:1
# Option (b) of the M7 object-store research (plans/reports/researcher-261106-m7-object-store.md):
# a pinned source build of the LAST upstream MinIO community release. Not the recommendation
# (it receives no further patches: every 2026 MinIO CVE and the GOVERNANCE retention bypass
# fixed in forks stay open), kept as the fallback if no maintained fork is acceptable.
#
# Heavy (Go build, ~2-3 GB RAM): build alone, never alongside the test lanes.
#   docker build -t cyberlab/minio-src:2025-10-15 infra/minio/image
#   docker build --target vulncheck -o type=local,dest=./govulncheck infra/minio/image
#
# Drop-in for bitnami: same on-disk format (xl.meta, version ids), the upstream env names
# (MINIO_ROOT_USER / MINIO_ROOT_PASSWORD / MINIO_KMS_SECRET_KEY_FILE), data dir /data
# (MINIO_DATA_DIR=/data), and it runs as uid 1001 like bitnami, so a restored bitnami volume is
# readable without a chown. The compose service needs a command:
#   command: ["server", "/data", "--console-address", ":9001"]   (console never published)

ARG GO_IMAGE=golang:1.24.8-bookworm
ARG RUNTIME_IMAGE=alpine:3.22

FROM ${GO_IMAGE} AS build
# The last community release (the repository was archived on 2026-04-25).
ARG MINIO_RELEASE=RELEASE.2025-10-15T17-29-55Z
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN git clone --depth 1 --branch "${MINIO_RELEASE}" https://github.com/minio/minio.git /src
WORKDIR /src
# The upstream Makefile's build: version / commit / release stamped by gen-ldflags.
RUN go build -tags kqueue -ldflags "-s -w $(go run buildscripts/gen-ldflags.go)" -o /out/minio . \
 && /out/minio --version

# govulncheck report of the pinned tree (Go vuln database advisories only; it cannot see
# the fork-only "SN-2026-*" fixes). Exported with `--target vulncheck -o type=local,...`.
FROM build AS vulncheck-run
RUN go install golang.org/x/vuln/cmd/govulncheck@latest \
 && (govulncheck ./... > /out/govulncheck.txt 2>&1 || true)
FROM scratch AS vulncheck
COPY --from=vulncheck-run /out/govulncheck.txt /

FROM ${RUNTIME_IMAGE}
# curl: the compose healthcheck (`curl -fsS http://localhost:9000/minio/health/live`).
RUN apk add --no-cache ca-certificates curl \
 && addgroup -S -g 1001 minio && adduser -S -D -H -u 1001 -G minio minio \
 && mkdir -p /data && chown 1001:1001 /data
COPY --from=build /out/minio /usr/bin/minio
USER 1001:1001
EXPOSE 9000
VOLUME ["/data"]
ENTRYPOINT ["/usr/bin/minio"]
CMD ["server", "/data", "--console-address", ":9001"]
