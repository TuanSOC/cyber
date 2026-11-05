#!/bin/sh
# Idempotent MinIO bootstrap: object-locked buckets + scoped API user, and (M7) SSE-S3 on
# every bucket plus the least-privilege purge user of the retention worker.
set -eu

# M7 (RT7): the committed dev KMS key (infra/minio/dev-kms-key) must never protect a prod
# store. Only the key NAME is read here (the part before ':'); the key itself is never printed.
if [ "${ENV:-dev}" = "prod" ] && [ -r /run/secrets/minio_kms_key ]; then
  kms_name="$(cut -d: -f1 /run/secrets/minio_kms_key | head -n1)"
  if [ "$kms_name" = "cyberlab-dev-kms" ]; then
    echo "ERROR: the committed dev KMS key is not allowed in prod (.secrets/minio_kms_key)" >&2
    exit 1
  fi
fi

# MinIO can report healthy a moment before it accepts connections on a recreated network.
attempt=0
until mc alias set local http://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "ERROR: MinIO not reachable" >&2
    exit 1
  fi
  sleep 1
done

for bucket in "$MINIO_BUCKET" "$MINIO_TEST_BUCKET"; do
  if mc ls "local/$bucket" >/dev/null 2>&1; then
    # Object lock can only be enabled at creation time; refuse to continue without it.
    if ! mc retention info --default "local/$bucket" >/dev/null 2>&1; then
      echo "ERROR: bucket $bucket exists without object lock. Recreate it (docker compose down -v)." >&2
      exit 1
    fi
    echo "bucket $bucket ok (object lock enabled)"
  else
    mc mb --with-lock "local/$bucket"
  fi
done

# Analysis results: versioned (ingest reads an exact version), no object lock (derived data).
for bucket in "$RESULTS_BUCKET" "$RESULTS_TEST_BUCKET"; do
  mc mb --ignore-existing "local/$bucket"
  mc version enable "local/$bucket"
done

# Reports (M6, RT6): object-locked and versioned like evidence, with NO bucket default
# retention (it would make MinIO demand Content-MD5 on the renderer's presigned POST).
# Retention is set per object (GOVERNANCE, EVIDENCE_LOCK_DAYS) by the API on the snapshot and
# by the ingest worker on each artifact. An existing bucket without object lock is refused.
REPORTS_BUCKET="${REPORTS_BUCKET:-reports}"
REPORTS_TEST_BUCKET="${REPORTS_TEST_BUCKET:-reports-test}"
for bucket in "$REPORTS_BUCKET" "$REPORTS_TEST_BUCKET"; do
  if mc ls "local/$bucket" >/dev/null 2>&1; then
    if ! mc retention info --default "local/$bucket" >/dev/null 2>&1; then
      echo "ERROR: bucket $bucket exists without object lock. Recreate it (docker compose down -v)." >&2
      exit 1
    fi
    echo "bucket $bucket ok (object lock enabled)"
  else
    mc mb --with-lock "local/$bucket"
  fi
done

# Test buckets only: expire leftover noncurrent versions. The evidence and reports buckets
# get no lifecycle rule on purpose: a noncurrent version there may be original evidence or a
# signed report that was overwritten, and it must not be auto-deleted.
mc ilm import "local/$MINIO_TEST_BUCKET" </init/test-lifecycle.json
mc ilm import "local/$REPORTS_TEST_BUCKET" </init/reports-test-lifecycle.json

# SSE-S3 at rest (M7): the bucket default encrypts every NEW object with MinIO's KMS key
# (MINIO_KMS_SECRET_KEY_FILE on the minio service). Objects written before stay plaintext
# until rewritten. MINIO_SSE_ENABLED=false skips it (e.g. a store without a KMS key); an
# existing setting is never cleared here.
if [ "${MINIO_SSE_ENABLED:-true}" = "true" ]; then
  for bucket in "$MINIO_BUCKET" "$MINIO_TEST_BUCKET" "$RESULTS_BUCKET" "$RESULTS_TEST_BUCKET" \
    "$REPORTS_BUCKET" "$REPORTS_TEST_BUCKET"; do
    mc encrypt set sse-s3 "local/$bucket" >/dev/null
    echo "bucket $bucket: SSE-S3 on"
  done
else
  echo "SSE-S3 skipped (MINIO_SSE_ENABLED=${MINIO_SSE_ENABLED})"
fi

# Policy is rendered from the bucket names in the environment.
sed -e "s/__BUCKET__/$MINIO_BUCKET/g" -e "s/__TEST_BUCKET__/$MINIO_TEST_BUCKET/g" \
  -e "s/__RESULTS_BUCKET__/$RESULTS_BUCKET/g" -e "s/__RESULTS_TEST_BUCKET__/$RESULTS_TEST_BUCKET/g" \
  -e "s/__REPORTS_BUCKET__/$REPORTS_BUCKET/g" -e "s/__REPORTS_TEST_BUCKET__/$REPORTS_TEST_BUCKET/g" \
  /init/api-policy.template.json >/tmp/api-policy.json
mc admin policy create local cyberlab-api /tmp/api-policy.json
mc admin user add local "$MINIO_ACCESS_KEY" "$MINIO_SECRET_KEY"
if mc admin user info local "$MINIO_ACCESS_KEY" --json | grep -q '"policyName":"cyberlab-api"'; then
  echo "policy cyberlab-api already attached"
else
  mc admin policy attach local cyberlab-api --user "$MINIO_ACCESS_KEY"
fi

# The retention worker's purge user (M7, RT5): delete expired versions, read retention,
# read / set S3 legal holds (the hold sync), list; an explicit Deny on report snapshots; no
# PutObject and no governance bypass. The api policy above is unchanged (no legal-hold action).
: "${MINIO_PURGE_ACCESS_KEY:?}" "${MINIO_PURGE_SECRET_KEY:?}"
# mc would parse a leading '-' as a flag (and echo the value in its usage error).
case "$MINIO_PURGE_ACCESS_KEY$MINIO_PURGE_SECRET_KEY" in
  -*) echo "ERROR: MINIO_PURGE_ACCESS_KEY / MINIO_PURGE_SECRET_KEY must not start with '-'" >&2; exit 1 ;;
esac
case "$MINIO_PURGE_SECRET_KEY" in
  -*) echo "ERROR: MINIO_PURGE_SECRET_KEY must not start with '-'" >&2; exit 1 ;;
esac
sed -e "s/__BUCKET__/$MINIO_BUCKET/g" -e "s/__TEST_BUCKET__/$MINIO_TEST_BUCKET/g" \
  -e "s/__RESULTS_BUCKET__/$RESULTS_BUCKET/g" -e "s/__RESULTS_TEST_BUCKET__/$RESULTS_TEST_BUCKET/g" \
  -e "s/__REPORTS_BUCKET__/$REPORTS_BUCKET/g" -e "s/__REPORTS_TEST_BUCKET__/$REPORTS_TEST_BUCKET/g" \
  /init/purge-policy.template.json >/tmp/purge-policy.json
mc admin policy create local cyberlab-purge /tmp/purge-policy.json
mc admin user add local "$MINIO_PURGE_ACCESS_KEY" "$MINIO_PURGE_SECRET_KEY"
if mc admin user info local "$MINIO_PURGE_ACCESS_KEY" --json | grep -q '"policyName":"cyberlab-purge"'; then
  echo "policy cyberlab-purge already attached"
else
  mc admin policy attach local cyberlab-purge --user "$MINIO_PURGE_ACCESS_KEY"
fi

echo "minio init done"
