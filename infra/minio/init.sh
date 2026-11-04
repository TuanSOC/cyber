#!/bin/sh
# Idempotent MinIO bootstrap: object-locked buckets + scoped API user.
set -eu

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

# Test bucket only: expire leftover noncurrent versions. The evidence bucket gets no
# lifecycle rule on purpose: a noncurrent version there may be original evidence that
# was overwritten, and it must not be auto-deleted.
mc ilm import "local/$MINIO_TEST_BUCKET" </init/test-lifecycle.json

# Policy is rendered from the bucket names in the environment.
sed -e "s/__BUCKET__/$MINIO_BUCKET/g" -e "s/__TEST_BUCKET__/$MINIO_TEST_BUCKET/g" \
  -e "s/__RESULTS_BUCKET__/$RESULTS_BUCKET/g" -e "s/__RESULTS_TEST_BUCKET__/$RESULTS_TEST_BUCKET/g" \
  /init/api-policy.template.json >/tmp/api-policy.json
mc admin policy create local cyberlab-api /tmp/api-policy.json
mc admin user add local "$MINIO_ACCESS_KEY" "$MINIO_SECRET_KEY"
if mc admin user info local "$MINIO_ACCESS_KEY" --json | grep -q '"policyName":"cyberlab-api"'; then
  echo "policy cyberlab-api already attached"
else
  mc admin policy attach local cyberlab-api --user "$MINIO_ACCESS_KEY"
fi

echo "minio init done"
