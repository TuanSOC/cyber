#!/usr/bin/env bash
# Run api-test (or another test-profile service) against an isolated test lane (parallel
# development agents).
#   scripts/lane-test.sh <lane 2..8> [--service <test service>] [--heavy] <command...>
#   e.g. scripts/lane-test.sh 3 uv run pytest -q -p no:cacheprovider tests/unit/test_ai_providers.py
#        scripts/lane-test.sh 4 --service report-worker-test pytest -q tests/   (M6, RT21)
#        scripts/lane-test.sh 2 --service memory-worker-test --heavy pytest -q tests/engine  (M8)
# `--heavy` (M8) takes two slots, atomically (both or wait): runs that load a memory image.
# `--print-lock-root` prints the slot lock root and exits (M7 restore drill, RT25).
# Lane N uses database cyberlab_bN_test, app Redis db N and broker db N, so lanes never
# truncate or purge each other's state. The default lane (cyberlab_test, db 1) is untouched.
# The MinIO test buckets are shared: TEST_LANE gives the lane its own key prefix (`lane-N/`)
# for the objects tests write, and cleanup removes only the keys of the orgs that process
# created plus that prefix, never a whole bucket (M7 phase 11, apps/api/tests/storage_helpers.py).
# Every service takes a slot from the same lock (host memory). A service other than
# api-test gets only the lane's broker db (TEST_BROKER_DB): it has no database or app Redis.
# Never `up`/`down`/`build` from a lane: compose project `cyberlab` is shared.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" = "--print-lock-root" ]; then
  echo "${LANE_LOCK_ROOT:-${TMPDIR:-${TEMP:-/tmp}}/cyberlab-lane-slots}"
  exit 0
fi

lane="${1:?lane number 2..8}"
shift
case "$lane" in [2-8]) ;; *) echo "lane must be 2..8" >&2; exit 2 ;; esac

service="api-test"
if [ "${1:-}" = "--service" ]; then
  service="${2:?--service needs a test-profile service name}"
  shift 2
fi
case "$service" in
  api-test|report-worker-test|memory-worker-test) ;;
  *) echo "unsupported lane service: $service" >&2; exit 2 ;;
esac
need=1
if [ "${1:-}" = "--heavy" ]; then
  need=2
  shift
fi

env_value() { grep -E "^$1=" .env | head -n1 | cut -d= -f2- || true; }
db="cyberlab_b${lane}_test"
app_url="$(env_value TEST_DATABASE_URL | sed -E "s#/[^/]+\$#/${db}#")"
owner_url="$(env_value TEST_MIGRATION_DATABASE_URL | sed -E "s#/[^/]+\$#/${db}#")"
redis_url="$(env_value TEST_REDIS_URL | sed -E "s#/[0-9]+\$#/${lane}#")"
# M7 (RT15): the retention role's URL points at the lane DB too (compose builds the default
# from POSTGRES_RETENTION_PASSWORD, so derive it the same way; passwords are URL-safe).
retention_pw="$(env_value POSTGRES_RETENTION_PASSWORD)"
retention_url="$(env_value TEST_DATABASE_URL \
  | sed -E "s#//[^@/]+@#//cyberlab_retention:${retention_pw:-change-me-retention}@#; s#/[^/]+\$#/${db}#")"

# At most LANE_SLOTS (default 3) lane containers at once: host memory is limited. The lock
# root is exported as LANE_LOCK_ROOT (M7, RT25) so scripts/restore-drill.mjs takes exactly
# these slots; set LANE_LOCK_ROOT to override it (default unchanged).
slots="${LANE_SLOTS:-3}"
lock_root="${LANE_LOCK_ROOT:-${TMPDIR:-${TEMP:-/tmp}}/cyberlab-lane-slots}"
export LANE_LOCK_ROOT="$lock_root"
mkdir -p "$lock_root"
if [ "$need" -gt "$slots" ]; then
  echo "--heavy needs $need slots but LANE_SLOTS is $slots" >&2
  exit 2
fi
# Take `need` slots. Several slots are taken under one acquisition mutex (`acquire`, a dir) and
# released again unless all were free, so two heavy lanes never each hold half (M8).
held=""
release() { for s in $held; do rmdir "$s" 2>/dev/null || true; done; held=""; }
trap 'release' EXIT INT TERM
while :; do
  mutex=""
  if [ "$need" -gt 1 ]; then
    if mkdir "$lock_root/acquire" 2>/dev/null; then mutex="$lock_root/acquire"; else sleep 5; continue; fi
  fi
  count=0
  for i in $(seq 1 "$slots"); do
    [ "$count" -ge "$need" ] && break
    if mkdir "$lock_root/slot-$i" 2>/dev/null; then
      held="$held $lock_root/slot-$i"
      count=$((count + 1))
    fi
  done
  [ -n "$mutex" ] && rmdir "$mutex" 2>/dev/null
  [ "$count" -ge "$need" ] && break
  release
  sleep 5
done

export TEST_BROKER_DB="$lane" MSYS_NO_PATHCONV=1
if [ "$service" = "api-test" ]; then
  docker compose --profile test run --rm --no-deps \
    -e DATABASE_URL="$app_url" \
    -e MIGRATION_DATABASE_URL="$owner_url" \
    -e TEST_MIGRATION_DATABASE_URL="$owner_url" \
    -e REDIS_URL="$redis_url" \
    -e RETENTION_TEST_DATABASE_URL="$retention_url" \
    -e TEST_LANE="$lane" \
    api-test "$@"
else
  # The renderer and the memory analyzer hold no DB or app Redis settings: only the lane's
  # broker db, which compose interpolates into its BROKER_URL through TEST_BROKER_DB.
  docker compose --profile test run --rm --no-deps "$service" "$@"
fi
