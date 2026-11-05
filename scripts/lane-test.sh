#!/usr/bin/env bash
# Run api-test (or another test-profile service) against an isolated test lane (parallel
# development agents).
#   scripts/lane-test.sh <lane 2..7> [--service <test service>] <command...>
#   e.g. scripts/lane-test.sh 3 uv run pytest -q -p no:cacheprovider tests/unit/test_ai_providers.py
#        scripts/lane-test.sh 4 --service report-worker-test pytest -q tests/   (M6, RT21)
# `--print-lock-root` prints the slot lock root and exits (M7 restore drill, RT25).
# Lane N uses database cyberlab_bN_test, app Redis db N and broker db N, so lanes never
# truncate or purge each other's state. The default lane (cyberlab_test, db 1) is untouched.
# Every service takes a slot from the same lock (host memory). A service other than
# api-test gets only the lane's broker db (TEST_BROKER_DB): it has no database or app Redis.
# Never `up`/`down`/`build` from a lane: compose project `cyberlab` is shared.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" = "--print-lock-root" ]; then
  echo "${LANE_LOCK_ROOT:-${TMPDIR:-${TEMP:-/tmp}}/cyberlab-lane-slots}"
  exit 0
fi

lane="${1:?lane number 2..7}"
shift
case "$lane" in [2-7]) ;; *) echo "lane must be 2..7" >&2; exit 2 ;; esac

service="api-test"
if [ "${1:-}" = "--service" ]; then
  service="${2:?--service needs a test-profile service name}"
  shift 2
fi
case "$service" in
  api-test|report-worker-test) ;;
  *) echo "unsupported lane service: $service" >&2; exit 2 ;;
esac

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
slot=""
while [ -z "$slot" ]; do
  for i in $(seq 1 "$slots"); do
    if mkdir "$lock_root/slot-$i" 2>/dev/null; then slot="$lock_root/slot-$i"; break; fi
  done
  [ -n "$slot" ] || sleep 5
done
trap 'rmdir "$slot" 2>/dev/null || true' EXIT INT TERM

export TEST_BROKER_DB="$lane" MSYS_NO_PATHCONV=1
if [ "$service" = "api-test" ]; then
  docker compose --profile test run --rm --no-deps \
    -e DATABASE_URL="$app_url" \
    -e MIGRATION_DATABASE_URL="$owner_url" \
    -e TEST_MIGRATION_DATABASE_URL="$owner_url" \
    -e REDIS_URL="$redis_url" \
    -e RETENTION_TEST_DATABASE_URL="$retention_url" \
    api-test "$@"
else
  # The renderer holds no DB or app Redis settings: only the lane's broker db, which
  # compose interpolates into its BROKER_URL through TEST_BROKER_DB.
  docker compose --profile test run --rm --no-deps "$service" "$@"
fi
