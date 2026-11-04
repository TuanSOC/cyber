#!/usr/bin/env bash
# Run api-test against an isolated test lane (parallel development agents).
#   scripts/lane-test.sh <lane 2..7> <command...>
#   e.g. scripts/lane-test.sh 3 uv run pytest -q -p no:cacheprovider tests/unit/test_ai_providers.py
# Lane N uses database cyberlab_bN_test, app Redis db N and broker db N, so lanes never
# truncate or purge each other's state. The default lane (cyberlab_test, db 1) is untouched.
# Never `up`/`down`/`build` from a lane: compose project `cyberlab` is shared.
set -euo pipefail
cd "$(dirname "$0")/.."

lane="${1:?lane number 2..7}"
shift
case "$lane" in [2-7]) ;; *) echo "lane must be 2..7" >&2; exit 2 ;; esac

env_value() { grep -E "^$1=" .env | head -n1 | cut -d= -f2-; }
db="cyberlab_b${lane}_test"
app_url="$(env_value TEST_DATABASE_URL | sed -E "s#/[^/]+\$#/${db}#")"
owner_url="$(env_value TEST_MIGRATION_DATABASE_URL | sed -E "s#/[^/]+\$#/${db}#")"
redis_url="$(env_value TEST_REDIS_URL | sed -E "s#/[0-9]+\$#/${lane}#")"

# At most LANE_SLOTS (default 3) lane containers at once: host memory is limited.
slots="${LANE_SLOTS:-3}"
lock_root="${TMPDIR:-${TEMP:-/tmp}}/cyberlab-lane-slots"
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
docker compose --profile test run --rm --no-deps \
  -e DATABASE_URL="$app_url" \
  -e MIGRATION_DATABASE_URL="$owner_url" \
  -e TEST_MIGRATION_DATABASE_URL="$owner_url" \
  -e REDIS_URL="$redis_url" \
  api-test "$@"
