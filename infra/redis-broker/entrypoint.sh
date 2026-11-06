#!/bin/sh
# Celery broker for analysis jobs: a separate Redis instance from the app Redis (token
# denylist, rate limits), with one ACL user per component and the default user disabled.
# Nothing is persisted: a lost queue only loses jobs, which the reaper then fails.
set -eu

: "${BROKER_API_PASSWORD:?}" "${BROKER_INGEST_PASSWORD:?}" "${BROKER_PCAP_PASSWORD:?}"
: "${BROKER_STATIC_PASSWORD:?}" "${BROKER_ENRICH_PASSWORD:?}" "${BROKER_ANALYST_PASSWORD:?}"
: "${BROKER_REPORT_PASSWORD:?}" "${BROKER_RETENTION_PASSWORD:?}" "${BROKER_MEMORY_PASSWORD:?}"
: "${BROKER_DISK_PASSWORD:?}" "${BROKER_REVERSE_PASSWORD:?}"

# Commands no component needs and that would let one inspect or disrupt others' queues.
DENY="-@dangerous -@admin -keys -scan -randomkey -sort -dump -object"
READ_DENY="-lrange -lindex -hgetall -hscan -hkeys -hvals -hrandfield"

# An untrusted analyzer user only touches keys it must (dev queues + "test." queues):
#   its own queue and unacked keys (read/write), the ingest queue (write only: it can add
#   reports but never read others'), and kombu bindings (its own read/write, ingest's read).
analyzer_keys() {
  keys="resetkeys ~$1* ~test.$1*"
  for q in "$1" "test.$1"; do
    keys="$keys ~_kombu.binding.$q ~_kombu.binding_permanent.$q"
  done
  keys="$keys %W~ingest* %W~test.ingest*"
  for q in ingest test.ingest; do
    keys="$keys %R~_kombu.binding.$q %R~_kombu.binding_permanent.$q"
  done
  echo "$keys"
}

# The trusted enrich worker (M4) is internet-facing, so it gets no trusted.* or ingest* keys
# (ingest messages carry per-job tokens): only its queue, its unacked keys, its slice
# re-publish and its limiter keys (`enrich.ti:*`), all under enrich* / test.enrich*.
enrich_keys() {
  keys="resetkeys ~enrich* ~test.enrich*"
  for q in enrich test.enrich; do
    keys="$keys ~_kombu.binding.$q ~_kombu.binding_permanent.$q"
  done
  echo "$keys"
}

# The trusted AI analyst worker (M5) is internet-facing too: same confinement as enrich,
# under analyst* / test.analyst* (its queue, unacked keys and `analyst.ai:*` limiter and
# budget keys). It cannot touch enrich*, ingest* or trusted.*, and nothing but api / ingest
# (`~*`) can touch analyst*.
analyst_keys() {
  keys="resetkeys ~analyst* ~test.analyst*"
  for q in analyst test.analyst; do
    keys="$keys ~_kombu.binding.$q ~_kombu.binding_permanent.$q"
  done
  echo "$keys"
}

# The least-privilege retention worker (M7) is trusted but confined like enrich: only its
# queue and unacked keys under retention* / test.retention* (the beat and the api publish to
# it through their `~*` users). It cannot touch ingest*, trusted.* or any other queue.
retention_keys() {
  keys="resetkeys ~retention* ~test.retention*"
  for q in retention test.retention; do
    keys="$keys ~_kombu.binding.$q ~_kombu.binding_permanent.$q"
  done
  echo "$keys"
}

# The untrusted report renderer (M6) is analyzer-class: `analyzer_keys report` confines it to
# report* / test.report* (queue, unacked keys, bindings), write-only to ingest. Only api and
# ingest (`~*`) reach report*; no other user's patterns match it.
# The untrusted memory analyzer (M8) is an analyzer: `analyzer_keys memory` (memory* /
# test.memory*, write-only to ingest). The api publishes `memory.analyze` through `~*`.
# The untrusted disk analyzer (M9) is an analyzer: `analyzer_keys disk` (disk* / test.disk*,
# write-only to ingest*). The api publishes `disk.analyze` / `disk.export` through `~*`; the
# trusted ingest user (`~*`) hands results to `ingest_disk` and the disk ingest worker (same
# user) consumes it (RT9). Analyzers can write `ingest_disk` (it matches `ingest*`) but never
# read it; a `disk.ingest` message is re-authenticated by its per-job token like any report.
# The untrusted reverse-engineering analyzer (M10) is an analyzer: `analyzer_keys reverse`
# (reverse* / test.reverse*, write-only to ingest*). The api publishes `reverse.analyze`
# through `~*`.
cat >/tmp/users.acl <<EOF
user default off
user api on >${BROKER_API_PASSWORD} ~* resetchannels +@all ${DENY}
user ingest on >${BROKER_INGEST_PASSWORD} ~* resetchannels +@all ${DENY}
user pcap on >${BROKER_PCAP_PASSWORD} $(analyzer_keys pcap) resetchannels +@all ${DENY} ${READ_DENY}
user static on >${BROKER_STATIC_PASSWORD} $(analyzer_keys static) resetchannels +@all ${DENY} ${READ_DENY}
user enrich on >${BROKER_ENRICH_PASSWORD} $(enrich_keys) resetchannels +@all ${DENY} ${READ_DENY}
user analyst on >${BROKER_ANALYST_PASSWORD} $(analyst_keys) resetchannels +@all ${DENY} ${READ_DENY}
user report on >${BROKER_REPORT_PASSWORD} $(analyzer_keys report) resetchannels +@all ${DENY} ${READ_DENY}
user retention on >${BROKER_RETENTION_PASSWORD} $(retention_keys) resetchannels +@all ${DENY} ${READ_DENY}
user memory on >${BROKER_MEMORY_PASSWORD} $(analyzer_keys memory) resetchannels +@all ${DENY} ${READ_DENY}
user disk on >${BROKER_DISK_PASSWORD} $(analyzer_keys disk) resetchannels +@all ${DENY} ${READ_DENY}
user reverse on >${BROKER_REVERSE_PASSWORD} $(analyzer_keys reverse) resetchannels +@all ${DENY} ${READ_DENY}
user healthcheck on nopass resetkeys +ping
EOF
chmod 600 /tmp/users.acl

exec redis-server --aclfile /tmp/users.acl --save "" --appendonly no --protected-mode no \
  --maxmemory 256mb --maxmemory-policy noeviction
