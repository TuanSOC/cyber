#!/bin/sh
# Celery broker for analysis jobs: a separate Redis instance from the app Redis (token
# denylist, rate limits), with one ACL user per component and the default user disabled.
# Nothing is persisted: a lost queue only loses jobs, which the reaper then fails.
set -eu

: "${BROKER_API_PASSWORD:?}" "${BROKER_INGEST_PASSWORD:?}" "${BROKER_PCAP_PASSWORD:?}"
: "${BROKER_STATIC_PASSWORD:?}" "${BROKER_ENRICH_PASSWORD:?}"

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

cat >/tmp/users.acl <<EOF
user default off
user api on >${BROKER_API_PASSWORD} ~* resetchannels +@all ${DENY}
user ingest on >${BROKER_INGEST_PASSWORD} ~* resetchannels +@all ${DENY}
user pcap on >${BROKER_PCAP_PASSWORD} $(analyzer_keys pcap) resetchannels +@all ${DENY} ${READ_DENY}
user static on >${BROKER_STATIC_PASSWORD} $(analyzer_keys static) resetchannels +@all ${DENY} ${READ_DENY}
user enrich on >${BROKER_ENRICH_PASSWORD} $(enrich_keys) resetchannels +@all ${DENY} ${READ_DENY}
user healthcheck on nopass resetkeys +ping
EOF
chmod 600 /tmp/users.acl

exec redis-server --aclfile /tmp/users.acl --save "" --appendonly no --protected-mode no \
  --maxmemory 256mb --maxmemory-policy noeviction
