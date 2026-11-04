#!/bin/sh
# Celery broker for analysis jobs: a separate Redis instance from the app Redis (token
# denylist, rate limits), with one ACL user per component and the default user disabled.
# Nothing is persisted: a lost queue only loses jobs, which the reaper then fails.
set -eu

: "${BROKER_API_PASSWORD:?}" "${BROKER_INGEST_PASSWORD:?}" "${BROKER_PCAP_PASSWORD:?}"

# Commands no component needs and that would let one inspect or disrupt others' queues.
DENY="-@dangerous -@admin -keys -scan -randomkey -sort -dump -object"

# The untrusted analyzer's user only touches keys it must (dev queues + "test." queues):
#   its own queue and unacked keys (read/write), the ingest queue (write only: it can add
#   reports but never read others'), and kombu bindings (its own read/write, ingest's read).
PCAP_KEYS="resetkeys ~pcap* ~test.pcap*"
for q in pcap test.pcap; do
  PCAP_KEYS="$PCAP_KEYS ~_kombu.binding.$q ~_kombu.binding_permanent.$q"
done
PCAP_KEYS="$PCAP_KEYS %W~ingest* %W~test.ingest*"
for q in ingest test.ingest; do
  PCAP_KEYS="$PCAP_KEYS %R~_kombu.binding.$q %R~_kombu.binding_permanent.$q"
done

cat >/tmp/users.acl <<EOF
user default off
user api on >${BROKER_API_PASSWORD} ~* resetchannels +@all ${DENY}
user ingest on >${BROKER_INGEST_PASSWORD} ~* resetchannels +@all ${DENY}
user pcap on >${BROKER_PCAP_PASSWORD} ${PCAP_KEYS} resetchannels +@all ${DENY} -lrange -lindex -hgetall -hscan -hkeys -hvals -hrandfield
user healthcheck on nopass resetkeys +ping
EOF
chmod 600 /tmp/users.acl

exec redis-server --aclfile /tmp/users.acl --save "" --appendonly no --protected-mode no \
  --maxmemory 256mb --maxmemory-policy noeviction
