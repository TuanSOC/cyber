#!/bin/sh
# Idempotent M7 role bootstrap (superuser): creates or updates `cyberlab_retention`, the
# least-privilege role of the retention worker, and lets it connect to the app, test and lane
# databases. Run by the one-shot `db-bootstrap` service before `migrate` (existing volumes,
# lanes, restores) and by `init/02-m7-roles.sh` on a fresh volume. Migration 0014 grants the
# table privileges and refuses to run while the role is missing.
# Passwords are passed as psql variables (:'name' quoting), never pasted into SQL.
set -eu

: "${POSTGRES_RETENTION_PASSWORD:?set POSTGRES_RETENTION_PASSWORD}"

psql -v ON_ERROR_STOP=1 --no-psqlrc --username "${PGUSER:-${POSTGRES_USER:-postgres}}" \
  --dbname postgres -v retention_pw="$POSTGRES_RETENTION_PASSWORD" <<'EOSQL'
SELECT 'CREATE ROLE cyberlab_retention LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE'
WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'cyberlab_retention')
\gexec
ALTER ROLE cyberlab_retention LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION
  PASSWORD :'retention_pw';
ALTER ROLE cyberlab_retention SET statement_timeout = '30s';
ALTER ROLE cyberlab_retention SET idle_in_transaction_session_timeout = '60s';

-- The app and test databases plus every lane database that exists (cyberlab_b<N>_test).
SELECT format('GRANT CONNECT ON DATABASE %I TO cyberlab_retention', datname)
FROM pg_catalog.pg_database
WHERE datname IN ('cyberlab', 'cyberlab_test') OR datname ~ '^cyberlab_b[0-9]+_test$'
\gexec
EOSQL

echo "db-bootstrap: role cyberlab_retention ok"
