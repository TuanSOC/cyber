#!/bin/sh
# Idempotent role bootstrap (superuser): creates or updates `cyberlab_retention` (M7), the
# least-privilege role of the retention worker, and `cyberlab_mail` (M11, RT9), the mail
# worker's role, and lets both connect to the app, test and lane databases. Run by the one-shot
# `db-bootstrap` service before `migrate` (existing volumes, lanes, restores) and by
# `init/02-m7-roles.sh` on a fresh volume. Migrations 0014 and 0019 grant the table privileges
# (the mail role: SELECT / UPDATE on `email_outbox` only) and refuse to run while a role is
# missing.
# Passwords are passed as psql variables (:'name' quoting), never pasted into SQL.
set -eu

: "${POSTGRES_RETENTION_PASSWORD:?set POSTGRES_RETENTION_PASSWORD}"
: "${POSTGRES_MAIL_PASSWORD:?set POSTGRES_MAIL_PASSWORD}"

psql -v ON_ERROR_STOP=1 --no-psqlrc --username "${PGUSER:-${POSTGRES_USER:-postgres}}" \
  --dbname postgres -v retention_pw="$POSTGRES_RETENTION_PASSWORD" \
  -v mail_pw="$POSTGRES_MAIL_PASSWORD" <<'EOSQL'
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

-- M11 (RT9): the mail worker reads and updates `email_outbox` only (grants in 0019).
SELECT 'CREATE ROLE cyberlab_mail LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE'
WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'cyberlab_mail')
\gexec
ALTER ROLE cyberlab_mail LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION
  PASSWORD :'mail_pw';
ALTER ROLE cyberlab_mail SET statement_timeout = '15s';
ALTER ROLE cyberlab_mail SET idle_in_transaction_session_timeout = '30s';
SELECT format('GRANT CONNECT ON DATABASE %I TO cyberlab_mail', datname)
FROM pg_catalog.pg_database
WHERE datname IN ('cyberlab', 'cyberlab_test') OR datname ~ '^cyberlab_b[0-9]+_test$'
\gexec
EOSQL

echo "db-bootstrap: roles cyberlab_retention and cyberlab_mail ok"
