#!/bin/sh
# Runs once, on an empty data volume only. After editing: docker compose down -v
# Passwords are passed as psql variables (:'name' quoting), never pasted into SQL.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v owner_pw="$POSTGRES_OWNER_PASSWORD" \
  -v app_pw="$POSTGRES_APP_PASSWORD" <<'EOSQL'
CREATE ROLE cyberlab_owner LOGIN PASSWORD :'owner_pw';
CREATE ROLE cyberlab_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
  PASSWORD :'app_pw';
ALTER ROLE cyberlab_app SET idle_in_transaction_session_timeout = '60s';
ALTER ROLE cyberlab_app SET statement_timeout = '30s';

CREATE DATABASE cyberlab OWNER cyberlab_owner;
CREATE DATABASE cyberlab_test OWNER cyberlab_owner;

REVOKE CONNECT ON DATABASE cyberlab FROM PUBLIC;
REVOKE CONNECT ON DATABASE cyberlab_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cyberlab TO cyberlab_app;
GRANT CONNECT ON DATABASE cyberlab_test TO cyberlab_app;
EOSQL
