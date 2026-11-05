-- Exact row count of every table of `public` (M7 backup / restore_verify --db, RT4): one JSON
-- object {table: count} on one line. No content digests: pg_restore --exit-on-error
-- --single-transaction is all-or-nothing, and an ordered digest hits the 1 GB text limit on
-- network_records and depends on TimeZone and float settings. Run as the superuser (FORCE RLS
-- binds every other role, so their counts would be filtered).
-- Run: psql -At -v ON_ERROR_STOP=1 -f infra/backup/tables.sql
-- KEEP IN SYNC: the statement (these comment lines aside) equals TABLES_SQL in
-- apps/api/app/scripts/restore_verify.py (scripts/lib/stack.test.mjs checks it).
SELECT coalesce(json_object_agg(
  c.relname,
  (xpath('/row/n/text()', query_to_xml(
    format('SELECT count(*) AS n FROM %I.%I', n.nspname, c.relname), false, true, '')))[1]
    ::text::bigint
  ORDER BY c.relname), '{}'::json)::text
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p');
