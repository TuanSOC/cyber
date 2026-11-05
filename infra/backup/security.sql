-- Catalog security fingerprint of the current database (M7 backup / restore_verify --db, RT4).
-- One JSON document on one line: row level security and its FORCE flag per table, the
-- policies, table / column / schema / function / default privileges, the non-internal
-- triggers, extensions, and the role attributes, memberships and settings of every non-pg_
-- role. No passwords, no row content. Every list is sorted, so two databases with the same
-- security state print the same text.
-- Run as the superuser: psql -At -v ON_ERROR_STOP=1 -f infra/backup/security.sql
-- KEEP IN SYNC: the statement (these comment lines aside) equals SECURITY_SQL in
-- apps/api/app/scripts/restore_verify.py (scripts/lib/stack.test.mjs checks it).
SELECT json_build_object(
  'database', (
    SELECT json_build_object(
      'owner', pg_get_userbyid(d.datdba),
      'acl', CASE WHEN d.datacl IS NULL THEN NULL ELSE (
        SELECT json_agg(a ORDER BY a) FROM unnest(d.datacl::text[]) AS a) END)
    FROM pg_database d WHERE d.datname = current_database()),
  'schemas', (
    SELECT coalesce(json_agg(json_build_object(
      'name', n.nspname,
      'owner', pg_get_userbyid(n.nspowner),
      'acl', CASE WHEN n.nspacl IS NULL THEN NULL ELSE (
        SELECT json_agg(a ORDER BY a) FROM unnest(n.nspacl::text[]) AS a) END
    ) ORDER BY n.nspname), '[]'::json)
    FROM pg_namespace n WHERE n.nspname = 'public'),
  'tables', (
    SELECT coalesce(json_agg(json_build_object(
      'name', c.relname,
      'kind', c.relkind::text,
      'owner', pg_get_userbyid(c.relowner),
      'rls', c.relrowsecurity,
      'force_rls', c.relforcerowsecurity,
      'acl', CASE WHEN c.relacl IS NULL THEN NULL ELSE (
        SELECT json_agg(a ORDER BY a) FROM unnest(c.relacl::text[]) AS a) END
    ) ORDER BY c.relname), '[]'::json)
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
      AND NOT EXISTS (
        SELECT 1 FROM pg_depend dep
        WHERE dep.classid = 'pg_class'::regclass AND dep.objid = c.oid AND dep.deptype = 'e')),
  'columns', (
    SELECT coalesce(json_agg(json_build_object(
      'table', c.relname,
      'column', a.attname,
      'acl', (SELECT json_agg(x ORDER BY x) FROM unnest(a.attacl::text[]) AS x)
    ) ORDER BY c.relname, a.attname), '[]'::json)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND a.attnum > 0 AND NOT a.attisdropped
      AND a.attacl IS NOT NULL),
  'policies', (
    SELECT coalesce(json_agg(json_build_object(
      'table', p.tablename,
      'name', p.policyname,
      'permissive', p.permissive,
      'roles', (SELECT json_agg(r ORDER BY r) FROM unnest(p.roles::text[]) AS r),
      'cmd', p.cmd,
      'qual', p.qual,
      'with_check', p.with_check
    ) ORDER BY p.tablename, p.policyname), '[]'::json)
    FROM pg_policies p WHERE p.schemaname = 'public'),
  'triggers', (
    SELECT coalesce(json_agg(json_build_object(
      'table', c.relname,
      'name', t.tgname,
      'enabled', t.tgenabled::text,
      'definition', pg_get_triggerdef(t.oid)
    ) ORDER BY c.relname, t.tgname), '[]'::json)
    FROM pg_trigger t
    JOIN pg_class c ON c.oid = t.tgrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND NOT t.tgisinternal),
  'functions', (
    SELECT coalesce(json_agg(json_build_object(
      'signature', p.oid::regprocedure::text,
      'owner', pg_get_userbyid(p.proowner),
      'security_definer', p.prosecdef,
      'config', (SELECT json_agg(x ORDER BY x) FROM unnest(p.proconfig) AS x),
      'acl', CASE WHEN p.proacl IS NULL THEN NULL ELSE (
        SELECT json_agg(x ORDER BY x) FROM unnest(p.proacl::text[]) AS x) END
    ) ORDER BY p.oid::regprocedure::text), '[]'::json)
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND NOT EXISTS (
        SELECT 1 FROM pg_depend dep
        WHERE dep.classid = 'pg_proc'::regclass AND dep.objid = p.oid AND dep.deptype = 'e')),
  'default_acl', (
    SELECT coalesce(json_agg(json_build_object(
      'role', pg_get_userbyid(d.defaclrole),
      'schema', coalesce(n.nspname, ''),
      'objtype', d.defaclobjtype::text,
      'acl', (SELECT json_agg(x ORDER BY x) FROM unnest(d.defaclacl::text[]) AS x)
    ) ORDER BY pg_get_userbyid(d.defaclrole), coalesce(n.nspname, ''), d.defaclobjtype::text),
      '[]'::json)
    FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace),
  'extensions', (
    SELECT coalesce(json_agg(json_build_object(
      'name', e.extname,
      'version', e.extversion,
      'schema', n.nspname
    ) ORDER BY e.extname), '[]'::json)
    FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace),
  'roles', (
    SELECT coalesce(json_agg(json_build_object(
      'name', r.rolname,
      'superuser', r.rolsuper,
      'inherit', r.rolinherit,
      'createrole', r.rolcreaterole,
      'createdb', r.rolcreatedb,
      'login', r.rolcanlogin,
      'replication', r.rolreplication,
      'bypassrls', r.rolbypassrls,
      'connlimit', r.rolconnlimit
    ) ORDER BY r.rolname), '[]'::json)
    FROM pg_roles r WHERE r.rolname !~ '^pg_'),
  'memberships', (
    SELECT coalesce(json_agg(json_build_object(
      'role', pg_get_userbyid(m.roleid),
      'member', pg_get_userbyid(m.member),
      'admin', m.admin_option
    ) ORDER BY pg_get_userbyid(m.roleid), pg_get_userbyid(m.member)), '[]'::json)
    FROM pg_auth_members m
    WHERE pg_get_userbyid(m.roleid) !~ '^pg_' OR pg_get_userbyid(m.member) !~ '^pg_'),
  'role_settings', (
    SELECT coalesce(json_agg(json_build_object(
      'role', CASE WHEN s.setrole = 0 THEN '' ELSE pg_get_userbyid(s.setrole) END,
      'database', CASE WHEN s.setdatabase = 0 THEN '' ELSE current_database() END,
      'settings', (SELECT json_agg(x ORDER BY x) FROM unnest(s.setconfig) AS x)
    ) ORDER BY CASE WHEN s.setrole = 0 THEN '' ELSE pg_get_userbyid(s.setrole) END,
      s.setdatabase), '[]'::json)
    FROM pg_db_role_setting s
    WHERE s.setdatabase IN (0, (SELECT oid FROM pg_database WHERE datname = current_database())))
)::text;
