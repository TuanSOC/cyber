#!/usr/bin/env node
// `pnpm restore -- --from <dir> --replace-empty-stack [--keep-sessions] [--prod] [--project <p>]`
// (M7 phase 2): rebuild an EMPTY stack from a `pnpm backup` directory, verified in three
// phases (restore_verify --db / --objects / --rls, RT4).
//
//  1. Verify manifest.json and every file hash, the configured KMS key fingerprint (RT7) and
//     that this image knows the backup's alembic head (a newer backup is refused), all
//     before anything is restored. The manifest proves INTEGRITY, not AUTHENTICITY: it is not
//     signed, so whoever can write the backup dir can rewrite it to match altered files, and
//     pg_restore runs as the superuser. Restore only backups you produced and stored on a
//     trusted target. With BACKUP_MANIFEST_KEY set (kept apart from the backup), the restore
//     also requires manifest.json.hmac to verify (HMAC-SHA256) and refuses otherwise (exit 2).
//  2. Require empty volumes (pgdata missing or without alembic_version in `cyberlab`; MinIO
//     without .minio.sys); otherwise print the `docker compose down -v` command and exit 3.
//     This script never removes a volume.
//  3. postgres alone (its init creates the DBs and roles), db-bootstrap, then pg_restore
//     --exit-on-error --single-transaction as the superuser, then restore_verify --db at once.
//  4. Untar the MinIO volume as root (--numeric-owner) into the target image's data dir,
//     start minio, minio-init, then restore_verify --objects.
//  5. migrate; revoke every refresh token as the owner (unless --keep-sessions); start the
//     stack; restore_verify --rls; print the DR note (rotate JWT_SECRET after an incident).
import { resolve } from "node:path";

import { BACKUP_FILES, stackFacts } from "./backup.mjs";
import {
  Compose,
  HostDir,
  StackError,
  checkManifestAuthenticity,
  composeFiles,
  isMain,
  kmsFingerprint,
  loadEnv,
  need,
  parseArgs,
  pgTool,
  psql,
  runHelper,
  superuserUrl,
  volumeExists,
  volumeName,
} from "./lib/stack.mjs";

const REVOKE_SQL = `WITH revoked AS (
  UPDATE refresh_tokens SET revoked_at = now(), revoked_reason = 'logout'
  WHERE revoked_at IS NULL RETURNING 1
) SELECT count(*) FROM revoked;`;

function step(title) {
  console.log(`\n▶ ${title}`);
}

// restore_verify in a one-off api container; throws with the findings on any error.
function verify(compose, args, { input, secretEnv }) {
  const out = compose.oneOff("api", ["python", "-m", "app.scripts.restore_verify", ...args], { input, secretEnv, allowFail: true });
  let result;
  try {
    result = JSON.parse(out.stdout.trim().split("\n").at(-1));
  } catch {
    throw new StackError(`restore_verify ${args[0]}: no JSON report (exit ${out.status})\n${out.stderr.slice(-2000)}`);
  }
  if (result.error) throw new StackError(`restore_verify ${args[0]}: ${result.error}`);
  const warnings = result.findings?.filter((f) => f.severity === "warning") ?? [];
  for (const w of warnings) console.log(`  warning ${w.check}/${w.code} ${JSON.stringify(w.detail)}`);
  if (out.status !== 0 || !result.ok) {
    const errs = (result.findings ?? []).filter((f) => f.severity === "error").slice(0, 40);
    throw new StackError(`restore_verify ${args[0]} failed (${result.errors} error(s)):\n${errs.map((f) => `    ${f.check}/${f.code} ${JSON.stringify(f.detail)}`).join("\n")}`);
  }
  console.log(`  ✔ ${args[0]} clean ${JSON.stringify(result.stats ?? {})}`);
  return result;
}

function downCommand(compose) {
  return ["docker", ...compose.args(["down", "-v"])].join(" ");
}

function minioVolumeEmpty(project) {
  const name = volumeName(project, "miniodata");
  if (!volumeExists(name)) return true;
  const probe = runHelper({ mounts: [{ type: "volume", source: name, target: "/data", readonly: true }], cmd: ["test", "-e", "/data/.minio.sys"], allowFail: true, quiet: true });
  return probe.status !== 0;
}

// Restores `location` (HostDir or DockerVolume) into the empty stack of `compose`.
// `services`: what to start at the end (empty: every default service). Returns the reports.
export async function runRestore({ compose, location, env = loadEnv(), keepSessions = false, services = [], sample }) {
  const started = Date.now();
  const timings = {};
  const project = compose.project;
  const password = need(env, "POSTGRES_PASSWORD");
  const verifyEnv = {
    RESTORE_DATABASE_URL: superuserUrl(env),
    RESTORE_MINIO_ACCESS_KEY: need(env, "MINIO_ROOT_USER"),
    RESTORE_MINIO_SECRET_KEY: need(env, "MINIO_ROOT_PASSWORD"),
  };
  const facts = stackFacts(compose);
  if (!facts.kmsFile) throw new StackError("the compose model has no minio_kms_key secret file", 2);

  step(`Manifest, file hashes, KMS key fingerprint, alembic head (${location.label})`);
  if (!location.exists("manifest.json")) throw new StackError(`no manifest.json in ${location.label}`, 2);
  const manifestBytes = location.read("manifest.json");
  // Authenticity first (when a key is configured), then integrity against that manifest.
  checkManifestAuthenticity(location, manifestBytes, env);
  const manifest = JSON.parse(manifestBytes.toString());
  const files = await location.facts([...new Set([...BACKUP_FILES, ...Object.keys(manifest.files ?? {})])]);
  const kms = kmsFingerprint(facts.kmsFile);
  const checked = verify(compose, ["--manifest-check"], { input: JSON.stringify({ manifest, files, kms_fingerprint: kms.fingerprint }), secretEnv: {} });
  if (facts.minioDataDir !== manifest.minio_data_dir) {
    console.log(`  MinIO data dir ${manifest.minio_data_dir} -> ${facts.minioDataDir} (${facts.minioImage}); the tar is dir-relative (RT25)`);
  }

  step("Empty volumes only");
  if (!minioVolumeEmpty(project)) {
    throw new StackError(`the MinIO volume ${volumeName(project, "miniodata")} is not empty (.minio.sys). Remove the stack's volumes deliberately first:\n    ${downCommand(compose)}`, 3);
  }
  compose.run(["up", "-d", "--no-build", "postgres"]);
  compose.waitHealthy(["postgres"]);
  const hasSchema = psql(project, "SELECT to_regclass('public.alembic_version') IS NOT NULL;", { password }).stdout;
  if (hasSchema === "t") {
    throw new StackError(`the database cyberlab is not empty (alembic_version exists). Remove the stack's volumes deliberately first:\n    ${downCommand(compose)}`, 3);
  }

  step("db-bootstrap (roles), pg_restore (single transaction, superuser)");
  compose.oneOff("db-bootstrap", []);
  const t0 = Date.now();
  pgTool(project, ["pg_restore", "-h", "postgres", "-U", "postgres", "-d", "cyberlab", "--exit-on-error", "--single-transaction", "--no-password", "/backup/postgres.dump"], {
    password,
    mounts: [location.mount("/backup", true)],
  });
  timings.pg_restore_s = (Date.now() - t0) / 1000;

  step("restore_verify --db: fingerprint and row counts, before anything writes (RT4)");
  const baseline = { security: JSON.parse(location.read("security.json").toString()), tables: JSON.parse(location.read("tables.json").toString()) };
  const t1 = Date.now();
  const db = verify(compose, ["--db", "--baseline", "-"], { input: JSON.stringify(baseline), secretEnv: verifyEnv });
  timings.verify_db_s = (Date.now() - t1) / 1000;

  step("MinIO: untar into the empty volume (root, --numeric-owner), start, minio-init");
  compose.run(["create", "--no-build", "minio"]);
  runHelper({
    mounts: [{ type: "volume", source: volumeName(project, "miniodata"), target: "/data" }, location.mount("/backup", true)],
    cmd: ["tar", "--numeric-owner", "-xpf", "/backup/minio-data.tar", "-C", "/data"],
  });
  compose.run(["up", "-d", "--no-build", "--no-deps", "minio"]);
  compose.waitHealthy(["minio"]);
  compose.oneOff("minio-init", []);

  step("restore_verify --objects: versions, retention, legal holds, hashes, signatures");
  const objectsBaseline = location.read("objects.json").toString();
  const t2 = Date.now();
  const objects = verify(compose, ["--objects", "--baseline", "-", ...(sample ? ["--sample", String(sample)] : [])], { input: objectsBaseline, secretEnv: verifyEnv });
  timings.verify_objects_s = (Date.now() - t2) / 1000;

  step("migrate");
  compose.oneOff("migrate", []);

  if (keepSessions) {
    console.log("\n▶ --keep-sessions: refresh tokens kept");
  } else {
    step("Revoke every refresh token (as the owner)");
    const revoked = psql(project, REVOKE_SQL, { user: "cyberlab_owner", password: need(env, "POSTGRES_OWNER_PASSWORD") }).stdout;
    // auth_event_type has no restore value: the count is logged here instead.
    console.log(`  revoked ${revoked} refresh token(s)`);
  }

  step("Start the stack, then restore_verify --rls");
  compose.run(["up", "-d", "--no-build", ...services]);
  compose.waitHealthy(services.length ? services : ["api"]);
  const t3 = Date.now();
  const rls = verify(compose, ["--rls"], { secretEnv: verifyEnv });
  timings.verify_rls_s = (Date.now() - t3) / 1000;
  timings.total_s = (Date.now() - started) / 1000;

  console.log(`
✔ restore complete in ${timings.total_s.toFixed(0)} s (backup of ${manifest.created_at}, head ${manifest.alembic_head})
DR note: when restoring after an incident, rotate JWT_SECRET now. Redis is not restored, so
access tokens logged out after the backup are valid again until they expire (RT26).
After restoring an older backup, run the retention sweep again (purges are not retroactive).`);
  return { manifest: checked, db, objects, rls, timings };
}

async function main() {
  const args = parseArgs(process.argv.slice(2), { flags: ["replace-empty-stack", "keep-sessions", "prod"], options: ["from", "project", "sample"] });
  if (!args.from) throw new StackError("usage: pnpm restore -- --from <backup dir> --replace-empty-stack [--keep-sessions] [--prod]", 2);
  if (!args["replace-empty-stack"]) throw new StackError("--replace-empty-stack is required: a restore only fills an empty stack", 2);
  const project = args.project ?? process.env.COMPOSE_PROJECT_NAME ?? "cyberlab";
  const compose = new Compose({ project, files: composeFiles({ prod: Boolean(args.prod) }) });
  await runRestore({
    compose,
    location: new HostDir(resolve(args.from)),
    keepSessions: Boolean(args["keep-sessions"]),
    sample: args.sample ? Number(args.sample) : undefined,
  });
}

if (isMain(import.meta.url)) {
  main().catch((error) => {
    console.error(`\n✖ restore failed: ${error.message}`);
    process.exit(error.exitCode ?? 1);
  });
}
