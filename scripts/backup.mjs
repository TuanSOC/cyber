#!/usr/bin/env node
// `pnpm backup [-- --out <dir>] [--prod] [--force] [--project <name>] [--drain-timeout <s>]`
// (M7 phase 2): an offline, quiesced, single-node backup of Postgres and the MinIO volume.
//
//  1. Preconditions: the stack is up and healthy; no test-profile or `compose run` container
//     of the project runs (they share MinIO and Postgres, RT21); the output dir is not
//     tracked by git and not inside .secrets; free disk >= 1.2 x (pgdata + MinIO volume)
//     (else --force).
//  2. Drain (RT21): wait until no analysis job, TI run, AI run, render or retention run is
//     queued / running (10 min, then refuse unless --force); stop the writers.
//  3. As the superuser: pg_dump -Fc (FORCE RLS binds the owner), the globals without role
//     passwords, the catalog fingerprint (security.json) and the exact row counts
//     (tables.json, no content digests, RT4).
//  4. objects.json with MinIO still up: every version of the evidence, results and reports
//     buckets with its size, etag, retention and legal hold (RT4).
//  5. Stop MinIO and tar its volume (read-only mount, --numeric-owner, relative to the data
//     dir so it extracts into another image's dir, RT25).
//  6. manifest.json: sha256 and bytes per file, alembic head, image ids, MinIO image and data
//     dir, EVIDENCE_LOCK_DAYS, the KMS key name and fingerprint (never the key, RT7).
//     With BACKUP_MANIFEST_KEY set, also manifest.json.hmac (HMAC-SHA256 of the manifest
//     bytes). Without it the manifest proves integrity only, not authenticity: anyone who can
//     write the backup can rewrite it to match (see lib/stack.mjs, MANIFEST_HMAC_FILE).
//     The output dir is created 0700, every file is written owner-only (helpers run with
//     umask 077 and chown their output to the host user on a POSIX host).
//  7. Restart what was running (always, even after a failure) and print what the backup
//     holds (RT6) and the secrets checklist.
import { chmodSync, mkdirSync, readFileSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";

import {
  BACKUP_UMASK,
  Compose,
  HostDir,
  MANIFEST_HMAC_FILE,
  REPO_ROOT,
  StackError,
  composeFiles,
  exec,
  formatBytes,
  isMain,
  kmsFingerprint,
  loadEnv,
  manifestKey,
  need,
  parseArgs,
  psql,
  pgTool,
  runHelper,
  signManifest,
  startAll,
  stopWriters,
  volumeBytes,
  volumeName,
} from "./lib/stack.mjs";

export const BACKUP_FILES = ["postgres.dump", "globals.sql", "security.json", "tables.json", "objects.json", "minio-data.tar"];
const TEST_SERVICE = /(-test$|^ai-mock$|^ti-mock$|^e2e$)/;
// In-flight work by the system lookups (superuser: no RLS). TI and AI runs also wait.
const DRAIN_SQL = `SELECT json_build_object(
  'analysis_jobs', (SELECT count(*) FROM analysis_job_index WHERE status IN ('queued', 'running')),
  'ti_runs', (SELECT count(*) FROM ti_run_index WHERE status IN ('queued', 'running', 'waiting')),
  'ai_runs', (SELECT count(*) FROM ai_run_index WHERE status IN ('queued', 'running', 'waiting')),
  'renders', (SELECT count(*) FROM report_render_index WHERE status IN ('queued', 'running')),
  'retention_runs', (SELECT count(*) FROM retention_runs WHERE status IN ('queued', 'running'))
)::text;`;

function utcStamp(date = new Date()) {
  return date.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
}

function step(title) {
  console.log(`\n▶ ${title}`);
}

// The compose model facts a backup and a restore both need.
export function stackFacts(compose) {
  const config = compose.config();
  const minio = config.services?.minio ?? {};
  const dataMount = (minio.volumes ?? []).find((v) => v.source === "miniodata");
  const kmsFile = config.secrets?.minio_kms_key?.file;
  return {
    config,
    images: {
      api: config.services?.api?.image,
      minio: minio.image,
      postgres: config.services?.postgres?.image,
    },
    minioImage: minio.image,
    minioDataDir: dataMount?.target ?? "/bitnami/minio/data",
    evidenceLockDays: Number(config.services?.api?.environment?.EVIDENCE_LOCK_DAYS ?? 0),
    kmsFile: kmsFile ? (isAbsolute(kmsFile) ? kmsFile : resolve(REPO_ROOT, kmsFile)) : null,
  };
}

function imageId(image) {
  if (!image) return null;
  const out = exec("docker", ["image", "inspect", "--format", "{{.Id}}", image], { capture: true, allowFail: true, quiet: true });
  return out.status === 0 ? out.stdout.toString().trim() : null;
}

export function checkOutputDir(dir) {
  const rel = relative(REPO_ROOT, dir);
  const inside = rel && !rel.startsWith("..") && !isAbsolute(rel);
  if (inside) {
    if (rel.split(sep)[0] === ".secrets" || rel.split(/[\\/]/)[0] === ".secrets") {
      throw new StackError(`refusing ${dir}: inside .secrets`, 2);
    }
    const ignored = exec("git", ["check-ignore", "-q", rel], { capture: true, allowFail: true, quiet: true });
    if (ignored.status !== 0) throw new StackError(`refusing ${dir}: git would track it (use backups/ or a path outside the repo)`, 2);
  }
}

// Creates the backup dir owner-only (0700; an existing dir is tightened to 0700). On Windows
// chmod only toggles read-only, so the ACL of the parent applies there.
export function prepareOutputDir(dir, { platform = process.platform } = {}) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (platform !== "win32") chmodSync(dir, 0o700);
  return dir;
}

function preconditions(compose) {
  const containers = compose.ps();
  for (const service of ["postgres", "minio"]) {
    const c = containers.find((x) => x.Service === service);
    if (!c || c.State !== "running" || (c.Health && c.Health !== "healthy")) {
      throw new StackError(`${service} is not up and healthy in project ${compose.project}`, 2);
    }
  }
  const unhealthy = containers.filter((c) => c.State === "running" && c.Health && c.Health !== "healthy");
  if (unhealthy.length) throw new StackError(`unhealthy: ${unhealthy.map((c) => c.Service).join(", ")}`, 2);
  const ids = exec("docker", ["ps", "-q", "--filter", `label=com.docker.compose.project=${compose.project}`], { capture: true, quiet: true })
    .stdout.toString().split(/\s+/).filter(Boolean);
  if (!ids.length) return;
  const inspected = JSON.parse(exec("docker", ["inspect", ...ids], { capture: true, quiet: true }).stdout.toString());
  const blockers = inspected.filter((c) => {
    const labels = c.Config?.Labels ?? {};
    return labels["com.docker.compose.oneoff"] === "True" || TEST_SERVICE.test(labels["com.docker.compose.service"] ?? "");
  });
  if (blockers.length) {
    throw new StackError(`test-profile or 'compose run' containers share MinIO and Postgres (RT21): ${blockers.map((c) => c.Name.replace(/^\//, "")).join(", ")}`, 2);
  }
}

function inFlight(project, env) {
  const out = psql(project, DRAIN_SQL, { password: need(env, "POSTGRES_PASSWORD") });
  const counts = JSON.parse(out.stdout);
  return Object.fromEntries(Object.entries(counts).filter(([, n]) => Number(n) > 0));
}

function drain(project, env, { timeoutS, force }) {
  const deadline = Date.now() + timeoutS * 1000;
  for (;;) {
    const busy = inFlight(project, env);
    if (!Object.keys(busy).length) return {};
    if (Date.now() >= deadline) {
      const what = Object.entries(busy).map(([k, n]) => `${k}=${n}`).join(", ");
      if (!force) throw new StackError(`still in flight after ${timeoutS}s: ${what} (wait, or pass --force)`, 2);
      console.log(`  --force: backing up with in-flight work (${what}); the reapers will fail it after a restore`);
      return busy;
    }
    console.log(`  waiting for in-flight work: ${JSON.stringify(busy)}`);
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10_000);
  }
}

function printContents(location, sizes, seconds) {
  console.log(`\n✔ backup written to ${location.label} in ${seconds.toFixed(0)} s`);
  for (const [name, fact] of Object.entries(sizes)) console.log(`    ${name.padEnd(16)} ${formatBytes(fact.bytes)}`);
  console.log(`
What this backup holds (RT6) — treat it as TLP:RED:
  - every org's evidence (malware samples included; objects written before SSE-S3 are in
    clear in minio-data.tar), notes, reports, TI and AI results;
  - the argon2 password hashes and the refresh-token hashes;
  - the sealed TI / AI provider keys and MinIO's IAM store (users and policies).
  It holds no plaintext secret, but it is the prime exfiltration target. Keep it on an
  encrypted target excluded from antivirus (AV quarantines evidence bytes), e.g.
    age -r <recipient> -o backup.tar.age <(tar -C <backup dir> -cf - .)

Secrets checklist (NOT in the backup; store them separately, encrypted):
  - .env (DB, MinIO, broker passwords, JWT_SECRET);
  - .secrets/*: the TI and AI seal private keys (without them the sealed provider keys are
    unrecoverable), the report signing keys, the MinIO KMS key (without it MinIO cannot read
    its IAM, config or any SSE object, RT7), the metrics token.
    tar -C . -cf - .env .secrets | age -r <recipient> -o cyberlab-secrets.tar.age`);
}

// Runs a backup into `location` (HostDir or DockerVolume). `restart: false` skips the
// final restart (the drill tears the project down anyway). Returns the manifest and timings.
export async function runBackup({ compose, location, env = loadEnv(), force = false, drainTimeoutS = 600, restart = true }) {
  const started = Date.now();
  const project = compose.project;
  const facts = stackFacts(compose);
  if (!facts.kmsFile) throw new StackError("the compose model has no minio_kms_key secret file", 2);
  const kms = kmsFingerprint(facts.kmsFile);
  const rootEnv = { RESTORE_MINIO_ACCESS_KEY: need(env, "MINIO_ROOT_USER"), RESTORE_MINIO_SECRET_KEY: need(env, "MINIO_ROOT_PASSWORD") };
  const password = need(env, "POSTGRES_PASSWORD");
  const signingKey = manifestKey(env); // validated before anything stops

  step(`Preconditions (project ${project})`);
  preconditions(compose);
  const [pgBytes, minioBytes] = volumeBytes([volumeName(project, "pgdata"), volumeName(project, "miniodata")]);
  const free = location.freeBytes();
  const needed = 1.2 * (pgBytes + minioBytes);
  console.log(`  pgdata ${formatBytes(pgBytes)}, MinIO ${formatBytes(minioBytes)}, free at the target ${formatBytes(free)}`);
  if (free < needed) {
    if (!force) throw new StackError(`free disk ${formatBytes(free)} < 1.2 x volumes (${formatBytes(needed)}); free space or pass --force`, 2);
    console.log("  --force: continuing with little free disk");
  }

  let running = [];
  let stopped = false;
  try {
    step("Drain in-flight work (RT21), then stop the writers");
    const forced = drain(project, env, { timeoutS: drainTimeoutS, force });
    running = compose.runningServices();
    stopped = true;
    stopWriters(compose);

    step("Postgres: dump, globals, catalog fingerprint, row counts (superuser)");
    const mount = [location.mount("/backup")];
    const ownerOnly = { umask: BACKUP_UMASK, chown: location.owner("/backup") ?? undefined };
    pgTool(project, ["pg_dump", "-h", "postgres", "-U", "postgres", "-d", "cyberlab", "-Fc", "-f", "/backup/postgres.dump"], { password, mounts: mount, ...ownerOnly });
    pgTool(project, ["pg_dumpall", "-h", "postgres", "-U", "postgres", "--globals-only", "--no-role-passwords", "-f", "/backup/globals.sql"], { password, mounts: mount, ...ownerOnly });
    const securitySql = readFileSync(resolve(REPO_ROOT, "infra/backup/security.sql"), "utf8");
    const tablesSql = readFileSync(resolve(REPO_ROOT, "infra/backup/tables.sql"), "utf8");
    const security = psql(project, securitySql, { password }).stdout;
    const tables = psql(project, tablesSql, { password }).stdout;
    JSON.parse(security);
    JSON.parse(tables);
    location.write("security.json", security);
    location.write("tables.json", tables);
    const head = psql(project, "SELECT version_num FROM alembic_version;", { password }).stdout;

    step("objects.json: every object version with retention and legal hold (MinIO still up)");
    const captured = compose.oneOff("api", ["python", "-m", "app.scripts.restore_verify", "--capture-objects"], { secretEnv: rootEnv });
    const objects = JSON.parse(captured.stdout);
    location.write("objects.json", JSON.stringify(objects));
    console.log(`  ${objects.objects.length} object versions`);

    step("MinIO: stop, then tar the data volume (read-only, --numeric-owner, dir-relative)");
    compose.run(["stop", "minio"]);
    runHelper({
      mounts: [{ type: "volume", source: volumeName(project, "miniodata"), target: "/data", readonly: true }, location.mount("/backup")],
      cmd: ["tar", "--numeric-owner", "-cf", "/backup/minio-data.tar", "-C", "/data", "."],
      ...ownerOnly,
    });

    step("manifest.json");
    const files = await location.facts(BACKUP_FILES);
    const images = Object.fromEntries(Object.entries(facts.images).map(([k, img]) => [k, imageId(img) ?? `missing:${img}`]));
    const built = compose.oneOff("api", ["python", "-m", "app.scripts.restore_verify", "--manifest-build"], {
      input: JSON.stringify({
        files,
        alembic_head: head,
        images,
        minio_image: facts.minioImage,
        minio_data_dir: facts.minioDataDir,
        evidence_lock_days: facts.evidenceLockDays,
        kms,
        source_project: project,
      }),
      allowFail: true,
    });
    const manifest = JSON.parse(built.stdout);
    if (built.status !== 0) throw new StackError(`manifest: ${manifest.error ?? built.stderr}`);
    if (Object.keys(forced).length) manifest.forced_in_flight = forced;
    const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2), "utf8");
    location.write("manifest.json", manifestBytes);
    if (signingKey) {
      location.write(MANIFEST_HMAC_FILE, signManifest(manifestBytes, signingKey));
      console.log(`  ${MANIFEST_HMAC_FILE}: HMAC-SHA256 with BACKUP_MANIFEST_KEY (keep the key apart from the backup)`);
    } else {
      console.log("  manifest unsigned (BACKUP_MANIFEST_KEY unset): its hashes prove integrity, not authenticity");
    }
    const seconds = (Date.now() - started) / 1000;
    printContents(location, files, seconds);
    return { manifest, seconds };
  } finally {
    if (stopped && restart) {
      step("Restart the services that were running");
      try {
        startAll(compose, [...new Set([...running, "minio"])]);
      } catch (error) {
        console.error(`✖ restart failed: ${error.message}`);
        process.exitCode = 1;
      }
    }
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2), { flags: ["prod", "force"], options: ["out", "project", "drain-timeout"] });
  const env = loadEnv();
  const project = args.project ?? process.env.COMPOSE_PROJECT_NAME ?? "cyberlab";
  const compose = new Compose({ project, files: composeFiles({ prod: Boolean(args.prod) }) });
  const dir = args.out ? resolve(args.out) : resolve(REPO_ROOT, env.BACKUP_DIR ?? "backups", utcStamp());
  checkOutputDir(dir);
  prepareOutputDir(dir);
  await runBackup({
    compose,
    location: new HostDir(dir),
    env,
    force: Boolean(args.force),
    drainTimeoutS: args["drain-timeout"] !== undefined ? Number(args["drain-timeout"]) : 600,
  });
}

if (isMain(import.meta.url)) {
  main().catch((error) => {
    console.error(`\n✖ backup failed: ${error.message}`);
    process.exit(error.exitCode ?? 1);
  });
}
