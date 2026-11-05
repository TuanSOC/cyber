#!/usr/bin/env node
// `pnpm restore:drill [-- --prod] [--target-minio-image <img> [--target-minio-data-dir <dir>]]`
// (M7 phase 2; a heavy gate step, run ALONE): seed -> backup -> down -v -> restore -> verify ->
// HTTP checks, end to end in the compose project `cyberlab-drill` (about 1.2 GB).
//
// - Exclusive: takes every lane slot (LANE_LOCK_ROOT, as scripts/lane-test.sh, RT25) and
//   refuses while the main project's heavy services (analyzers, report worker) run.
// - The backup goes to the volume `cyberlab-drill_backups`, never to the host disk (RT6).
// - `down -v` only through stack.downVolumes("cyberlab-drill") (RT2); always at the end.
// - The timings, the drill containers' peak memory and the verify stats are written to
//   infra/backup/last-drill.json (gitignored; phase 11's metric).
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { runBackup } from "./backup.mjs";
import { runRestore } from "./restore.mjs";
import {
  Compose,
  DRILL_BACKUPS_VOLUME,
  DRILL_PROJECT,
  DockerVolume,
  HEAVY_SERVICES,
  REPO_ROOT,
  StackError,
  composeFiles,
  createDrillBackupsVolume,
  downVolumes,
  exec,
  isMain,
  loadEnv,
  lockAllSlots,
  need,
  parseArgs,
  removeDrillBackupsVolume,
} from "./lib/stack.mjs";

const DRILL_SERVICES = ["postgres", "redis", "redis-broker", "minio", "api"];
const LAST_DRILL = resolve(REPO_ROOT, "infra/backup/last-drill.json");

function step(title) {
  console.log(`\n■ drill: ${title}`);
}

function heavyMainServices() {
  const out = exec("docker", ["ps", "--filter", "label=com.docker.compose.project=cyberlab", "--format", "{{.Label \"com.docker.compose.service\"}}"], { capture: true, quiet: true });
  const running = out.stdout.toString().split(/\s+/).filter(Boolean);
  return running.filter((s) => HEAVY_SERVICES.includes(s));
}

// Sum of the drill containers' memory right now (MiB); the drill keeps the max of its samples.
function drillMemoryMiB() {
  const ids = exec("docker", ["ps", "-q", "--filter", `label=com.docker.compose.project=${DRILL_PROJECT}`], { capture: true, quiet: true })
    .stdout.toString().split(/\s+/).filter(Boolean);
  if (!ids.length) return 0;
  const out = exec("docker", ["stats", "--no-stream", "--format", "{{.MemUsage}}", ...ids], { capture: true, quiet: true, allowFail: true });
  const unit = { B: 1 / 1048576, KiB: 1 / 1024, MiB: 1, GiB: 1024, kB: 1 / 1024, MB: 1, GB: 1024 };
  let total = 0;
  for (const line of out.stdout.toString().split("\n")) {
    const m = line.trim().match(/^([\d.]+)\s*([A-Za-z]+)/);
    if (m) total += Number(m[1]) * (unit[m[2]] ?? 0);
  }
  return Math.round(total);
}

function pythonJson(compose, mode, { input, secretEnv }) {
  const out = compose.oneOff("api", ["python", "-m", "app.scripts.drill_seed", mode], { input, secretEnv, allowFail: true });
  let result;
  try {
    result = JSON.parse(out.stdout.trim().split("\n").at(-1));
  } catch {
    throw new StackError(`drill_seed ${mode}: no JSON (exit ${out.status})\n${out.stderr.slice(-3000)}`);
  }
  if (out.status !== 0 || result.error) throw new StackError(`drill_seed ${mode} failed: ${result.error ?? JSON.stringify(result.checks ?? result)}`);
  return result;
}

export async function runDrill({ prod = false, targetMinioImage, targetMinioDataDir } = {}) {
  const env = loadEnv();
  const started = Date.now();
  const timings = {};
  const memory = [];
  const files = composeFiles({ prod, drill: true });
  const compose = new Compose({ project: DRILL_PROJECT, files });
  const ownerUrl = `postgresql+asyncpg://cyberlab_owner:${encodeURIComponent(need(env, "POSTGRES_OWNER_PASSWORD"))}@postgres:5432/cyberlab`;
  const seedEnv = {
    DRILL_OWNER_DATABASE_URL: ownerUrl,
    DRILL_MINIO_ROOT_USER: need(env, "MINIO_ROOT_USER"),
    DRILL_MINIO_ROOT_PASSWORD: need(env, "MINIO_ROOT_PASSWORD"),
    // drill_seed refuses to run outside the drill project (review finding).
    CYBERLAB_DRILL: "1",
    CYBERLAB_DRILL_PROJECT: DRILL_PROJECT,
  };

  step("exclusive: main-project heavy services, lane slots");
  const heavy = heavyMainServices();
  if (heavy.length) throw new StackError(`stop the main project's heavy services first: ${heavy.join(", ")}`, 2);
  const slots = lockAllSlots();
  let result;
  try {
    step("clean start (leftovers of an interrupted drill)");
    downVolumes(DRILL_PROJECT, { files });
    removeDrillBackupsVolume();
    createDrillBackupsVolume();
    const location = new DockerVolume(DRILL_BACKUPS_VOLUME);

    step("up: postgres, redis, redis-broker, minio, minio-init, db-bootstrap, migrate, api");
    let t = Date.now();
    compose.run(["up", "-d", "--no-build", "api"]);
    compose.waitHealthy(DRILL_SERVICES);
    timings.up_s = (Date.now() - t) / 1000;

    step("seed through the API (one-off container on the drill network)");
    t = Date.now();
    const seed = pythonJson(compose, "seed", { secretEnv: seedEnv });
    timings.seed_s = (Date.now() - t) / 1000;
    memory.push(drillMemoryMiB());
    console.log(`  seeded orgs ${seed.orgs.a}, ${seed.orgs.b}; ${seed.evidence.length} evidence items, tombstone ${seed.tombstoned_evidence}`);

    step("backup into the drill volume (the seeded queued render is in flight: --force)");
    t = Date.now();
    const backup = await runBackup({ compose, location, env, force: true, drainTimeoutS: 0, restart: false });
    timings.backup_s = (Date.now() - t) / 1000;

    step("down -v (the backups volume is outside the model and stays)");
    downVolumes(DRILL_PROJECT, { files });

    let target = compose;
    if (targetMinioImage) {
      const dataDir = targetMinioDataDir ?? "/data";
      console.log(`  restoring into MINIO_IMAGE=${targetMinioImage} (MINIO_DATA_DIR=${dataDir})`);
      target = compose.with({ MINIO_IMAGE: targetMinioImage, MINIO_DATA_DIR: dataDir });
    }

    step("restore (restore_verify --db / --objects / --rls run inside)");
    t = Date.now();
    const restored = await runRestore({ compose: target, location, env, services: ["api"] });
    timings.restore_s = (Date.now() - t) / 1000;
    memory.push(drillMemoryMiB());
    for (const phase of ["manifest", "db", "objects", "rls"]) {
      if (!restored[phase]?.ok) throw new StackError(`restore_verify ${phase} is not clean`);
    }
    const warnings = restored.objects.findings.filter((f) => f.severity === "warning").map((f) => f.code);
    if (warnings.some((code) => code !== "purged_version_absent")) {
      throw new StackError(`unexpected object warnings: ${warnings.join(", ")}`);
    }
    if (!restored.objects.stats || restored.objects.stats.hashed < seed.evidence.length - 1) {
      throw new StackError(`only ${restored.objects.stats?.hashed} evidence objects re-hashed`);
    }

    step("HTTP checks: login after revocation, download, signature, 410, viewer 403");
    t = Date.now();
    const checks = pythonJson(compose, "check", { input: JSON.stringify(seed), secretEnv: seedEnv });
    timings.check_s = (Date.now() - t) / 1000;
    for (const c of checks.checks) console.log(`  ✔ ${c.check}`);
    memory.push(drillMemoryMiB());

    timings.verify_s = (restored.timings.verify_db_s ?? 0) + (restored.timings.verify_objects_s ?? 0) + (restored.timings.verify_rls_s ?? 0);
    result = {
      ok: true,
      finished_at: new Date().toISOString(),
      prod,
      target_minio_image: targetMinioImage ?? null,
      timings: { ...timings, restore_detail: restored.timings, backup_tool_s: backup.seconds },
      peak_memory_mib: Math.max(...memory),
      stats: { db: restored.db.stats, objects: restored.objects.stats, rls: restored.rls.stats },
      warnings,
      checks: checks.checks.map((c) => c.check),
    };
  } catch (error) {
    result = { ok: false, finished_at: new Date().toISOString(), prod, target_minio_image: targetMinioImage ?? null, error: error.message, timings, peak_memory_mib: memory.length ? Math.max(...memory) : null };
    throw error;
  } finally {
    step("cleanup: down -v of cyberlab-drill and its backups volume (always, RT2)");
    try {
      downVolumes(DRILL_PROJECT, { files });
      removeDrillBackupsVolume();
    } catch (error) {
      console.error(`✖ cleanup failed: ${error.message}`);
      process.exitCode = 1;
    }
    slots.release();
    if (result) {
      result.timings.total_s = (Date.now() - started) / 1000;
      writeFileSync(LAST_DRILL, `${JSON.stringify(result, null, 2)}\n`);
      console.log(`  wrote ${LAST_DRILL}`);
    }
  }
  console.log(`\n✔ restore drill passed in ${result.timings.total_s.toFixed(0)} s (backup ${timings.backup_s.toFixed(0)} s, restore ${timings.restore_s.toFixed(0)} s, verify ${timings.verify_s.toFixed(1)} s, peak ${result.peak_memory_mib} MiB)`);
  return result;
}

async function main() {
  const args = parseArgs(process.argv.slice(2), { flags: ["prod"], options: ["target-minio-image", "target-minio-data-dir"] });
  await runDrill({ prod: Boolean(args.prod), targetMinioImage: args["target-minio-image"], targetMinioDataDir: args["target-minio-data-dir"] });
}

if (isMain(import.meta.url)) {
  main().catch((error) => {
    console.error(`\n✖ restore drill failed: ${error.message}`);
    process.exit(error.exitCode ?? 1);
  });
}
