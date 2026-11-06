#!/usr/bin/env node
// `node scripts/minio-switch.mjs <preflight | run | rollback> [--prod] [--lane <2..8>]
//   [--skip-attestation] [--backup-volume <name>]` (M7 phase 6): prepares the switch of the
// object store from the frozen bitnami MinIO build to pgsty/silo. It never switches by itself.
//
//  preflight  Checks only (read-only): the compose model still runs bitnami, the Silo files and
//             the candidate compose file exist, the pin matches, no COMPOSE_* variable is set, and
//             the provenance attestation verifies. It then prints the planned sequence.
//  run        Runs preflight, then:
//             1. builds the local wrapper image (infra/minio/silo/Dockerfile, FROM the pinned
//                digest);
//             2. takes `pnpm backup` into a NEW labelled Docker volume (RT6), the rollback
//                anchor, kept afterwards. Writers and MinIO stay stopped from here on, so the
//                backup stays current;
//             3. runs the conformance suite against the candidate in its isolated project
//                (infra/minio/image/docker-compose.candidate.yml), including RT7 prepare /
//                restart / verify. Only postgres, redis and the current MinIO are up for it.
//                It always ends with a guarded `down -v` of `cyberlab-objstore` only;
//             4. stops the main project and runs
//                `pnpm restore:drill -- --target-minio-image <wrapper> --target-minio-data-dir /data`;
//             5. only when all of that passed: writes infra/minio/silo/.env.silo (gitignored)
//                and prints the activation and the rollback.
//             On any failure nothing has switched: the stack still runs bitnami.
//  rollback   Restores the pre-switch backup volume onto the bitnami image (`pnpm restore`
//             reads only a host dir, so this is its Docker-volume twin). It requires .env
//             reverted to bitnami and an empty stack (restore refuses otherwise and prints the
//             `down -v` command). Silo cannot be downgraded in place, so this is the only way
//             back.
import { randomBytes } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { runBackup, stackFacts } from "./backup.mjs";
import { runDrill } from "./restore-drill.mjs";
import { runRestore } from "./restore.mjs";
import {
  Compose,
  DockerVolume,
  REPO_ROOT,
  StackError,
  childEnv,
  composeFiles,
  exec,
  isMain,
  loadEnv,
  lockAllSlots,
  parseArgs,
  runHelper,
  volumeName,
} from "./lib/stack.mjs";

// --- the pin (verified 2026-11-06 against the Docker Hub registry API and the GitHub attestation) -
export const SILO = Object.freeze({
  repository: "pgsty/silo",
  tag: "RELEASE.2026-10-26T00-00-00Z",
  // The multi-arch OCI index: the subject of the SLSA provenance attestation.
  indexDigest: "sha256:7bb2aff6b89efe1cb1303c10fc21d579447434ed06649ac9ec05a5e2dbf30ad7",
  // Its linux/amd64 image manifest (what Docker resolves on this host).
  amd64Digest: "sha256:003925ecebdcd659494621de84984f20aac2ca0ce88684ba23bb1e38b8e0db3c",
  signerWorkflow: "pgsty/silo/.github/workflows/docker-release.yml",
});
export const WRAPPER_IMAGE = `localhost/cyberlab/silo:${SILO.tag}`;
// uid 1001, gid 0: exactly bitnami's user. The bitnami volume root is root:root 0775, so new
// buckets are created through its group 0 write bit; 1001:1001 got AccessDenied (2026-11-06).
export const WRAPPER_USER = "1001:0";
export const SILO_DATA_DIR = "/data";
export const BITNAMI_DATA_DIR = "/bitnami/minio/data";
export const SILO_DIR = "infra/minio/silo";
export const SILO_OVERLAY = `${SILO_DIR}/docker-compose.silo.yml`;
export const ENV_SUGGESTION = `${SILO_DIR}/.env.silo`;
export const CANDIDATE_FILE = "infra/minio/image/docker-compose.candidate.yml";
export const CANDIDATE_PROJECT = "cyberlab-objstore";
export const MAIN_PROJECT = "cyberlab";
export const SWITCH_LABEL = "cyberlab.switch=pre-silo";
export const DEFAULT_LANE = 6;
// Since the switch was folded into docker-compose.yml (2026-11-06) the defaults are the
// wrapper's; the bitnami rollback sets these in .env (bitnami cannot run read-only).
export const BITNAMI_ROLLBACK_ENV = Object.freeze(["MINIO_IMAGE=bitnamilegacy/minio:2025.5.24", `MINIO_DATA_DIR=${BITNAMI_DATA_DIR}`, "MINIO_READ_ONLY=false"]);
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const CONFORMANCE_DEPS = ["postgres", "redis", "minio"];

// --- pure parts (scripts/minio-switch.test.mjs) ----------------------------------------------

// `repository[:tag]@sha256:<64 hex>`: a digest is required, a tag is optional.
export function parsePinnedRef(ref) {
  const m = typeof ref === "string" ? ref.match(/^([a-z0-9][a-z0-9._/-]*?)(?::([\w][\w.-]{0,127}))?@(sha256:[0-9a-f]{64})$/) : null;
  if (!m) throw new StackError(`not a digest-pinned image reference: ${ref}`, 2);
  return { repository: m[1], tag: m[2] ?? null, digest: m[3] };
}

export function isBitnamiMinio(image) {
  return typeof image === "string" && /^(docker\.io\/)?bitnami(legacy)?\/minio([:@]|$)/.test(image);
}

// The current compose model must still be the bitnami build on its data dir (else: switched
// already, or an unknown image this script did not plan for).
export function checkCurrentStack({ minioImage, minioDataDir }) {
  const errors = [];
  if (!isBitnamiMinio(minioImage)) errors.push(`MINIO_IMAGE resolves to ${minioImage}, not the bitnami build (switched already? revert .env first)`);
  if (minioDataDir !== BITNAMI_DATA_DIR) errors.push(`MINIO_DATA_DIR resolves to ${minioDataDir}, not ${BITNAMI_DATA_DIR}`);
  return errors;
}

// A polluted shell would point compose at another project or file set.
export function checkProjectEnv(env) {
  const errors = [];
  const project = env.COMPOSE_PROJECT_NAME;
  if (project !== undefined && project !== "" && project !== MAIN_PROJECT) errors.push(`COMPOSE_PROJECT_NAME=${project} is set; unset it`);
  if (env.COMPOSE_FILE) errors.push("COMPOSE_FILE is set; unset it (this script passes -f explicitly)");
  return errors;
}

// The candidate must be exactly the pinned Silo release: the wrapper builds FROM that digest.
export function candidateRef(env, silo = SILO) {
  const image = env.CANDIDATE_MINIO_IMAGE || silo.repository;
  const digest = env.CANDIDATE_MINIO_DIGEST || silo.indexDigest;
  if (image.includes("@")) throw new StackError("CANDIDATE_MINIO_IMAGE takes repository[:tag], no digest", 2);
  if (!DIGEST.test(digest)) throw new StackError(`CANDIDATE_MINIO_DIGEST is not sha256:<64 hex>: ${digest}`, 2);
  const repository = image.replace(/:[\w][\w.-]*$/, "");
  if (repository !== silo.repository || digest !== silo.indexDigest) {
    throw new StackError(`candidate ${image}@${digest} is not the pinned ${silo.repository}@${silo.indexDigest} (update SILO, the Dockerfile and the overlay together)`, 2);
  }
  return { image, digest };
}

// Lane URLs exactly as scripts/lane-test.sh derives them (database cyberlab_bN_test, Redis db N).
export function laneUrls(env, lane) {
  if (!Number.isInteger(lane) || lane < 2 || lane > 8) throw new StackError(`lane must be 2..8, got ${lane}`, 2);
  const need = (name) => {
    if (!env[name]) throw new StackError(`${name} is not set (.env)`, 2);
    return env[name];
  };
  const db = `cyberlab_b${lane}_test`;
  return {
    database: need("TEST_DATABASE_URL").replace(/\/[^/]+$/, `/${db}`),
    migration: need("TEST_MIGRATION_DATABASE_URL").replace(/\/[^/]+$/, `/${db}`),
    redis: need("TEST_REDIS_URL").replace(/\/[0-9]+$/, `/${lane}`),
  };
}

// The interpolation values of the candidate compose file (secrets stay in the child env).
export function candidateEnv(env, { lane = DEFAULT_LANE, password, silo = SILO } = {}) {
  const { image, digest } = candidateRef(env, silo);
  const urls = laneUrls(env, lane);
  return {
    CANDIDATE_MINIO_IMAGE: image,
    CANDIDATE_MINIO_DIGEST: digest,
    CANDIDATE_ROOT_PASSWORD: env.CANDIDATE_ROOT_PASSWORD || password || randomBytes(16).toString("hex"),
    TEST_BROKER_DB: String(lane),
    CONFORMANCE_DATABASE_URL: urls.database,
    CONFORMANCE_MIGRATION_DATABASE_URL: urls.migration,
    CONFORMANCE_REDIS_URL: urls.redis,
  };
}

// `stat -c '%u %g %a'` of a data dir root -> { uid, gid, mode }.
export function parseStat(text) {
  const m = typeof text === "string" ? text.trim().match(/^(\d+) (\d+) ([0-7]{3,4})$/) : null;
  if (!m) throw new StackError(`unexpected stat output: ${JSON.stringify(text)}`);
  return { uid: Number(m[1]), gid: Number(m[2]), mode: parseInt(m[3], 8) };
}

// Can `user` ("uid:gid", no supplementary groups) create entries (new buckets) in a directory?
// POSIX order: the owner bits apply to the owner alone, the group bits to the group alone.
export function canCreateIn({ uid, gid, mode }, user = WRAPPER_USER) {
  const [u, g] = String(user).split(":").map(Number);
  if (!Number.isInteger(u) || !Number.isInteger(g)) throw new StackError(`not a uid:gid user: ${user}`, 2);
  if (u === 0) return true;
  const wx = (shift) => ((mode >> shift) & 0o3) === 0o3;
  if (uid === u) return wx(6);
  if (gid === g) return wx(3);
  return wx(0);
}

// The ORIGINAL volume's root must take new buckets from the wrapper's user (the 2026-11-06
// failure: every existing bucket worked, a new one got AccessDenied).
export function checkDataDirLayout(stat, user = WRAPPER_USER) {
  if (canCreateIn(stat, user)) return [];
  const mode = stat.mode.toString(8).padStart(4, "0");
  return [`the MinIO data dir root is ${stat.uid}:${stat.gid} ${mode}: ${user} cannot create a bucket in it (fix the wrapper user, never chown the live volume blindly)`];
}

export function backupVolumeName(date = new Date()) {
  const stamp = date.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "z").toLowerCase();
  return `cyberlab-switch_pre-silo-${stamp}`;
}

export function checkBackupVolumeName(name) {
  if (typeof name !== "string" || !/^cyberlab-switch_pre-silo-\d{8}t\d{6}z$/.test(name)) {
    throw new StackError(`not a switch backup volume name: ${name}`, 2);
  }
  return name;
}

// The provenance check, gh (verified 2026-11-06) or cosign (same Sigstore bundle; not tried here).
export function attestationCommand(tool, silo = SILO) {
  const subject = `index.docker.io/${silo.repository}@${silo.indexDigest}`;
  const ref = `refs/tags/${silo.tag}`;
  if (tool === "gh") {
    return ["attestation", "verify", `oci://${subject}`, "--repo", silo.repository, "--signer-workflow", silo.signerWorkflow, "--source-ref", ref, "--deny-self-hosted-runners"];
  }
  if (tool === "cosign") {
    return [
      "verify-attestation", "--new-bundle-format", "--type", "https://slsa.dev/provenance/v1",
      "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
      "--certificate-identity", `https://github.com/${silo.signerWorkflow}@${ref}`,
      subject,
    ];
  }
  throw new StackError(`unknown attestation tool ${tool}`);
}

export function candidateComposeArgs(rest = []) {
  return ["compose", "-p", CANDIDATE_PROJECT, "--env-file", ".env", "-f", CANDIDATE_FILE, ...rest];
}

export function mainComposeFiles({ prod = false, overlay = false } = {}) {
  return [...composeFiles({ prod }), ...(overlay ? [SILO_OVERLAY] : [])];
}

function composeLine(files, rest) {
  return ["docker compose", ...files.map((f) => `-f ${f}`), rest].join(" ");
}

export function envSuggestion({ backupVolume, finishedAt, image = WRAPPER_IMAGE }) {
  return `# Written by scripts/minio-switch.mjs at ${finishedAt}, after backup, the conformance suite
# and the restore drill into ${image} all passed. Merge into .env to switch, and keep the
# lines below for the rollback. Silo base: ${SILO.repository}:${SILO.tag}@${SILO.indexDigest}
# (linux/amd64 ${SILO.amd64Digest}). The rollback anchor is the Docker volume ${backupVolume}.
MINIO_IMAGE=${image}
MINIO_DATA_DIR=${SILO_DATA_DIR}
# MC_IMAGE stays bitnamilegacy/minio-client:2025.5.21. pgsty/mc ships the binary as \`mcli\`,
# and infra/minio/init.sh calls \`mc\`.
# Optional: have plain \`docker compose\` / \`pnpm dev\` include the hardening overlay. On Windows,
# also set COMPOSE_PATH_SEPARATOR=: (or use ";").
# COMPOSE_PATH_SEPARATOR=:
# COMPOSE_FILE=docker-compose.yml:${SILO_OVERLAY}
`;
}

export function activationSteps({ prod = false } = {}) {
  const files = mainComposeFiles({ prod, overlay: true });
  return [
    `merge ${ENV_SUGGESTION} into .env (MINIO_IMAGE=${WRAPPER_IMAGE}, MINIO_DATA_DIR=${SILO_DATA_DIR})`,
    composeLine(files, "up -d --no-build --no-deps --wait minio"),
    composeLine(files, "run --rm minio-init"),
    composeLine(files, "up -d --no-build"),
    `scripts/lane-test.sh ${DEFAULT_LANE} uv run pytest -q -p no:cacheprovider tests/integration/test_object_store_conformance.py   # now against the switched store`,
    "pnpm verify",
  ];
}

export function rollbackSteps({ backupVolume, prod = false } = {}) {
  const files = mainComposeFiles({ prod, overlay: true });
  return [
    `# Silo cannot be downgraded in place (durable IAM revocation history, .minio.sys metadata).`,
    `# Rollback = restore the pre-switch backup onto the bitnami image. Writes since the backup are lost.`,
    composeLine(files, "stop"),
    `set ${BITNAMI_ROLLBACK_ENV.join(" ")} in .env (and remove COMPOSE_FILE): the compose default is the Silo wrapper since the fold; have the bitnami image local (pull_policy never)`,
    `docker compose -p ${MAIN_PROJECT} ${mainComposeFiles({ prod }).map((f) => `-f ${f}`).join(" ")} down -v   # DELIBERATE: removes the current volumes`,
    `node scripts/minio-switch.mjs rollback --backup-volume ${backupVolume}${prod ? " --prod" : ""}`,
    `docker volume rm ${backupVolume}   # only once the rollback, or the switch, has been verified`,
  ];
}

export function planSequence({ prod = false, lane = DEFAULT_LANE } = {}) {
  return [
    `preflight: bitnami model, files, pin ${SILO.repository}@${SILO.indexDigest}, provenance (gh attestation verify), ${volumeName(MAIN_PROJECT, "miniodata")} root writable by ${WRAPPER_USER}`,
    composeLine(mainComposeFiles({ prod, overlay: true }), `build minio   # ${WRAPPER_IMAGE} FROM the pinned digest`),
    `backup (runBackup) -> docker volume cyberlab-switch_pre-silo-<utc stamp> (label ${SWITCH_LABEL}); writers and MinIO stay stopped`,
    composeLine(mainComposeFiles({ prod }), `up -d --no-build --no-deps ${CONFORMANCE_DEPS.join(" ")}`),
    `docker ${candidateComposeArgs(["up -d --wait candidate"]).join(" ")}; run --rm conformance (lane ${lane}); RT7 prepare, restart candidate, verify; down -v (guarded)`,
    composeLine(mainComposeFiles({ prod }), "stop"),
    `pnpm restore:drill --${prod ? " --prod" : ""} --target-minio-image ${WRAPPER_IMAGE} --target-minio-data-dir ${SILO_DATA_DIR}   # check: bucket_create on the restored (original) layout`,
    `write ${ENV_SUGGESTION}; print the activation and the rollback`,
  ];
}

// `down -v` of the candidate project only: the model must resolve to `cyberlab-objstore`, and
// every volume it would remove must be one of that project's own.
export function downCandidate({ env, runner = exec } = {}) {
  const opts = { env: childEnv(env), capture: true, quiet: true };
  const config = JSON.parse(runner("docker", candidateComposeArgs(["config", "--format", "json"]), opts).stdout.toString());
  if (config.name !== CANDIDATE_PROJECT) throw new StackError(`downCandidate refused: the model resolved project ${JSON.stringify(config.name)}`, 4);
  const volumes = Object.entries(config.volumes ?? {})
    .filter(([, v]) => !v?.external)
    .map(([key, v]) => v?.name || `${CANDIDATE_PROJECT}_${key}`);
  for (const name of volumes) {
    if (!name.startsWith(`${CANDIDATE_PROJECT}_`)) throw new StackError(`downCandidate refused: volume ${name} is not a ${CANDIDATE_PROJECT} volume`, 4);
  }
  runner("docker", candidateComposeArgs(["down", "-v", "--remove-orphans", "--timeout", "20"]), { env: childEnv(env) });
  return volumes;
}

// --- orchestration (Docker; not unit-tested) --------------------------------------------------

function step(title) {
  console.log(`\n▶ switch: ${title}`);
}

function hasTool(tool) {
  try {
    return exec(tool, ["--version"], { capture: true, allowFail: true, quiet: true }).status === 0;
  } catch {
    return false;
  }
}

function verifyAttestation({ skip }) {
  for (const tool of ["gh", "cosign"]) {
    if (!hasTool(tool)) continue;
    exec(tool, attestationCommand(tool));
    console.log(`  ✔ SLSA provenance of ${SILO.repository}@${SILO.indexDigest} verified with ${tool}`);
    return tool;
  }
  if (!skip) throw new StackError("neither gh nor cosign is installed: install one, or pass --skip-attestation after verifying elsewhere", 2);
  console.log("  ! provenance NOT verified here (--skip-attestation)");
  return null;
}

export function preflight({ prod = false, skipAttestation = false, env = loadEnv() } = {}) {
  step("preflight");
  const errors = [...checkProjectEnv(process.env)];
  for (const file of [SILO_OVERLAY, `${SILO_DIR}/Dockerfile`, CANDIDATE_FILE]) {
    if (!existsSync(resolve(REPO_ROOT, file))) errors.push(`missing ${file}`);
  }
  const compose = new Compose({ project: MAIN_PROJECT, files: composeFiles({ prod }) });
  const facts = stackFacts(compose);
  errors.push(...checkCurrentStack(facts));
  candidateRef(env);
  errors.push(...checkDataDirLayout(dataDirStat(volumeName(MAIN_PROJECT, "miniodata"))));
  if (errors.length) throw new StackError(`preflight failed:\n  - ${errors.join("\n  - ")}`, 2);
  console.log(`  current: ${facts.minioImage} on ${facts.minioDataDir}`);
  verifyAttestation({ skip: skipAttestation });
  return { compose, facts };
}

// The live volume's root, read-only (helper image, no network).
export function dataDirStat(volume, { runner = exec } = {}) {
  const out = runHelper({ mounts: [{ type: "volume", source: volume, target: "/data", readonly: true }], cmd: ["stat", "-c", "%u %g %a", "/data"], quiet: true, exec: runner });
  return parseStat(out.stdout.toString());
}

function buildWrapper({ prod }) {
  step(`build ${WRAPPER_IMAGE} (FROM ${SILO.repository}:${SILO.tag}@${SILO.indexDigest})`);
  const compose = new Compose({ project: MAIN_PROJECT, files: mainComposeFiles({ prod, overlay: true }) });
  compose.run(["build", "minio"]);
  const out = exec("docker", ["image", "inspect", "--format", "{{.Config.User}}", WRAPPER_IMAGE], { capture: true, quiet: true });
  const user = out.stdout.toString().trim();
  if (user !== WRAPPER_USER) throw new StackError(`${WRAPPER_IMAGE} runs as ${JSON.stringify(user)}, expected ${WRAPPER_USER}`);
}

function runConformance({ lane, env }) {
  step(`conformance suite against the candidate (project ${CANDIDATE_PROJECT}, lane ${lane})`);
  const cEnv = candidateEnv(env, { lane });
  const run = (rest, extra = {}) => exec("docker", candidateComposeArgs(rest), { env: childEnv({ ...cEnv, ...extra }) });
  const slots = lockAllSlots();
  try {
    downCandidate({ env: cEnv });
    run(["up", "-d", "--wait", "candidate"]);
    run(["run", "--rm", "conformance"]);
    run(["run", "--rm", "-e", "OBJECT_STORE_RESTART_PHASE", "conformance"], { OBJECT_STORE_RESTART_PHASE: "prepare" });
    run(["restart", "candidate"]);
    run(["up", "-d", "--wait", "candidate"]);
    run(["run", "--rm", "-e", "OBJECT_STORE_RESTART_PHASE", "conformance"], { OBJECT_STORE_RESTART_PHASE: "verify" });
  } finally {
    try {
      downCandidate({ env: cEnv });
    } catch (error) {
      console.error(`✖ candidate cleanup failed: ${error.message}`);
      process.exitCode = 1;
    }
    slots.release();
  }
}

export async function runSwitch({ prod = false, lane = DEFAULT_LANE, skipAttestation = false } = {}) {
  const env = loadEnv();
  const { compose } = preflight({ prod, skipAttestation, env });
  let backupVolume = null;
  try {
    buildWrapper({ prod });

    backupVolume = backupVolumeName();
    step(`backup into the new volume ${backupVolume} (writers and MinIO stay stopped)`);
    exec("docker", ["volume", "create", "--label", SWITCH_LABEL, backupVolume], { capture: true, quiet: true });
    await runBackup({ compose, location: new DockerVolume(backupVolume), env, restart: false });

    step(`stop the stack: only ${CONFORMANCE_DEPS.join(", ")} run for the suite`);
    compose.run(["up", "-d", "--no-build", "--no-deps", ...CONFORMANCE_DEPS]);
    compose.waitHealthy(CONFORMANCE_DEPS);
    runConformance({ lane, env });

    step("stop the main project, then the restore drill into the Silo wrapper");
    compose.run(["stop"]);
    const drill = await runDrill({ prod, targetMinioImage: WRAPPER_IMAGE, targetMinioDataDir: SILO_DATA_DIR });
    if (!drill?.ok || drill.target_minio_image !== WRAPPER_IMAGE) throw new StackError("the restore drill did not pass against the wrapper");
  } catch (error) {
    console.error(`\n✖ switch aborted: ${error.message}
  Nothing has switched: .env and the miniodata volume are still the bitnami ones.
  Bring the stack back: docker compose ${composeFiles({ prod }).map((f) => `-f ${f}`).join(" ")} up -d --no-build${backupVolume ? `
  The backup volume ${backupVolume} is kept (docker volume rm it when no longer needed).` : ""}`);
    throw error;
  }

  const finishedAt = new Date().toISOString();
  writeFileSync(resolve(REPO_ROOT, ENV_SUGGESTION), envSuggestion({ backupVolume, finishedAt }));
  console.log(`\n✔ backup, conformance and restore drill passed. Wrote ${ENV_SUGGESTION} (the stack is stopped).`);
  console.log("\nActivate (the parent's decision):");
  activationSteps({ prod }).forEach((s, i) => console.log(`  ${i + 1}. ${s}`));
  console.log("\nRollback (keep this):");
  rollbackSteps({ backupVolume, prod }).forEach((s) => console.log(`  ${s}`));
  return { backupVolume, finishedAt };
}

export async function runRollback({ backupVolume, prod = false } = {}) {
  checkBackupVolumeName(backupVolume);
  const inspect = exec("docker", ["volume", "inspect", backupVolume], { capture: true, allowFail: true, quiet: true });
  if (inspect.status !== 0) throw new StackError(`no volume ${backupVolume}`, 2);
  const [key, value] = SWITCH_LABEL.split("=");
  if (JSON.parse(inspect.stdout.toString())[0]?.Labels?.[key] !== value) throw new StackError(`${backupVolume} lacks the label ${SWITCH_LABEL}`, 2);
  const compose = new Compose({ project: MAIN_PROJECT, files: composeFiles({ prod }) });
  const errors = [...checkProjectEnv(process.env), ...checkCurrentStack(stackFacts(compose))];
  if (errors.length) throw new StackError(`rollback refused (revert .env to bitnami first):\n  - ${errors.join("\n  - ")}`, 2);
  step(`restore ${backupVolume} onto the bitnami image (an empty stack only)`);
  return runRestore({ compose, location: new DockerVolume(backupVolume), env: loadEnv() });
}

async function main() {
  const args = parseArgs(process.argv.slice(2), { flags: ["prod", "skip-attestation"], options: ["lane", "backup-volume"] });
  const [command = "preflight"] = args._;
  const prod = Boolean(args.prod);
  const lane = args.lane ? Number(args.lane) : DEFAULT_LANE;
  if (command === "preflight") {
    preflight({ prod, skipAttestation: Boolean(args["skip-attestation"]) });
    laneUrls(loadEnv(), lane);
    console.log("\nPlanned sequence (`run`):");
    planSequence({ prod, lane }).forEach((s, i) => console.log(`  ${i + 1}. ${s}`));
  } else if (command === "run") {
    await runSwitch({ prod, lane, skipAttestation: Boolean(args["skip-attestation"]) });
  } else if (command === "rollback") {
    if (!args["backup-volume"]) throw new StackError("usage: node scripts/minio-switch.mjs rollback --backup-volume <cyberlab-switch_pre-silo-...> [--prod]", 2);
    await runRollback({ backupVolume: args["backup-volume"], prod });
  } else {
    throw new StackError(`unknown command ${command} (preflight | run | rollback)`, 2);
  }
}

if (isMain(import.meta.url)) {
  main().catch((error) => {
    console.error(`\n✖ minio-switch failed: ${error.message}`);
    process.exit(error.exitCode ?? 1);
  });
}
