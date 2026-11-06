// node --test scripts/minio-switch.test.mjs: the pure parts of scripts/minio-switch.mjs (no Docker).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import {
  BITNAMI_DATA_DIR,
  CANDIDATE_PROJECT,
  SILO,
  SILO_OVERLAY,
  WRAPPER_IMAGE,
  WRAPPER_USER,
  activationSteps,
  attestationCommand,
  backupVolumeName,
  candidateComposeArgs,
  candidateEnv,
  candidateRef,
  canCreateIn,
  checkBackupVolumeName,
  checkCurrentStack,
  checkDataDirLayout,
  dataDirStat,
  checkProjectEnv,
  downCandidate,
  envSuggestion,
  isBitnamiMinio,
  laneUrls,
  parsePinnedRef,
  parseStat,
  planSequence,
  rollbackSteps,
} from "./minio-switch.mjs";
import { REPO_ROOT } from "./lib/stack.mjs";

const HEX = "a".repeat(64);
const ENV = {
  TEST_DATABASE_URL: "postgresql+asyncpg://cyberlab_app:pw@postgres:5432/cyberlab_test",
  TEST_MIGRATION_DATABASE_URL: "postgresql+asyncpg://cyberlab_owner:pw2@postgres:5432/cyberlab_test",
  TEST_REDIS_URL: "redis://redis:6379/1",
};

test("parsePinnedRef requires a digest and keeps an optional tag", () => {
  assert.deepEqual(parsePinnedRef(`pgsty/silo:${SILO.tag}@${SILO.indexDigest}`), { repository: "pgsty/silo", tag: SILO.tag, digest: SILO.indexDigest });
  assert.deepEqual(parsePinnedRef(`pgsty/silo@sha256:${HEX}`), { repository: "pgsty/silo", tag: null, digest: `sha256:${HEX}` });
  for (const bad of ["pgsty/silo", `pgsty/silo:${SILO.tag}`, "pgsty/silo@sha256:abc", `pgsty/silo@sha512:${HEX}`, "", undefined]) {
    assert.throws(() => parsePinnedRef(bad), /digest-pinned/);
  }
});

test("the pinned digests are well formed and distinct", () => {
  assert.match(SILO.indexDigest, /^sha256:[0-9a-f]{64}$/);
  assert.match(SILO.amd64Digest, /^sha256:[0-9a-f]{64}$/);
  assert.notEqual(SILO.indexDigest, SILO.amd64Digest);
});

test("the Dockerfile and the overlay pin the same base as the script", () => {
  const base = `${SILO.repository}:${SILO.tag}@${SILO.indexDigest}`;
  const dockerfile = readFileSync(resolve(REPO_ROOT, "infra/minio/silo/Dockerfile"), "utf8");
  const overlay = readFileSync(resolve(REPO_ROOT, SILO_OVERLAY), "utf8");
  assert.ok(dockerfile.includes(`ARG SILO_BASE=${base}`));
  assert.equal(WRAPPER_USER, "1001:0");
  assert.match(dockerfile, /^USER 1001:0$/m);
  assert.match(dockerfile, /chown 1001:0 \/data/);
  assert.ok(overlay.includes(`user: "${WRAPPER_USER}"`));
  assert.match(dockerfile, /^CMD \["server", "\/data"/m);
  assert.ok(overlay.includes(`SILO_BASE: ${base}`));
  assert.ok(overlay.includes(`image: ${WRAPPER_IMAGE}`));
  assert.ok(!/image:\s*\$\{MINIO_IMAGE/.test(overlay), "the overlay must not tag its build with ${MINIO_IMAGE}");
  assert.ok(overlay.includes(`TARGET_IMAGE: ${WRAPPER_IMAGE}`));
});

test("docker-compose.yml defaults to the wrapper, built from the same pin, never pulled", () => {
  const base = `${SILO.repository}:${SILO.tag}@${SILO.indexDigest}`;
  const compose = readFileSync(resolve(REPO_ROOT, "docker-compose.yml"), "utf8");
  const minio = compose.slice(compose.indexOf("\n  minio:\n"), compose.indexOf("\n  minio-init:\n"));
  assert.ok(minio.includes(`image: \${MINIO_IMAGE:-${WRAPPER_IMAGE}}`));
  assert.ok(minio.includes("context: ./infra/minio/silo"));
  assert.ok(minio.includes(`SILO_BASE: ${base}`));
  // The build's tag guard sees the same value compose tags the build with.
  assert.ok(minio.includes(`TARGET_IMAGE: \${MINIO_IMAGE:-${WRAPPER_IMAGE}}`));
  assert.match(minio, /^ {4}pull_policy: never$/m);
  assert.ok(minio.includes(`user: "${WRAPPER_USER}"`));
  assert.ok(minio.includes("miniodata:${MINIO_DATA_DIR:-/data}"));
  assert.ok(minio.includes("read_only: ${MINIO_READ_ONLY:-true}"));
  const dockerfile = readFileSync(resolve(REPO_ROOT, "infra/minio/silo/Dockerfile"), "utf8");
  assert.ok(dockerfile.includes(`ARG TARGET_IMAGE=${WRAPPER_IMAGE}`));
  assert.ok(dockerfile.includes(`localhost/cyberlab/silo:*) ;;`) && /exit 1/.test(dockerfile));
});

test("isBitnamiMinio / checkCurrentStack", () => {
  assert.ok(isBitnamiMinio("bitnamilegacy/minio:2025.5.24"));
  assert.ok(isBitnamiMinio("docker.io/bitnami/minio:2025"));
  assert.ok(!isBitnamiMinio("bitnamilegacy/minio-client:2025.5.21"));
  assert.ok(!isBitnamiMinio(WRAPPER_IMAGE));
  assert.deepEqual(checkCurrentStack({ minioImage: "bitnamilegacy/minio:2025.5.24", minioDataDir: BITNAMI_DATA_DIR }), []);
  const errors = checkCurrentStack({ minioImage: WRAPPER_IMAGE, minioDataDir: "/data" });
  assert.equal(errors.length, 2);
  assert.match(errors[0], /switched already/);
});

test("checkProjectEnv refuses a polluted shell", () => {
  assert.deepEqual(checkProjectEnv({}), []);
  assert.deepEqual(checkProjectEnv({ COMPOSE_PROJECT_NAME: "cyberlab" }), []);
  assert.equal(checkProjectEnv({ COMPOSE_PROJECT_NAME: "cyberlab-drill" }).length, 1);
  assert.equal(checkProjectEnv({ COMPOSE_FILE: "a.yml" }).length, 1);
});

test("candidateRef accepts only the pinned release", () => {
  assert.deepEqual(candidateRef({}), { image: "pgsty/silo", digest: SILO.indexDigest });
  assert.deepEqual(candidateRef({ CANDIDATE_MINIO_IMAGE: `pgsty/silo:${SILO.tag}` }).digest, SILO.indexDigest);
  assert.throws(() => candidateRef({ CANDIDATE_MINIO_IMAGE: `pgsty/silo@${SILO.indexDigest}` }), /no digest/);
  assert.throws(() => candidateRef({ CANDIDATE_MINIO_DIGEST: "sha256:xyz" }), /not sha256/);
  assert.throws(() => candidateRef({ CANDIDATE_MINIO_DIGEST: `sha256:${HEX}` }), /not the pinned/);
  assert.throws(() => candidateRef({ CANDIDATE_MINIO_IMAGE: "cgr.dev/chainguard/minio" }), /not the pinned/);
});

test("laneUrls matches scripts/lane-test.sh", () => {
  assert.deepEqual(laneUrls(ENV, 6), {
    database: "postgresql+asyncpg://cyberlab_app:pw@postgres:5432/cyberlab_b6_test",
    migration: "postgresql+asyncpg://cyberlab_owner:pw2@postgres:5432/cyberlab_b6_test",
    redis: "redis://redis:6379/6",
  });
  assert.throws(() => laneUrls(ENV, 1), /2\.\.8/);
  assert.throws(() => laneUrls(ENV, 9), /2\.\.8/);
  assert.throws(() => laneUrls({}, 6), /TEST_DATABASE_URL/);
});

test("candidateEnv never points at the default test DB and keeps a given password", () => {
  const env = candidateEnv({ ...ENV, CANDIDATE_ROOT_PASSWORD: "given" }, { lane: 4 });
  assert.equal(env.CANDIDATE_ROOT_PASSWORD, "given");
  assert.equal(env.TEST_BROKER_DB, "4");
  assert.ok(!env.CONFORMANCE_DATABASE_URL.endsWith("/cyberlab_test"));
  assert.equal(env.CONFORMANCE_REDIS_URL, "redis://redis:6379/4");
  const generated = candidateEnv(ENV);
  assert.match(generated.CANDIDATE_ROOT_PASSWORD, /^[0-9a-f]{32}$/);
  assert.notEqual(generated.CANDIDATE_ROOT_PASSWORD, candidateEnv(ENV).CANDIDATE_ROOT_PASSWORD);
});

test("backup volume names are stamped and checked", () => {
  const name = backupVolumeName(new Date("2026-11-07T08:09:10.123Z"));
  assert.equal(name, "cyberlab-switch_pre-silo-20261107t080910z");
  assert.equal(checkBackupVolumeName(name), name);
  for (const bad of ["cyberlab_miniodata", "cyberlab-drill_backups", `${name}/..`, ""]) assert.throws(() => checkBackupVolumeName(bad));
});

test("attestation commands name the subject, the workflow and the tag", () => {
  const gh = attestationCommand("gh");
  assert.deepEqual(gh.slice(0, 3), ["attestation", "verify", `oci://index.docker.io/pgsty/silo@${SILO.indexDigest}`]);
  assert.ok(gh.includes(SILO.signerWorkflow) && gh.includes(`refs/tags/${SILO.tag}`) && gh.includes("--deny-self-hosted-runners"));
  const cosign = attestationCommand("cosign");
  assert.equal(cosign[0], "verify-attestation");
  assert.ok(cosign.includes(`https://github.com/${SILO.signerWorkflow}@refs/tags/${SILO.tag}`));
  assert.equal(cosign.at(-1), `index.docker.io/pgsty/silo@${SILO.indexDigest}`);
  assert.throws(() => attestationCommand("notary"));
});

test("envSuggestion switches image and data dir only, and keeps the bitnami client", () => {
  const text = envSuggestion({ backupVolume: "cyberlab-switch_pre-silo-20261107t080910z", finishedAt: "2026-11-07T08:09:10Z" });
  const active = text.split("\n").filter((l) => l && !l.startsWith("#"));
  assert.deepEqual(active, [`MINIO_IMAGE=${WRAPPER_IMAGE}`, "MINIO_DATA_DIR=/data"]);
  assert.ok(text.includes(SILO.indexDigest) && text.includes("cyberlab-switch_pre-silo-20261107t080910z"));
  assert.ok(!text.includes("\r"));
});

test("activation uses the overlay; rollback restores the backup onto bitnami", () => {
  const steps = activationSteps();
  assert.ok(steps[1].includes(`-f ${SILO_OVERLAY}`) && steps[1].includes("--wait minio"));
  assert.ok(activationSteps({ prod: true })[1].includes("-f docker-compose.prod.yml"));
  const rollback = rollbackSteps({ backupVolume: "cyberlab-switch_pre-silo-20261107t080910z" });
  assert.ok(rollback.some((s) => s.includes("rollback --backup-volume cyberlab-switch_pre-silo-20261107t080910z")));
  const down = rollback.find((s) => s.includes("down -v"));
  assert.ok(down.startsWith("docker compose -p cyberlab ") && !down.includes(SILO_OVERLAY));
  const env = rollback.find((s) => s.startsWith("set MINIO_IMAGE="));
  assert.ok(env.includes("MINIO_IMAGE=bitnamilegacy/minio:2025.5.24") && env.includes(`MINIO_DATA_DIR=${BITNAMI_DATA_DIR}`) && env.includes("MINIO_READ_ONLY=false"));
  assert.ok(rollback.indexOf(env) < rollback.indexOf(down));
});

test("planSequence orders backup, conformance, drill, then the suggestion", () => {
  const plan = planSequence({ lane: 5 });
  const at = (re) => plan.findIndex((s) => re.test(s));
  const order = [/^preflight/, /build minio/, /^backup/, /conformance \(lane 5\)/, /restore:drill/, /^write /].map(at);
  assert.ok(order.every((i) => i >= 0), JSON.stringify(order));
  assert.deepEqual([...order].sort((a, b) => a - b), order);
  assert.ok(plan.some((s) => s.includes(`--target-minio-image ${WRAPPER_IMAGE} --target-minio-data-dir /data`)));
});

test("candidateComposeArgs targets the isolated project with the repo .env", () => {
  assert.deepEqual(candidateComposeArgs(["ps"]), ["compose", "-p", CANDIDATE_PROJECT, "--env-file", ".env", "-f", "infra/minio/image/docker-compose.candidate.yml", "ps"]);
});

function fakeRunner(config) {
  const calls = [];
  const runner = (cmd, args) => {
    calls.push(args);
    if (args.includes("config")) return { status: 0, stdout: Buffer.from(JSON.stringify(config)) };
    return { status: 0, stdout: Buffer.alloc(0) };
  };
  return { runner, calls };
}

test("downCandidate removes only the candidate project's volumes", () => {
  const ok = fakeRunner({ name: CANDIDATE_PROJECT, volumes: { candidate_data: {}, ext: { external: true, name: "cyberlab_backend" } } });
  assert.deepEqual(downCandidate({ env: {}, runner: ok.runner }), [`${CANDIDATE_PROJECT}_candidate_data`]);
  assert.ok(ok.calls.at(-1).includes("down") && ok.calls.at(-1).includes("-v"));

  const wrongProject = fakeRunner({ name: "cyberlab", volumes: { candidate_data: {} } });
  assert.throws(() => downCandidate({ env: {}, runner: wrongProject.runner }), /resolved project/);
  assert.ok(!wrongProject.calls.some((a) => a.includes("down")));

  const foreign = fakeRunner({ name: CANDIDATE_PROJECT, volumes: { x: { name: "cyberlab_miniodata" } } });
  assert.throws(() => downCandidate({ env: {}, runner: foreign.runner }), /not a cyberlab-objstore volume/);
  assert.ok(!foreign.calls.some((a) => a.includes("down")));
});

// The 2026-11-06 failure: the live bitnami volume root is root:root 0775 (bitnami runs as
// 1001:0); a 1001:1001 wrapper read every existing bucket but could not create a new one.
const BITNAMI_ROOT = { uid: 0, gid: 0, mode: 0o775 };

test("parseStat reads `stat -c '%u %g %a'`", () => {
  assert.deepEqual(parseStat("0 0 775\n"), BITNAMI_ROOT);
  assert.deepEqual(parseStat("1001 0 770"), { uid: 1001, gid: 0, mode: 0o770 });
  for (const bad of ["", "0 0", "root root 775", "0 0 999", undefined]) assert.throws(() => parseStat(bad), /stat output/);
});

test("canCreateIn follows the POSIX owner / group / other order", () => {
  assert.equal(canCreateIn(BITNAMI_ROOT, "1001:1001"), false, "the failed wrapper user");
  assert.equal(canCreateIn(BITNAMI_ROOT, WRAPPER_USER), true, "gid 0 uses the group write bit");
  assert.equal(canCreateIn({ uid: 1001, gid: 1001, mode: 0o750 }, WRAPPER_USER), true, "a fresh 1001-owned volume");
  assert.equal(canCreateIn({ uid: 1001, gid: 0, mode: 0o770 }, WRAPPER_USER), true, "a fresh wrapper volume");
  assert.equal(canCreateIn({ uid: 1001, gid: 0, mode: 0o570 }, WRAPPER_USER), false, "owner bits win over group bits");
  assert.equal(canCreateIn({ uid: 0, gid: 0, mode: 0o755 }, WRAPPER_USER), false);
  assert.equal(canCreateIn({ uid: 0, gid: 0, mode: 0o777 }, "1001:1001"), true);
  assert.equal(canCreateIn({ uid: 0, gid: 0, mode: 0o773 }, "1001:1001"), true);
  assert.equal(canCreateIn({ uid: 0, gid: 0, mode: 0o700 }, "0:0"), true);
  assert.throws(() => canCreateIn(BITNAMI_ROOT, "minio"), /uid:gid/);
});

test("checkDataDirLayout names the layout it refuses", () => {
  assert.deepEqual(checkDataDirLayout(BITNAMI_ROOT), []);
  const [error] = checkDataDirLayout(BITNAMI_ROOT, "1001:1001");
  assert.match(error, /0:0 0775: 1001:1001 cannot create a bucket/);
});

test("dataDirStat reads the volume root read-only, with no network", () => {
  const calls = [];
  const stat = dataDirStat("cyberlab_miniodata", {
    runner: (cmd, args) => {
      calls.push([cmd, args]);
      return { status: 0, stdout: Buffer.from("0 0 775\n") };
    },
  });
  assert.deepEqual(stat, BITNAMI_ROOT);
  const [[cmd, args]] = calls;
  assert.equal(cmd, "docker");
  assert.deepEqual(args.slice(0, 4), ["run", "--rm", "--network", "none"]);
  assert.ok(args.includes("type=volume,source=cyberlab_miniodata,target=/data,readonly"));
  assert.deepEqual(args.slice(-4), ["stat", "-c", "%u %g %a", "/data"]);
});

test("planSequence checks the live layout and the drill probes bucket creation", () => {
  const plan = planSequence();
  assert.match(plan[0], new RegExp(`cyberlab_miniodata root writable by ${WRAPPER_USER}`));
  assert.ok(plan.some((s) => s.includes("restore:drill") && s.includes("bucket_create")));
});
