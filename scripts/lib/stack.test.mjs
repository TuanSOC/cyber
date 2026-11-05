// node --test scripts/lib/stack.test.mjs (host; no container is started).
// test_stack_guard: downVolumes refuses any project but the literal "cyberlab-drill", a
// polluted env and unlabelled volumes (RT2); the lane-slot lock uses lane-test.sh's root
// (RT25); the backup SQL files and restore_verify's copies never drift apart.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { prepareOutputDir } from "../backup.mjs";
import {
  BACKUP_UMASK,
  DRILL_BACKUPS_VOLUME,
  HELPER_IMAGE,
  HostDir,
  MANIFEST_HMAC_FILE,
  REPO_ROOT,
  StackError,
  checkBackupName,
  checkManifestAuthenticity,
  childEnv,
  composeFiles,
  downVolumes,
  kmsFingerprint,
  lockAllSlots,
  parseArgs,
  parseEnvFile,
  manifestKey,
  removeDrillBackupsVolume,
  runHelper,
  signManifest,
  verifyManifestSignature,
  volumeName,
} from "./stack.mjs";

// A fake `exec` recording every call; `respond(args)` returns {status, stdout}.
function fakeDocker(respond) {
  const calls = [];
  const runner = (command, args, opts = {}) => {
    calls.push({ command, args, env: opts.env });
    const out = respond(args) ?? { status: 0, stdout: "" };
    const result = { status: out.status ?? 0, stdout: Buffer.from(out.stdout ?? ""), stderr: Buffer.alloc(0) };
    if (result.status !== 0 && !opts.allowFail) throw new StackError(`fake ${args.join(" ")} failed`);
    return result;
  };
  return { calls, runner };
}

const DRILL_CONFIG = JSON.stringify({
  name: "cyberlab-drill",
  volumes: {
    pgdata: { name: "cyberlab-drill_pgdata" },
    miniodata: { name: "cyberlab-drill_miniodata" },
    e2e_samples: { name: "cyberlab_e2e_samples", external: true },
  },
});

function drillDocker({ config = DRILL_CONFIG, labelled = ["cyberlab-drill_pgdata", "cyberlab-drill_miniodata"], existing } = {}) {
  return fakeDocker((args) => {
    if (args.includes("config")) return { stdout: config };
    if (args[0] === "volume" && args[1] === "ls" && args.includes("--filter")) return { stdout: labelled.join("\n") };
    if (args[0] === "volume" && args[1] === "ls") return { stdout: (existing ?? ["cyberlab_pgdata", "cyberlab_miniodata", "cyberlab_e2e_samples", ...labelled]).join("\n") };
    return { stdout: "" };
  });
}

const downCalls = (calls) => calls.filter((c) => c.args.includes("down"));

test("downVolumes refuses the main project and any other name", () => {
  for (const project of ["cyberlab", "cyberlab-drill ", "CYBERLAB-DRILL", "cyberlab-drill2", "", undefined, null]) {
    const { calls, runner } = drillDocker();
    assert.throws(() => downVolumes(project, { env: {}, exec: runner }), /downVolumes refused/);
    assert.equal(calls.length, 0, `no docker call for ${JSON.stringify(project)}`);
  }
});

test("downVolumes refuses a polluted COMPOSE_PROJECT_NAME", () => {
  const { calls, runner } = drillDocker();
  assert.throws(
    () => downVolumes("cyberlab-drill", { env: { COMPOSE_PROJECT_NAME: "cyberlab" }, exec: runner }),
    /COMPOSE_PROJECT_NAME=cyberlab/,
  );
  assert.equal(calls.length, 0);
});

test("downVolumes refuses a model that resolves to another project", () => {
  const { calls, runner } = drillDocker({ config: JSON.stringify({ name: "cyberlab", volumes: { pgdata: {} } }) });
  assert.throws(() => downVolumes("cyberlab-drill", { env: {}, exec: runner }), /resolved the project "cyberlab"/);
  assert.equal(downCalls(calls).length, 0);
});

test("downVolumes refuses a volume without the drill project label", () => {
  const { calls, runner } = drillDocker({ labelled: ["cyberlab-drill_miniodata"], existing: ["cyberlab-drill_pgdata", "cyberlab-drill_miniodata"] });
  assert.throws(() => downVolumes("cyberlab-drill", { env: {}, exec: runner }), /cyberlab-drill_pgdata lacks the label/);
  assert.equal(downCalls(calls).length, 0);
});

test("downVolumes refuses a declared volume named outside the drill project", () => {
  const config = JSON.stringify({ name: "cyberlab-drill", volumes: { pgdata: { name: "cyberlab_pgdata" } } });
  // Even if someone labelled the main volume as a drill volume.
  const { calls, runner } = drillDocker({ config, labelled: ["cyberlab_pgdata"], existing: ["cyberlab_pgdata"] });
  assert.throws(() => downVolumes("cyberlab-drill", { env: {}, exec: runner }), /not a cyberlab-drill volume/);
  assert.equal(downCalls(calls).length, 0);
});

test("downVolumes runs down -v of the literal drill project with COMPOSE_* stripped", () => {
  const { calls, runner } = drillDocker();
  const env = { COMPOSE_PROJECT_NAME: "cyberlab-drill", COMPOSE_FILE: "docker-compose.yml", COMPOSE_PROFILES: "test", PATH: "x" };
  const removed = downVolumes("cyberlab-drill", { env, exec: runner });
  assert.deepEqual(removed, ["cyberlab-drill_pgdata", "cyberlab-drill_miniodata"]);
  const [down] = downCalls(calls);
  assert.ok(down, "down was called");
  assert.deepEqual(down.args.slice(0, 3), ["compose", "-p", "cyberlab-drill"]);
  assert.ok(down.args.includes("-v"));
  for (const call of calls) {
    for (const name of ["COMPOSE_PROJECT_NAME", "COMPOSE_FILE", "COMPOSE_PROFILES"]) assert.equal(call.env[name], undefined, `${name} stripped`);
    assert.equal(call.env.MSYS_NO_PATHCONV, "1");
  }
  // The external e2e volume and the main project's volumes are never targets.
  assert.ok(!removed.some((name) => name.startsWith("cyberlab_")));
});

test("the drill backups volume is removed only with its drill label", () => {
  const unlabelled = fakeDocker((args) => (args[1] === "inspect" ? { stdout: JSON.stringify([{ Name: DRILL_BACKUPS_VOLUME, Labels: {} }]) } : {}));
  assert.throws(() => removeDrillBackupsVolume({ exec: unlabelled.runner }), /lacks the label/);
  assert.ok(!unlabelled.calls.some((c) => c.args[1] === "rm"));
  const labelled = fakeDocker((args) => (args[1] === "inspect" ? { stdout: JSON.stringify([{ Labels: { "cyberlab.drill": "backups" } }]) } : {}));
  assert.equal(removeDrillBackupsVolume({ exec: labelled.runner }), true);
  assert.deepEqual(labelled.calls.at(-1).args, ["volume", "rm", DRILL_BACKUPS_VOLUME]);
  const missing = fakeDocker(() => ({ status: 1 }));
  assert.equal(removeDrillBackupsVolume({ exec: missing.runner }), false);
});

test("compose files, names, env and arguments", () => {
  assert.deepEqual(composeFiles(), ["docker-compose.yml"]);
  assert.deepEqual(composeFiles({ drill: true }), ["docker-compose.yml", "infra/backup/docker-compose.drill.yml", "infra/backup/docker-compose.drill-dev.yml"]);
  assert.deepEqual(composeFiles({ drill: true, prod: true }), ["docker-compose.yml", "docker-compose.prod.yml", "infra/backup/docker-compose.drill.yml"]);
  assert.equal(volumeName("cyberlab-drill", "miniodata"), "cyberlab-drill_miniodata");
  const env = childEnv({ A: "1" }, { COMPOSE_FILE: "x", COMPOSE_PROJECT_NAME: "y", B: "2" });
  assert.deepEqual(env, { A: "1", B: "2", MSYS_NO_PATHCONV: "1" });
  assert.deepEqual(parseEnvFile("# c\nA=1\nB='two words'\n C = \"3\" \nbad\n"), { A: "1", B: "two words", C: "3" });
  assert.deepEqual(parseArgs(["--", "--from", "d", "--force"], { flags: ["force"], options: ["from"] }), { _: [], from: "d", force: true });
  assert.throws(() => parseArgs(["--nope"]), /unknown option/);
});

test("the KMS fingerprint is the sha256 of the trimmed key file, never the key", () => {
  const dir = mkdtempSync(join(tmpdir(), "kms-"));
  try {
    const file = join(dir, "key");
    writeFileSync(file, "cyberlab-dev-kms:c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTEyMzQ=\n");
    const fp = kmsFingerprint(file);
    assert.equal(fp.name, "cyberlab-dev-kms");
    assert.equal(fp.fingerprint, createHash("sha256").update("cyberlab-dev-kms:c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTEyMzQ=").digest("hex"));
    assert.ok(!JSON.stringify(fp).includes("c2VjcmV0"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function sqlStatement(file) {
  return readFileSync(join(REPO_ROOT, file), "utf8").split("\n").filter((line) => !line.startsWith("--")).join("\n").trim();
}

function pythonConstant(name) {
  const source = readFileSync(join(REPO_ROOT, "apps/api/app/scripts/restore_verify.py"), "utf8");
  const match = source.match(new RegExp(`^${name} = """\\\\\\n([\\s\\S]*?)"""`, "m"));
  assert.ok(match, `${name} not found in restore_verify.py`);
  return match[1].trim();
}

test("infra/backup SQL equals restore_verify's copies", () => {
  assert.equal(sqlStatement("infra/backup/security.sql"), pythonConstant("SECURITY_SQL"));
  assert.equal(sqlStatement("infra/backup/tables.sql"), pythonConstant("TABLES_SQL"));
});

test("lockAllSlots takes every slot under lane-test.sh's lock root and releases them", () => {
  const root = mkdtempSync(join(tmpdir(), "lane-slots-")).replace(/\\/g, "/");
  const saved = process.env.LANE_LOCK_ROOT;
  process.env.LANE_LOCK_ROOT = root;
  try {
    const lock = lockAllSlots({ slots: 2, timeoutMs: 5_000 });
    assert.equal(lock.root, root);
    assert.deepEqual(lock.slots, [`${root}/slot-1`, `${root}/slot-2`]);
    for (const slot of lock.slots) assert.ok(existsSync(slot), `${slot} exists`);
    // A second taker (a lane or another drill) waits, then gives up, holding nothing.
    assert.throws(() => lockAllSlots({ slots: 2, timeoutMs: 200, pollMs: 50 }), /still taken/);
    assert.ok(existsSync(`${root}/slot-2`), "the first holder keeps its slots");
    lock.release();
    for (const slot of lock.slots) assert.ok(!existsSync(slot), `${slot} released`);
  } finally {
    if (saved === undefined) delete process.env.LANE_LOCK_ROOT;
    else process.env.LANE_LOCK_ROOT = saved;
    rmSync(root, { recursive: true, force: true });
  }
});

// --- host-dir backups, owner-only files, manifest HMAC ------------------------------------

const POSIX = process.platform !== "win32";

async function withTempDir(prefix, fn) {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  try {
    return await fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("HostDir writes, reads and hashes every backup file, manifest included", () =>
  withTempDir("hostdir-", async (dir) => {
    const location = new HostDir(dir);
    const manifest = JSON.stringify({ tool_version: 1, files: {} }, null, 2);
    const names = ["security.json", "tables.json", "objects.json", "manifest.json", MANIFEST_HMAC_FILE, "minio-data.tar", "postgres_v2.dump"];
    for (const name of names) {
      location.write(name, name === "manifest.json" ? manifest : `content of ${name}`);
      assert.ok(location.exists(name), name);
    }
    assert.equal(location.read("manifest.json").toString(), manifest);
    assert.equal(location.exists("globals.sql"), false);
    const facts = await location.facts(["manifest.json", "security.json", "globals.sql"]);
    assert.deepEqual(Object.keys(facts).sort(), ["manifest.json", "security.json"]);
    assert.deepEqual(facts["manifest.json"], { sha256: createHash("sha256").update(manifest).digest("hex"), bytes: Buffer.byteLength(manifest) });
    if (POSIX) assert.equal(statSync(join(dir, "manifest.json")).mode & 0o777, 0o600, "owner-only file");
  }));

test("backup file names are one safe path segment", () => {
  // "w" passes too: the old pattern only accepted the letter w, dots and dashes.
  for (const good of ["postgres.dump", "minio-data.tar", "manifest.json.hmac", "a_B-1.json", "w"]) assert.equal(checkBackupName(good), good);
  for (const bad of ["", ".", "..", "../x", "a/b", "a\\b", "x y", "$(id)", undefined]) {
    assert.throws(() => checkBackupName(bad), StackError, String(bad));
  }
  assert.throws(() => new HostDir(tmpdir()).write("../escape.json", "x"), /invalid backup file name/);
});

test("HostDir hands root-helper output to the host user only on a non-root POSIX host", () => {
  const location = new HostDir(tmpdir());
  assert.deepEqual(location.owner("/backup", { getuid: () => 1000, getgid: () => 1001 }), { owner: "1000:1001", path: "/backup" });
  assert.equal(location.owner("/backup", { getuid: () => 0, getgid: () => 0 }), null);
  assert.equal(location.owner("/backup", { getuid: undefined, getgid: undefined }), null);
});

test("backup helpers run with umask 077 and chown their output", () => {
  const { calls, runner } = fakeDocker(() => ({}));
  runHelper({ cmd: ["tar", "-cf", "/backup/x.tar", "-C", "/data", "."], umask: BACKUP_UMASK, chown: { owner: "1000:1000", path: "/backup" }, exec: runner });
  runHelper({ cmd: ["pg_dump", "-f", "/backup/postgres.dump"], umask: BACKUP_UMASK, exec: runner });
  runHelper({ cmd: ["cat", "/backup/x"], exec: runner });
  const tail = (args) => args.slice(args.indexOf(HELPER_IMAGE) + 1);
  assert.deepEqual(tail(calls[0].args), ["sh", "-c", 'umask 077 && "$@" && chown -R 1000:1000 /backup', "_", "tar", "-cf", "/backup/x.tar", "-C", "/data", "."]);
  assert.deepEqual(tail(calls[1].args), ["sh", "-c", 'umask 077 && exec "$@"', "_", "pg_dump", "-f", "/backup/postgres.dump"]);
  assert.deepEqual(tail(calls[2].args), ["cat", "/backup/x"]);
  assert.throws(() => runHelper({ cmd: ["true"], umask: "077; rm -rf /", exec: runner }), /invalid umask/);
  assert.throws(() => runHelper({ cmd: ["true"], umask: BACKUP_UMASK, chown: { owner: "0:0 /", path: "/backup" }, exec: runner }), /invalid chown/);
  assert.throws(() => runHelper({ cmd: ["true"], umask: BACKUP_UMASK, chown: { owner: "1:1", path: "/backup/../etc" }, exec: runner }), /invalid chown/);
  assert.equal(calls.length, 3, "a refused helper never reaches docker");
});

test("the backup dir is created owner-only (0700), an existing one is tightened", () =>
  withTempDir("backupdir-", (root) => {
    const dir = join(root, "backups", "20261106T000000Z");
    prepareOutputDir(dir);
    assert.ok(statSync(dir).isDirectory());
    if (POSIX) {
      assert.equal(statSync(dir).mode & 0o777, 0o700);
      prepareOutputDir(root);
      assert.equal(statSync(root).mode & 0o777, 0o700);
    }
  }));

const KEY_ENV = { BACKUP_MANIFEST_KEY: "k".repeat(32) };

test("the manifest HMAC: sign, verify, refuse a short key", () => {
  const key = manifestKey(KEY_ENV);
  const bytes = Buffer.from('{"files": {}}');
  const sig = signManifest(bytes, key);
  assert.match(sig, /^hmac-sha256:[0-9a-f]{64}\n$/);
  assert.equal(verifyManifestSignature(bytes, sig, key), true);
  assert.equal(verifyManifestSignature(bytes, Buffer.from(sig), key), true);
  assert.equal(verifyManifestSignature(Buffer.from('{"files": {"x": 1}}'), sig, key), false);
  assert.equal(verifyManifestSignature(bytes, sig, manifestKey({ BACKUP_MANIFEST_KEY: "j".repeat(32) })), false);
  assert.equal(verifyManifestSignature(bytes, "hmac-sha256:zz", key), false);
  assert.equal(verifyManifestSignature(bytes, "", key), false);
  assert.equal(manifestKey({}), null);
  assert.throws(() => manifestKey({ BACKUP_MANIFEST_KEY: "short" }), /at least 32/);
});

test("restore checks manifest authenticity at a host dir", () =>
  withTempDir("manifest-auth-", (dir) => {
    const location = new HostDir(dir);
    const bytes = Buffer.from(JSON.stringify({ tool_version: 1 }, null, 2));
    location.write("manifest.json", bytes);
    const logs = [];
    const log = (line) => logs.push(line);
    // No key, no signature: allowed, but said to be integrity only.
    assert.equal(checkManifestAuthenticity(location, bytes, {}, { log }), "unsigned");
    assert.match(logs.at(-1), /integrity, not authenticity/);
    // A key and no signature: refused (exit 2).
    assert.throws(
      () => checkManifestAuthenticity(location, bytes, KEY_ENV, { log }),
      (e) => e instanceof StackError && e.exitCode === 2 && /unsigned backup/.test(e.message),
    );
    location.write(MANIFEST_HMAC_FILE, signManifest(bytes, manifestKey(KEY_ENV)));
    assert.equal(checkManifestAuthenticity(location, location.read("manifest.json"), KEY_ENV, { log }), "signed");
    // A rewritten manifest (hashes updated to match altered files) no longer verifies.
    const forged = Buffer.from(JSON.stringify({ tool_version: 1, files: { "postgres.dump": "evil" } }, null, 2));
    location.write("manifest.json", forged);
    assert.throws(() => checkManifestAuthenticity(location, forged, KEY_ENV, { log }), /does not verify/);
    // A signature but no key here: warned, not trusted.
    assert.equal(checkManifestAuthenticity(location, forged, {}, { log }), "unsigned");
    assert.match(logs.at(-1), /authenticity NOT checked/);
  }));
