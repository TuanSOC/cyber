// Shared compose / Docker helpers of the M7 backup, restore and restore drill (phase 2).
//
// - Every Docker call takes an argument array (no shell, so no path or value is ever pasted
//   into a command string) and runs with COMPOSE_PROJECT_NAME / COMPOSE_FILE / COMPOSE_PROFILES
//   removed from the child env: the project, files and profiles are always explicit (-p/-f).
//   MSYS_NO_PATHCONV=1 keeps Git Bash from rewriting container paths.
// - Secrets reach containers only through the child env (`-e NAME` without a value), never on
//   a command line, and are never printed.
// - `downVolumes()` is the only code path that removes volumes. It refuses every project but
//   the literal "cyberlab-drill" (RT2).
import { spawnSync } from "node:child_process";
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { createReadStream, existsSync, readFileSync, statSync, statfsSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
// The drill's compose project: a literal, compared as such, never derived (RT2).
export const DRILL_PROJECT = "cyberlab-drill";
// The drill's backups volume (RT6): outside compose (`down -v` mid-drill keeps it), removed
// by `removeDrillBackupsVolume()` at the end.
export const DRILL_BACKUPS_VOLUME = "cyberlab-drill_backups";
export const DRILL_BACKUPS_LABEL = "cyberlab.drill=backups";
// Helper image for tar, sha256sum, du and the Postgres clients: pinned, already used by the
// stack (postgres and db-bootstrap), with BusyBox tar (--numeric-owner).
export const HELPER_IMAGE = "postgres:17.11-alpine";
// Every file a backup helper writes is owner-only (the backup is TLP:RED, RT6).
export const BACKUP_UMASK = "077";
const STRIPPED_ENV = ["COMPOSE_PROJECT_NAME", "COMPOSE_FILE", "COMPOSE_PROFILES"];
const MAX_BUFFER = 512 * 1024 * 1024;

// Writers stopped before a backup, in this order (plan.md: gateway, web, api, workers, beat).
export const WRITERS = [
  "gateway",
  "web",
  "api",
  "ingest-worker",
  "enrich-worker",
  "analyst-worker",
  "pcap-worker",
  "static-worker",
  "report-worker",
  "retention-worker",
  "ingest-beat",
];
// Heavy main-project services: the drill refuses to run next to them (host memory).
export const HEAVY_SERVICES = [
  "pcap-worker",
  "static-worker",
  "report-worker",
  "pcap-worker-test",
  "static-worker-test",
  "report-worker-test",
];

export class StackError extends Error {
  constructor(message, exitCode = 1) {
    super(message);
    this.exitCode = exitCode;
  }
}

// --- env ---------------------------------------------------------------------------------

export function parseEnvFile(text) {
  const values = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (value.length >= 2 && (value[0] === '"' || value[0] === "'") && value.at(-1) === value[0]) {
      value = value.slice(1, -1);
    }
    values[key] = value;
  }
  return values;
}

// Compose semantics: the shell env wins over `.env`.
export function loadEnv(file = join(REPO_ROOT, ".env"), env = process.env) {
  const fromFile = existsSync(file) ? parseEnvFile(readFileSync(file, "utf8")) : {};
  return { ...fromFile, ...Object.fromEntries(Object.entries(env).filter(([, v]) => v !== undefined)) };
}

export function childEnv(extra = {}, base = process.env) {
  const env = { ...base, ...extra, MSYS_NO_PATHCONV: "1" };
  for (const name of STRIPPED_ENV) delete env[name];
  return env;
}

// --- processes ---------------------------------------------------------------------------

// spawnSync with an argument array. `capture` returns stdout (Buffer or string); otherwise
// stdout and stderr are inherited. A non-zero exit throws unless `allowFail`.
export function exec(command, args, { input, env, capture = false, allowFail = false, quiet = false, cwd = REPO_ROOT } = {}) {
  if (!quiet) console.log(`  $ ${command} ${args.map(displayArg).join(" ")}`);
  const result = spawnSync(command, args, {
    cwd,
    env: env ?? childEnv(),
    input,
    maxBuffer: MAX_BUFFER,
    stdio: [input === undefined ? "ignore" : "pipe", capture ? "pipe" : "inherit", capture ? "pipe" : "inherit"],
  });
  if (result.error) throw new StackError(`${command}: ${result.error.message}`);
  const out = { status: result.status ?? 1, stdout: result.stdout ?? Buffer.alloc(0), stderr: result.stderr ?? Buffer.alloc(0) };
  if (out.status !== 0 && !allowFail) {
    const tail = capture ? out.stderr.toString().trim().split(/\r?\n/).slice(-8).join("\n    ") : "";
    throw new StackError(`${command} ${args.slice(0, 6).map(displayArg).join(" ")} … exited ${out.status}${tail ? `\n    ${tail}` : ""}`);
  }
  return out;
}

function displayArg(arg) {
  return /^[\w@%+=:,./-]+$/.test(arg) ? arg : JSON.stringify(arg);
}

// --- compose -----------------------------------------------------------------------------

export class Compose {
  // project: compose project name; files: compose files relative to the repo; profiles;
  // env: extra child env (interpolation values such as MINIO_IMAGE, or secrets for `-e NAME`).
  constructor({ project, files = ["docker-compose.yml"], profiles = [], env = {}, exec: runner = exec }) {
    if (!project || !/^[a-z0-9][a-z0-9_-]*$/.test(project)) throw new StackError(`invalid compose project ${project}`);
    this.project = project;
    this.files = files;
    this.profiles = profiles;
    this.env = env;
    this.exec = runner;
  }

  with(extra) {
    return new Compose({ project: this.project, files: this.files, profiles: this.profiles, env: { ...this.env, ...extra }, exec: this.exec });
  }

  args(rest) {
    const args = ["compose", "-p", this.project];
    for (const file of this.files) args.push("-f", file);
    for (const profile of this.profiles) args.push("--profile", profile);
    return [...args, ...rest];
  }

  run(rest, opts = {}) {
    return this.exec("docker", this.args(rest), { ...opts, env: childEnv({ ...this.env, ...(opts.envExtra ?? {}) }) });
  }

  config() {
    const { stdout } = this.run(["config", "--format", "json"], { capture: true, quiet: true });
    return JSON.parse(stdout.toString());
  }

  // Containers of the project (running and stopped) as compose reports them.
  ps({ all = false } = {}) {
    const { stdout } = this.run(["ps", ...(all ? ["-a"] : []), "--format", "json"], { capture: true, quiet: true });
    return parseJsonLines(stdout.toString());
  }

  runningServices() {
    return [...new Set(this.ps().filter((c) => c.State === "running").map((c) => c.Service))];
  }

  // A one-off container of `service` with stdin/stdout piped (-T): returns stdout as text.
  // `secretEnv` names variables passed with `-e NAME`, their values only in the child env.
  oneOff(service, command, { input, secretEnv = {}, entrypoint, volumes = [], allowFail = false } = {}) {
    const rest = ["run", "--rm", "--no-deps", "-T"];
    for (const name of Object.keys(secretEnv)) rest.push("-e", name);
    for (const volume of volumes) rest.push("-v", volume);
    if (entrypoint) rest.push("--entrypoint", entrypoint);
    rest.push(service, ...command);
    const out = this.run(rest, { input, capture: true, allowFail, envExtra: secretEnv });
    return { status: out.status, stdout: out.stdout.toString(), stderr: out.stderr.toString() };
  }

  // Waits until every listed service has a running container that is healthy (or has no
  // healthcheck). Exited one-shot services are reported as failures.
  waitHealthy(services, { timeoutMs = 400_000 } = {}) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const containers = this.ps({ all: true });
      const pending = [];
      for (const service of services) {
        const c = containers.find((x) => x.Service === service);
        if (!c || c.State !== "running" || (c.Health && c.Health !== "healthy")) pending.push(`${service}:${c ? `${c.State}/${c.Health || "-"}` : "missing"}`);
        if (c && c.State === "exited") throw new StackError(`${service} exited (${c.Status})`);
      }
      if (!pending.length) return;
      if (Date.now() > deadline) throw new StackError(`not healthy in time: ${pending.join(", ")}`);
      sleep(3000);
    }
  }
}

export function parseJsonLines(text) {
  const trimmed = text.trim();
  if (!trimmed) return [];
  if (trimmed.startsWith("[")) return JSON.parse(trimmed);
  return trimmed.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
}

export function sleep(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

export function volumeName(project, name) {
  return `${project}_${name}`;
}

export function networkName(project, name = "backend") {
  return `${project}_${name}`;
}

// The compose files of a project: the base, the prod overlay, the drill overlays.
export function composeFiles({ prod = false, drill = false } = {}) {
  const files = ["docker-compose.yml"];
  if (prod) files.push("docker-compose.prod.yml");
  if (drill) {
    files.push("infra/backup/docker-compose.drill.yml");
    if (!prod) files.push("infra/backup/docker-compose.drill-dev.yml");
  }
  return files;
}

// Stops the running writers in WRITERS order; returns every service that was running before
// (to restart exactly that set).
export function stopWriters(compose) {
  const running = compose.runningServices();
  for (const service of WRITERS) {
    if (running.includes(service)) compose.run(["stop", service]);
  }
  return running;
}

// Starts `services` (all default services when empty) and waits until they are healthy.
export function startAll(compose, services = []) {
  compose.run(["up", "-d", "--no-build", ...services]);
  const targets = services.length ? services : compose.runningServices();
  compose.waitHealthy(targets);
}

// --- the down -v guard (RT2) -------------------------------------------------------------

function refuse(message) {
  throw new StackError(`downVolumes refused: ${message}`, 4);
}

// `docker compose down -v` for the drill project only. Refuses:
// - any project other than the literal "cyberlab-drill";
// - an env whose COMPOSE_PROJECT_NAME names another project (a polluted shell);
// - a compose model that resolves to another project name;
// - any existing volume it would remove that lacks the label
//   com.docker.compose.project=cyberlab-drill.
// It lists those volumes first, and runs with COMPOSE_* removed from the child env.
export function downVolumes(project, { files = composeFiles({ drill: true }), env = process.env, exec: runner = exec } = {}) {
  if (project !== "cyberlab-drill") refuse(`project ${JSON.stringify(project)} is not "cyberlab-drill"`);
  for (const name of STRIPPED_ENV) {
    const value = env[name];
    if (name === "COMPOSE_PROJECT_NAME" && value !== undefined && value !== "" && value !== "cyberlab-drill") {
      refuse(`COMPOSE_PROJECT_NAME=${value} is set in the environment; unset it`);
    }
  }
  const compose = new Compose({ project: "cyberlab-drill", files, env: {}, exec: runner });
  const childBase = childEnv({}, env);
  const run = (args, opts = {}) => runner("docker", args, { ...opts, env: childBase });
  const config = JSON.parse(run(compose.args(["config", "--format", "json"]), { capture: true, quiet: true }).stdout.toString());
  if (config.name !== "cyberlab-drill") refuse(`compose resolved the project ${JSON.stringify(config.name)}`);
  const declared = Object.entries(config.volumes ?? {})
    .filter(([, v]) => !v?.external)
    .map(([key, v]) => v?.name || volumeName("cyberlab-drill", key));
  const labelled = run(["volume", "ls", "-q", "--filter", "label=com.docker.compose.project=cyberlab-drill"], { capture: true, quiet: true })
    .stdout.toString().split(/\s+/).filter(Boolean);
  const existing = run(["volume", "ls", "-q"], { capture: true, quiet: true }).stdout.toString().split(/\s+/).filter(Boolean);
  const targets = declared.filter((name) => existing.includes(name));
  console.log(`  down -v of cyberlab-drill would remove: ${targets.length ? targets.join(", ") : "(no volume)"}`);
  for (const name of targets) {
    if (!labelled.includes(name)) refuse(`volume ${name} lacks the label com.docker.compose.project=cyberlab-drill`);
    if (!name.startsWith("cyberlab-drill_")) refuse(`volume ${name} is not a cyberlab-drill volume`);
  }
  run(compose.args(["down", "-v", "--remove-orphans", "--timeout", "20"]));
  return targets;
}

export function createDrillBackupsVolume({ exec: runner = exec } = {}) {
  runner("docker", ["volume", "create", "--label", DRILL_BACKUPS_LABEL, DRILL_BACKUPS_VOLUME], { capture: true, quiet: true });
}

// Removes the drill backups volume, only when it carries the drill label.
export function removeDrillBackupsVolume({ exec: runner = exec } = {}) {
  const inspect = runner("docker", ["volume", "inspect", DRILL_BACKUPS_VOLUME], { capture: true, allowFail: true, quiet: true });
  if (inspect.status !== 0) return false;
  const [info] = JSON.parse(inspect.stdout.toString());
  const [key, value] = DRILL_BACKUPS_LABEL.split("=");
  if (info?.Labels?.[key] !== value) throw new StackError(`${DRILL_BACKUPS_VOLUME} lacks the label ${DRILL_BACKUPS_LABEL}; not removing it`, 4);
  runner("docker", ["volume", "rm", DRILL_BACKUPS_VOLUME], { capture: true, quiet: true });
  return true;
}

// --- lane slots (RT25) -------------------------------------------------------------------

// Takes every lane slot (LANE_SLOTS, default 3) under the lock root of scripts/lane-test.sh.
// The root and the lock directories are resolved and created by bash, exactly as lane-test.sh
// does it (Git Bash TMPDIR vs Node's os.tmpdir() differ on Windows). Returns release().
export function lockAllSlots({ slots = Number(process.env.LANE_SLOTS || 3), timeoutMs = 30 * 60_000, exec: runner = exec, pollMs = 5000 } = {}) {
  const env = childEnv();
  const root = runner("bash", ["scripts/lane-test.sh", "--print-lock-root"], { capture: true, quiet: true, env }).stdout.toString().trim();
  if (!root) throw new StackError("lane-test.sh printed no lock root");
  const taken = [];
  const release = () => {
    for (const slot of taken.splice(0)) {
      runner("bash", ["-c", 'rmdir "$1" 2>/dev/null || true', "_", slot], { capture: true, quiet: true, allowFail: true, env });
    }
  };
  const deadline = Date.now() + timeoutMs;
  try {
    for (let i = 1; i <= slots; i++) {
      const slot = `${root}/slot-${i}`;
      for (;;) {
        const got = runner("bash", ["-c", 'mkdir -p "$1" && mkdir "$2" 2>/dev/null', "_", root, slot], { capture: true, quiet: true, allowFail: true, env });
        if (got.status === 0) {
          taken.push(slot);
          break;
        }
        if (Date.now() > deadline) throw new StackError(`lane slot ${slot} still taken after ${timeoutMs / 1000}s`);
        sleep(pollMs);
      }
    }
  } catch (error) {
    release();
    throw error;
  }
  console.log(`  took ${taken.length} lane slot(s) under ${root}`);
  return { root, slots: [...taken], release };
}

// --- helper containers -------------------------------------------------------------------

// A throwaway container of `image` (no compose): mounts are {type: "bind"|"volume", source,
// target, readonly}; `env` holds values for `-e NAME` (child env only).
// `umask` (e.g. BACKUP_UMASK) wraps `cmd` in `sh -c 'umask <m> && exec "$@"'` so every file
// it creates is owner-only; `chown` ({owner: "uid:gid", path}) then hands what it wrote under
// `path` to the host user (a Linux bind mount: root-owned 0600 files would be unreadable to
// the host user that hashes them).
export function runHelper({ image = HELPER_IMAGE, mounts = [], cmd, network = "none", env = {}, input, capture = true, allowFail = false, quiet = false, umask, chown, exec: runner = exec }) {
  const args = ["run", "--rm", "--network", network];
  if (input !== undefined) args.push("-i");
  for (const m of mounts) {
    const parts = [`type=${m.type}`, `source=${m.source}`, `target=${m.target}`];
    if (m.readonly) parts.push("readonly");
    args.push("--mount", parts.join(","));
  }
  for (const name of Object.keys(env)) args.push("-e", name);
  if (umask !== undefined || chown) {
    const mask = umask ?? "022";
    if (!/^[0-7]{3,4}$/.test(mask)) throw new StackError(`invalid umask ${mask}`);
    let script = `umask ${mask} && exec "$@"`;
    if (chown) {
      if (!/^\d+:\d+$/.test(chown.owner ?? "") || !/^\/[\w./-]*$/.test(chown.path ?? "") || chown.path.includes("..")) {
        throw new StackError("invalid chown for a helper");
      }
      script = `umask ${mask} && "$@" && chown -R ${chown.owner} ${chown.path}`;
    }
    args.push(image, "sh", "-c", script, "_", ...cmd);
  } else {
    args.push(image, ...cmd);
  }
  return runner("docker", args, { input, capture, allowFail, quiet, env: childEnv(env) });
}

export function sha256File(path) {
  return new Promise((resolvePromise, reject) => {
    const hash = createHash("sha256");
    createReadStream(path)
      .on("error", reject)
      .on("data", (chunk) => hash.update(chunk))
      .on("end", () => resolvePromise(hash.digest("hex")));
  });
}

// The KMS key file's name and sha256 fingerprint (same rule as restore_verify.kms_fingerprint:
// the sha256 of the content without surrounding whitespace). The key is never returned.
export function kmsFingerprint(path) {
  const content = readFileSync(path, "utf8").trim();
  const sep = content.indexOf(":");
  if (sep <= 0) throw new StackError(`${path} is not <name>:<base64 key>`);
  return { name: content.slice(0, sep), fingerprint: createHash("sha256").update(content).digest("hex") };
}

// --- backup locations --------------------------------------------------------------------

// A host directory (pnpm backup / restore). Paths stay absolute and are passed to Docker as
// --mount sources, never through a shell.
export class HostDir {
  constructor(path) {
    this.path = isAbsolute(path) ? path : resolve(REPO_ROOT, path);
    this.label = this.path;
  }
  mount(target = "/backup", readonly = false) {
    return { type: "bind", source: this.path, target, readonly };
  }
  // What a root helper should chown its output under `target` to: the host user on a POSIX
  // host that is not root (null on Windows / as root, where the host can read it anyway).
  owner(target = "/backup", { getuid = process.getuid, getgid = process.getgid } = {}) {
    if (typeof getuid !== "function" || typeof getgid !== "function") return null;
    const uid = getuid();
    return uid === 0 ? null : { owner: `${uid}:${getgid()}`, path: target };
  }
  write(name, data) {
    checkBackupName(name);
    // Owner-only (TLP:RED, RT6); the mode applies when the file is created.
    writeFileSync(join(this.path, name), data, { mode: 0o600 });
  }
  read(name) {
    return readFileSync(join(this.path, name));
  }
  exists(name) {
    return existsSync(join(this.path, name));
  }
  async facts(names) {
    const out = {};
    for (const name of names) {
      const file = join(this.path, name);
      if (!existsSync(file)) continue;
      out[name] = { sha256: await sha256File(file), bytes: statSync(file).size };
    }
    return out;
  }
  freeBytes() {
    const s = statfsSync(this.path);
    return Number(s.bavail) * Number(s.bsize);
  }
}

// A named Docker volume (the drill's backups, RT6): every byte stays inside Docker.
export class DockerVolume {
  constructor(name) {
    this.name = name;
    this.label = `volume ${name}`;
  }
  mount(target = "/backup", readonly = false) {
    return { type: "volume", source: this.name, target, readonly };
  }
  owner() {
    return null;
  }
  write(name, data) {
    runHelperWrite(this, name, data);
  }
  read(name) {
    return runHelper({ mounts: [this.mount("/backup", true)], cmd: ["cat", `/backup/${name}`], quiet: true }).stdout;
  }
  exists(name) {
    return runHelper({ mounts: [this.mount("/backup", true)], cmd: ["test", "-e", `/backup/${name}`], allowFail: true, quiet: true }).status === 0;
  }
  async facts(names) {
    const script = 'cd /backup && for f in "$@"; do [ -f "$f" ] && printf "%s %s %s\\n" "$(sha256sum "$f" | cut -d" " -f1)" "$(stat -c %s "$f")" "$f"; done; true';
    const { stdout } = runHelper({ mounts: [this.mount("/backup", true)], cmd: ["sh", "-c", script, "_", ...names], quiet: true });
    const out = {};
    for (const line of stdout.toString().split("\n").filter(Boolean)) {
      const [sha256, bytes, name] = line.split(" ");
      out[name] = { sha256, bytes: Number(bytes) };
    }
    return out;
  }
  freeBytes() {
    const { stdout } = runHelper({ mounts: [this.mount("/backup", true)], cmd: ["df", "-Pk", "/backup"], quiet: true });
    const fields = stdout.toString().trim().split("\n").at(-1).split(/\s+/);
    return Number(fields[3]) * 1024;
  }
}

// A backup file name: one path segment of [A-Za-z0-9_.-], not "." or "..".
export function checkBackupName(name) {
  if (typeof name !== "string" || !/^[\w.-]+$/.test(name) || /^\.+$/.test(name)) {
    throw new StackError(`invalid backup file name ${name}`);
  }
  return name;
}

function runHelperWrite(location, name, data) {
  checkBackupName(name);
  runHelper({ mounts: [location.mount("/backup")], cmd: ["sh", "-c", 'cat > "/backup/$1"', "_", name], input: data, quiet: true, umask: BACKUP_UMASK });
}

// --- manifest authenticity (optional HMAC) -----------------------------------------------
//
// manifest.json gives INTEGRITY only: its sha256 per file catches a corrupted or truncated
// file, but anyone who can write the backup can rewrite the manifest to match (it is not
// signed), and pg_restore runs as the superuser. With BACKUP_MANIFEST_KEY set (>= 32 chars,
// kept apart from the backup and from .env, like the secrets checklist), `pnpm backup` also
// writes manifest.json.hmac (HMAC-SHA256 of the exact manifest bytes) and `pnpm restore`
// refuses a backup whose manifest is unsigned or does not verify, before any restore step.
export const MANIFEST_HMAC_FILE = "manifest.json.hmac";
const HMAC_PREFIX = "hmac-sha256:";
export const MIN_MANIFEST_KEY_CHARS = 32;

// The configured key (Buffer) or null when unset; throws on a key that is too short.
export function manifestKey(env) {
  const raw = env?.BACKUP_MANIFEST_KEY;
  if (!raw) return null;
  if (raw.length < MIN_MANIFEST_KEY_CHARS) {
    throw new StackError(`BACKUP_MANIFEST_KEY must be at least ${MIN_MANIFEST_KEY_CHARS} characters`, 2);
  }
  return Buffer.from(raw, "utf8");
}

export function signManifest(bytes, key) {
  return `${HMAC_PREFIX}${createHmac("sha256", key).update(bytes).digest("hex")}\n`;
}

// True when `signature` (the .hmac file content) is the HMAC of `bytes` under `key`.
export function verifyManifestSignature(bytes, signature, key) {
  const text = Buffer.isBuffer(signature) ? signature.toString("utf8") : String(signature ?? "");
  const m = /^hmac-sha256:([0-9a-f]{64})\s*$/.exec(text);
  if (!m) return false;
  const expected = createHmac("sha256", key).update(bytes).digest();
  return timingSafeEqual(Buffer.from(m[1], "hex"), expected);
}

// Checks manifest authenticity at `location`; returns "signed" or "unsigned". Throws (exit 2)
// when a key is configured and the signature is missing or wrong.
export function checkManifestAuthenticity(location, manifestBytes, env, { log = console.log } = {}) {
  const key = manifestKey(env);
  const signed = location.exists(MANIFEST_HMAC_FILE);
  if (!key) {
    log(
      signed
        ? `  warning: ${MANIFEST_HMAC_FILE} present but BACKUP_MANIFEST_KEY is not set: integrity only, authenticity NOT checked`
        : "  note: the manifest is unsigned: its hashes prove integrity, not authenticity (set BACKUP_MANIFEST_KEY to sign backups)",
    );
    return "unsigned";
  }
  if (!signed) throw new StackError(`BACKUP_MANIFEST_KEY is set but ${location.label} has no ${MANIFEST_HMAC_FILE}: refusing an unsigned backup`, 2);
  if (!verifyManifestSignature(manifestBytes, location.read(MANIFEST_HMAC_FILE), key)) {
    throw new StackError(`${MANIFEST_HMAC_FILE} does not verify with BACKUP_MANIFEST_KEY: the manifest was altered or signed with another key`, 2);
  }
  log("  ✔ manifest HMAC verified (BACKUP_MANIFEST_KEY)");
  return "signed";
}

// Sizes in bytes of named volumes (du inside a helper, read-only mounts).
export function volumeBytes(names) {
  const mounts = names.map((name, i) => ({ type: "volume", source: name, target: `/v${i}`, readonly: true }));
  const { stdout } = runHelper({ mounts, cmd: ["sh", "-c", 'for d in "$@"; do du -sk "$d" | cut -f1; done', "_", ...names.map((_, i) => `/v${i}`)], quiet: true });
  return stdout.toString().trim().split(/\s+/).map((kb) => Number(kb) * 1024);
}

export function volumeExists(name, { exec: runner = exec } = {}) {
  return runner("docker", ["volume", "inspect", name], { capture: true, allowFail: true, quiet: true }).status === 0;
}

// psql as `user` against the project's Postgres (helper container on its backend network);
// the password reaches it only as PGPASSWORD in the child env. Returns stdout text.
export function psql(project, sql, { user = "postgres", password, database = "cyberlab", mounts = [], allowFail = false } = {}) {
  const out = runHelper({
    network: networkName(project),
    env: { PGPASSWORD: password ?? "" },
    mounts,
    cmd: ["psql", "-X", "-h", "postgres", "-U", user, "-d", database, "-At", "-v", "ON_ERROR_STOP=1", "-f", "-"],
    input: sql,
    quiet: true,
    allowFail,
  });
  return { status: out.status, stdout: out.stdout.toString().trim(), stderr: out.stderr.toString() };
}

export function pgTool(project, cmd, { password, mounts = [], umask, chown } = {}) {
  return runHelper({ network: networkName(project), env: { PGPASSWORD: password ?? "" }, mounts, cmd, capture: true, umask, chown });
}

export function superuserUrl(env) {
  return `postgresql+asyncpg://postgres:${encodeURIComponent(env.POSTGRES_PASSWORD ?? "")}@postgres:5432/cyberlab`;
}

export function need(env, name) {
  const value = env[name];
  if (!value) throw new StackError(`${name} is not set (.env or the environment)`);
  return value;
}

// Parses `--flag value` / `--flag` arguments (after `pnpm <script> --`).
export function parseArgs(argv, { flags = [], options = [] } = {}) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--") continue;
    const name = arg.replace(/^--/, "");
    if (flags.includes(name)) out[name] = true;
    else if (options.includes(name)) {
      if (i + 1 >= argv.length) throw new StackError(`${arg} needs a value`, 2);
      out[name] = argv[++i];
    } else if (arg.startsWith("--")) throw new StackError(`unknown option ${arg}`, 2);
    else out._.push(arg);
  }
  return out;
}

export function isMain(metaUrl) {
  return process.argv[1] && resolve(process.argv[1]) === fileURLToPath(metaUrl);
}

export function formatBytes(n) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i ? 1 : 0)} ${units[i]}`;
}
