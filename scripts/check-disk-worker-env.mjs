#!/usr/bin/env node
// M9 gate check (phase 13, `verify:prod`): the disk analyzer's isolation, as `docker compose
// config` renders the dev, test (+ e2e + tools) and prod stacks. Names and mounts are compared;
// secret values are never printed.
// - disk-worker (dev, prod) and disk-worker-test hold only BROKER_URL (the `disk` broker user;
//   the test service adds its non-secret test settings), sit on the `analysis` network only,
//   and mount only their work volume, the hash-set volume READ-ONLY and (dev / test) read-only
//   source binds. No DB URL, MinIO keys, app Redis, JWT, seal / signing / AI / TI key.
//   Read-only root, every capability dropped but the sandbox set, no new privileges.
// - disk-ingest-worker (dev, prod) and disk-ingest-worker-test consume only `ingest_disk`
//   (`test.ingest_disk`), hold the ingest worker's settings (the same names as `ingest-worker`
//   in that stack; the test one may add its test names), sit on `backend` only (never
//   `analysis`) and run PROCESS_ROLE=ingest.
// - disk-hashsets, disk-hashsets-test and disk-hashsets-init have `network_mode: none`, the
//   hash-set volume(s) and (the tool) the read-only import dir only; no environment secret.
// - no other service mounts a hash-set volume writable.
// - no service of any profile is privileged, adds SYS_ADMIN (or ALL), maps a device under
//   /dev/loop* / /dev/fuse or mounts /dev (the parent's no-loop-mount decision, RT26).
// - the disk image's tool user is uid 10007 (Dockerfile: user + CYBERLAB_TOOL_UID / GID).
// - prod: the prod images (`cyberlab/disk-worker:prod`, `cyberlab/api:prod`), no source bind.
// With `--image <tag>` (after the prod build) it also runs the image itself, offline and
// read-only: /etc/cyberlab/versions.json says target `prod`, and no Debian TSK / ewf / mkfs /
// mtools / ntfs-3g / sfdisk tool, TSK CLI or compiler is on the PATH or installed (the
// build-time assertion of docker/finalize_image.py, checked again on the built image), and
// `id -u tool` is 10007.
//   node scripts/check-disk-worker-env.mjs [--image cyberlab/disk-worker:prod]
import { execSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const TOOL_UID = 10007;
const WORKERS = {
  "disk-worker": { dev: ["BROKER_URL"], prod: ["BROKER_URL"] },
  "disk-worker-test": {
    test: [
      "BROKER_URL",
      "DISK_TIMELINE_ENGINE",
      "DISK_WORK_MIN_FREE_BYTES",
      "MYPY_CACHE_DIR",
      "QUEUE_PREFIX",
      "RUFF_CACHE_DIR",
      "TEST_PROFILE",
      "WORKER_QUEUE",
    ],
  },
};
const INGEST = { "disk-ingest-worker": "ingest_disk", "disk-ingest-worker-test": "test.ingest_disk" };
// The test ingest worker's own (non-secret or test-DB) overrides.
const INGEST_TEST_EXTRA = new Set(["ENV", "QUEUE_PREFIX", "DATABASE_URL", "REDIS_URL", "MINIO_BUCKET", "RESULTS_BUCKET"]);
const HASHSET_VOLUMES = new Set(["disk_hashsets", "disk_hashsets_test"]);
const HASHSET_TOOLS = {
  "disk-hashsets": { volumes: ["disk_hashsets"], importDir: true },
  "disk-hashsets-test": { volumes: ["disk_hashsets_test"], importDir: true },
  "disk-hashsets-init": { volumes: ["disk_hashsets", "disk_hashsets_test"], importDir: false },
};
const FORBIDDEN = [
  /DATABASE/,
  /POSTGRES/,
  /^JWT_/,
  /^MINIO_/,
  /^REDIS_URL$/,
  /SIGNING/,
  /SEAL/,
  /^AI_/,
  /^TI_/,
  /^GEMINI_/,
  /_KEY(S)?(_FILE)?$/,
  /PASSWORD/,
  /SECRET/,
  /TOKEN/,
];
const SANDBOX_CAPS = new Set(["SETUID", "SETGID", "KILL", "CHOWN", "DAC_OVERRIDE", "FOWNER"]);

function render(command) {
  return JSON.parse(execSync(`${command} config --format json`, { stdio: ["ignore", "pipe", "inherit"] }).toString());
}

function secretsOf(service) {
  return (service.secrets ?? []).map((s) => (typeof s === "string" ? s : s.source));
}

function userOf(url) {
  return /^[a-z+]+:\/\/([^:@/]+)[:@]/.exec(String(url ?? ""))?.[1] ?? "";
}

function networksOf(service) {
  return Object.keys(service.networks ?? {}).sort().join(",");
}

function volumesOf(service) {
  return (service.volumes ?? []).map((v) =>
    typeof v === "string"
      ? { type: v.startsWith(".") || v.startsWith("/") ? "bind" : "volume", source: v.split(":")[0], target: v.split(":")[1], read_only: v.endsWith(":ro") }
      : { type: v.type, source: v.source, target: v.target, read_only: v.read_only === true },
  );
}

function queuesOf(service) {
  const command = Array.isArray(service.command) ? service.command : String(service.command ?? "").split(/\s+/);
  const queues = [];
  command.forEach((arg, i) => {
    if (arg === "-Q" || arg === "--queues") queues.push(...String(command[i + 1] ?? "").split(","));
    else if (arg.startsWith("--queues=")) queues.push(...arg.slice(9).split(","));
  });
  return queues.filter(Boolean);
}

const problems = [];
const configs = {
  dev: render("docker compose"),
  test: render("docker compose --profile test --profile e2e --profile tools"),
  prod: render("docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile tools"),
};
const stacks = Object.fromEntries(Object.entries(configs).map(([stack, config]) => [stack, config.services ?? {}]));

for (const [stack, services] of Object.entries(stacks)) {
  for (const [name, service] of Object.entries(services)) {
    const label = `${stack} ${name}`;
    const env = service.environment ?? {};
    const volumes = volumesOf(service);

    // RT26: no privileged container, no SYS_ADMIN, no loop / FUSE device, in any profile.
    if (service.privileged === true) problems.push(`${label}: privileged`);
    const added = (service.cap_add ?? []).map((c) => String(c).toUpperCase().replace(/^CAP_/, ""));
    if (added.includes("SYS_ADMIN") || added.includes("ALL")) problems.push(`${label}: cap_add ${added.join(",")}`);
    for (const device of service.devices ?? []) {
      const source = typeof device === "string" ? device.split(":")[0] : String(device.source ?? "");
      if (/^\/dev\/(loop|fuse)/.test(source) || source === "/dev/loop-control") problems.push(`${label}: maps ${source}`);
    }
    if (volumes.some((v) => v.type === "bind" && /^\/dev(\/|$)/.test(String(v.source)))) problems.push(`${label}: mounts /dev`);

    // A hash-set volume is writable for its trusted tool (and the init) only.
    for (const v of volumes) {
      if (v.type === "volume" && HASHSET_VOLUMES.has(v.source) && !v.read_only && !(name in HASHSET_TOOLS)) {
        problems.push(`${label} mounts ${v.source} writable`);
      }
    }

    if (name in WORKERS) {
      const allowed = WORKERS[name][stack] ?? Object.values(WORKERS[name])[0];
      const keys = Object.keys(env).sort();
      const extra = keys.filter((key) => !allowed.includes(key));
      if (extra.length) problems.push(`${label} holds ${extra.join(", ")} (allowed: ${allowed.join(", ")})`);
      const leaked = keys.filter((key) => key !== "BROKER_URL" && FORBIDDEN.some((re) => re.test(key)));
      if (leaked.length) problems.push(`${label} holds the secret-like ${leaked.join(", ")}`);
      if (userOf(env.BROKER_URL) !== "disk") problems.push(`${label}: BROKER_URL is not the disk broker user`);
      if (networksOf(service) !== "analysis") problems.push(`${label}: networks ${networksOf(service)} (expected analysis)`);
      if (service.network_mode) problems.push(`${label}: network_mode ${service.network_mode}`);
      if (secretsOf(service).length) problems.push(`${label} mounts the secret(s) ${secretsOf(service).join(", ")}`);
      if (service.read_only !== true) problems.push(`${label}: root filesystem is not read-only`);
      if (!(service.cap_drop ?? []).includes("ALL")) problems.push(`${label}: capabilities are not dropped`);
      const extraCaps = added.filter((c) => !SANDBOX_CAPS.has(c));
      if (extraCaps.length) problems.push(`${label}: adds ${extraCaps.join(",")} beyond the sandbox set`);
      if (!(service.security_opt ?? []).some((o) => String(o).startsWith("no-new-privileges"))) {
        problems.push(`${label}: no-new-privileges is not set`);
      }
      const hashsets = name === "disk-worker-test" ? "disk_hashsets_test" : "disk_hashsets";
      for (const v of volumes) {
        if (v.type === "volume") {
          const ok = (v.source === "disk_work" && v.target === "/work") || (v.source === hashsets && v.target === "/hashsets" && v.read_only);
          if (!ok) problems.push(`${label}: unexpected volume ${v.source} -> ${v.target}${v.read_only ? " (ro)" : ""}`);
        } else if (v.type === "bind") {
          if (stack === "prod") problems.push(`${label}: prod bind-mounts ${v.target}`);
          else if (!v.read_only) problems.push(`${label}: writable bind ${v.target}`);
        } else if (v.type !== "tmpfs") {
          problems.push(`${label}: unexpected ${v.type} mount ${v.target}`);
        }
      }
      if (!volumes.some((v) => v.source === hashsets && v.read_only)) problems.push(`${label}: no read-only ${hashsets} mount`);
      continue;
    }

    if (name in INGEST) {
      const queues = queuesOf(service);
      if (queues.join(",") !== INGEST[name]) problems.push(`${label}: consumes ${queues.join(",") || "(default queues)"} (expected ${INGEST[name]} only)`);
      if (networksOf(service) !== "backend") problems.push(`${label}: networks ${networksOf(service)} (expected backend)`);
      if (env.PROCESS_ROLE !== "ingest") problems.push(`${label}: PROCESS_ROLE is not ingest`);
      if (userOf(env.BROKER_URL) !== "ingest") problems.push(`${label}: BROKER_URL is not the ingest broker user`);
      // The ingest worker's settings, nothing more: the same names as that stack's
      // ingest-worker (the test one may add its test names only).
      const reference = name === "disk-ingest-worker" ? services["ingest-worker"] : services["disk-ingest-worker"];
      if (!reference) {
        problems.push(`${label}: no reference service to compare with`);
      } else {
        const want = new Set(Object.keys(reference.environment ?? {}));
        const have = new Set(Object.keys(env));
        const extra = [...have].filter((k) => !want.has(k) && !(name.endsWith("-test") && INGEST_TEST_EXTRA.has(k)));
        const missing = [...want].filter((k) => !have.has(k));
        if (extra.length) problems.push(`${label} holds ${extra.sort().join(", ")} beyond the ingest worker's settings`);
        if (missing.length) problems.push(`${label} lacks ${missing.sort().join(", ")} of the ingest worker's settings`);
      }
      continue;
    }

    if (name in HASHSET_TOOLS) {
      const rule = HASHSET_TOOLS[name];
      if (service.network_mode !== "none") problems.push(`${label}: network_mode ${service.network_mode ?? "(default)"} (expected none)`);
      if (Object.keys(service.networks ?? {}).length) problems.push(`${label}: joins ${networksOf(service)}`);
      const leaked = Object.keys(env).filter((key) => FORBIDDEN.some((re) => re.test(key)));
      if (leaked.length) problems.push(`${label} holds the secret-like ${leaked.join(", ")}`);
      if (secretsOf(service).length) problems.push(`${label} mounts the secret(s) ${secretsOf(service).join(", ")}`);
      for (const v of volumes) {
        if (v.type === "volume" && !rule.volumes.includes(v.source)) problems.push(`${label}: unexpected volume ${v.source}`);
        if (v.type === "bind") {
          const importBind = rule.importDir && v.target === "/import" && v.read_only;
          if (!importBind) problems.push(`${label}: unexpected bind ${v.target}${v.read_only ? " (ro)" : " (rw)"}`);
        }
      }
      for (const wanted of rule.volumes) {
        if (!volumes.some((v) => v.type === "volume" && v.source === wanted)) problems.push(`${label}: no ${wanted} mount`);
      }
    }
  }
}

for (const name of ["disk-worker", "disk-ingest-worker"]) {
  for (const stack of ["dev", "prod"]) {
    if (!stacks[stack][name]) problems.push(`${stack}: no ${name} service`);
  }
}
for (const name of ["disk-worker-test", "disk-ingest-worker-test", "disk-hashsets", "disk-hashsets-test", "disk-hashsets-init"]) {
  if (!stacks.test[name]) problems.push(`test: no ${name} service`);
}
if (stacks.prod["disk-worker"]?.image !== "cyberlab/disk-worker:prod") {
  problems.push(`prod disk-worker: image ${stacks.prod["disk-worker"]?.image}`);
}
if (stacks.prod["disk-ingest-worker"]?.image !== "cyberlab/api:prod") {
  problems.push(`prod disk-ingest-worker: image ${stacks.prod["disk-ingest-worker"]?.image}`);
}
if (stacks.prod["disk-ingest-worker"]?.environment?.ENV !== "prod") problems.push("prod disk-ingest-worker: ENV is not prod");
for (const name of ["disk-hashsets", "disk-hashsets-init"]) {
  if (stacks.prod[name] && stacks.prod[name].image !== "cyberlab/disk-worker:prod") {
    problems.push(`prod ${name}: image ${stacks.prod[name].image}`);
  }
}

// The tool user of the disk image (RLIMIT_NPROC is per uid: its own uid, never shared).
const dockerfile = readFileSync(resolve("apps/workers/disk/Dockerfile"), "utf8");
if (!new RegExp(`useradd[^\\n]*--uid ${TOOL_UID}[^\\n]*\\btool\\b`).test(dockerfile)) {
  problems.push(`apps/workers/disk/Dockerfile: the tool user is not uid ${TOOL_UID}`);
}
for (const name of ["CYBERLAB_TOOL_UID", "CYBERLAB_TOOL_GID"]) {
  if (!new RegExp(`${name}=${TOOL_UID}\\b`).test(dockerfile)) problems.push(`apps/workers/disk/Dockerfile: ${name} is not ${TOOL_UID}`);
}

// --image <tag>: the built prod image itself (offline, read-only, no capability).
const imageIndex = process.argv.indexOf("--image");
if (imageIndex !== -1) {
  const image = process.argv[imageIndex + 1];
  if (!image) {
    console.error("--image needs an image tag");
    process.exit(2);
  }
  const probe = [
    "import json, shutil, subprocess, sys",
    "v = json.load(open('/etc/cyberlab/versions.json'))",
    "bad = []",
    "bad += [] if v.get('target') == 'prod' else ['versions.json target ' + str(v.get('target'))]",
    "tools = ['fls','icat','mmls','fsstat','tsk_recover','srch_strings','ewfverify','ewfacquirestream','ewfinfo','mkfs.fat','mkfs.vfat','mkfs.ext4','mke2fs','debugfs','mkfs.exfat','mkntfs','ntfscp','ntfs-3g','mcopy','mmd','mtools','sfdisk','cc','gcc','c++','g++','clang','make']",
    "bad += ['on PATH: ' + t for t in tools if shutil.which(t)]",
    "pkgs = ['sleuthkit','python3-tsk','libtsk19','ewf-tools','mtools','ntfs-3g','dosfstools','exfatprogs','e2fsprogs-l10n','gcc','cpp','build-essential','libhivex-bin']",
    "q = subprocess.run(['dpkg-query','-W','-f','${Package} ${Status}\\n'] + pkgs, capture_output=True, text=True)",
    "bad += ['installed: ' + l.split()[0] for l in q.stdout.splitlines() if l.endswith('install ok installed')]",
    "uid = subprocess.run(['id','-u','tool'], capture_output=True, text=True).stdout.strip()",
    `bad += [] if uid == '${TOOL_UID}' else ['tool uid ' + uid]`,
    "print(json.dumps({k: v[k] for k in sorted(v)}))",
    "print('\\n'.join(bad)); sys.exit(1 if bad else 0)",
  ].join("\n");
  const run = spawnSync(
    "docker",
    ["run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--entrypoint", "python", image, "-c", probe],
    { encoding: "utf8" },
  );
  if (run.status !== 0) {
    problems.push(`${image}: ${(run.stdout + run.stderr).trim().split(/\r?\n/).slice(1).join("; ") || `exit ${run.status}`}`);
  } else {
    console.log(`  ${image}: ${run.stdout.trim().split(/\r?\n/)[0]}`);
  }
}

if (problems.length) {
  console.error(`disk worker configuration problems:\n  ${problems.join("\n  ")}`);
  process.exit(1);
}
console.log(
  "disk envs: worker BROKER_URL only on analysis with the hash sets read-only; ingest on ingest_disk / backend; hash-set tools offline; no privileged / SYS_ADMIN / loop / FUSE; tool uid 10007" +
    (imageIndex !== -1 ? "; prod image has no image tools or compiler" : ""),
);
