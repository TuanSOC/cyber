#!/usr/bin/env node
// The memory analyzer's and the symbol tool's configuration (M8 phase 11), as `docker compose
// config` renders the dev (+test, tools) and prod stacks:
// - memory-worker holds only BROKER_URL as the `memory` broker user (memory-worker-test: plus
//   its non-secret test switches), is on the `analysis` network only, and its only named
//   volumes are its work volume and the symbol store, mounted read-only; no DB, MinIO, JWT,
//   app Redis or other secret-like name, no secret mount; read-only root, capabilities dropped;
// - memory-symbols / memory-symbols-test have no environment, the `symbols_egress` network
//   only (no broker, backend, analysis or shared egress), their symbol volume and the
//   read-only import dir, and run as uid 10005;
// - no other service is on `symbols_egress` or mounts a symbol volume read-write (the
//   one-shot, network-less `memory-symbols-init` chown is the only exception);
// - the memory image's tool uid is 10006 (Dockerfile), not the analyzers' 10003.
// Names only are compared: values are never printed.
//   node scripts/check-memory-worker-env.mjs
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";

const WORKERS = {
  "memory-worker": { env: ["BROKER_URL"], work: "memory_work", store: "memory_symbols" },
  "memory-worker-test": {
    env: ["BROKER_URL", "MEMORY_ENGINE", "MYPY_CACHE_DIR", "QUEUE_PREFIX", "RUFF_CACHE_DIR", "TEST_PROFILE", "WORKER_QUEUE"],
    work: null, // a per-container tmpfs /work (RT6)
    store: "memory_symbols_test",
  },
};
const TOOLS = { "memory-symbols": "memory_symbols", "memory-symbols-test": "memory_symbols_test" };
const SYMBOL_VOLUMES = new Set(["memory_symbols", "memory_symbols_test"]);
const RW_SYMBOLS_ALLOWED = new Set(["memory-symbols", "memory-symbols-test", "memory-symbols-init"]);
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
  /_KEY(S)?(_FILE)?$/,
  /PASSWORD/,
  /SECRET/,
  /TOKEN/,
];

function render(command) {
  return JSON.parse(execSync(`${command} config --format json`, { stdio: ["ignore", "pipe", "inherit"] }).toString());
}

function named(service) {
  return (service.volumes ?? []).filter((v) => v.type === "volume");
}

function secretsOf(service) {
  return (service.secrets ?? []).map((s) => (typeof s === "string" ? s : s.source));
}

const problems = [];
const stacks = {
  dev: render("docker compose --profile test --profile tools").services,
  prod: render("docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile tools").services,
};

for (const [stack, services] of Object.entries(stacks)) {
  for (const [name, rule] of Object.entries(WORKERS)) {
    const service = services[name];
    if (!service) {
      if (stack === "dev" || name === "memory-worker") problems.push(`${stack}: no ${name} service`);
      continue;
    }
    const label = `${stack} ${name}`;
    const env = service.environment ?? {};
    const keys = Object.keys(env).sort();
    const extra = keys.filter((key) => !rule.env.includes(key));
    if (extra.length) problems.push(`${label} holds ${extra.join(", ")} (allowed: ${rule.env.join(", ")})`);
    const leaked = keys.filter((key) => key !== "BROKER_URL" && FORBIDDEN.some((re) => re.test(key)));
    if (leaked.length) problems.push(`${label} holds the secret-like ${leaked.join(", ")}`);
    if (!String(env.BROKER_URL ?? "").startsWith("redis://memory:")) problems.push(`${label}: BROKER_URL is not the memory user`);
    const networks = Object.keys(service.networks ?? {}).sort().join(",");
    if (networks !== "analysis") problems.push(`${label}: networks ${networks} (expected analysis)`);
    if (secretsOf(service).length) problems.push(`${label} mounts the secret(s) ${secretsOf(service).join(", ")}`);
    if (service.read_only !== true) problems.push(`${label}: root filesystem is not read-only`);
    if (!(service.cap_drop ?? []).includes("ALL")) problems.push(`${label}: capabilities are not dropped`);
    const volumes = named(service);
    const expected = [rule.work, rule.store].filter(Boolean).sort();
    const got = volumes.map((v) => v.source).sort();
    if (got.join(",") !== expected.join(",")) problems.push(`${label}: named volumes ${got.join(",")} (expected ${expected.join(",")})`);
    const store = volumes.find((v) => v.source === rule.store);
    if (store && (store.read_only !== true || store.target !== "/symbols")) problems.push(`${label}: the symbol store is not read-only at /symbols`);
  }

  for (const [name, volume] of Object.entries(TOOLS)) {
    const service = services[name];
    if (!service) {
      problems.push(`${stack}: no ${name} service (profile tools)`);
      continue;
    }
    const label = `${stack} ${name}`;
    const keys = Object.keys(service.environment ?? {});
    if (keys.length) problems.push(`${label} holds ${keys.join(", ")} (expected no environment)`);
    const networks = Object.keys(service.networks ?? {}).sort().join(",");
    if (networks !== "symbols_egress") problems.push(`${label}: networks ${networks} (expected symbols_egress only)`);
    if (service.user !== "10005:10005") problems.push(`${label}: user ${service.user} (expected 10005:10005)`);
    if (secretsOf(service).length) problems.push(`${label} mounts the secret(s) ${secretsOf(service).join(", ")}`);
    const volumes = named(service).map((v) => `${v.source}:${v.target}:${v.read_only ? "ro" : "rw"}`);
    if (volumes.join(",") !== `${volume}:/symbols:rw`) problems.push(`${label}: named volumes ${volumes.join(",")}`);
    const binds = (service.volumes ?? []).filter((v) => v.type === "bind");
    if (binds.length !== 1 || binds[0].target !== "/import" || binds[0].read_only !== true) {
      problems.push(`${label}: binds other than the read-only /import`);
    }
  }

  for (const [name, service] of Object.entries(services)) {
    const networks = Object.keys(service.networks ?? {});
    if (networks.includes("symbols_egress") && !(name in TOOLS)) problems.push(`${stack} ${name} is on symbols_egress`);
    for (const v of named(service)) {
      if (SYMBOL_VOLUMES.has(v.source) && !v.read_only && !RW_SYMBOLS_ALLOWED.has(name)) {
        problems.push(`${stack} ${name} mounts ${v.source} read-write`);
      }
    }
  }
  const init = services["memory-symbols-init"];
  if (init && Object.keys(init.networks ?? {}).length && init.network_mode !== "none") {
    problems.push(`${stack} memory-symbols-init has a network`);
  }
}

const prodWorker = stacks.prod["memory-worker"];
if (prodWorker?.image !== "cyberlab/memory-worker:prod") problems.push(`prod memory-worker: image ${prodWorker?.image}`);
const dockerfile = readFileSync("apps/workers/memory/Dockerfile", "utf8");
if (!/CYBERLAB_TOOL_UID=10006\b/.test(dockerfile) || !/--uid 10006\b/.test(dockerfile)) {
  problems.push("memory image: the tool uid is not 10006");
}

if (problems.length) {
  console.error(`memory-worker configuration problems:\n  ${problems.join("\n  ")}`);
  process.exit(1);
}
console.log(
  "memory-worker envs: BROKER_URL only, analysis only, work + read-only symbols; memory-symbols on symbols_egress only, uid 10005; tool uid 10006",
);
