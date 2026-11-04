#!/usr/bin/env node
// The prod enrich-worker environment, as `docker compose -f docker-compose.yml -f
// docker-compose.prod.yml config` renders it, must equal the fixture that
// apps/api/tests/unit/test_config.py builds `Settings` from (review H1: a missing or extra
// variable there crash-looped the prod worker). Passwords and the site's seal key are masked.
// Also (M4 phase 7, RT2/RT3): neither the dev nor the prod enrich workers hold a JWT secret,
// MinIO credentials or the app Redis URL, and the prod one runs ENV=prod on the prod image.
//   node scripts/check-enrich-env.mjs           # compare (exit 1 on drift)
//   node scripts/check-enrich-env.mjs --write   # regenerate the fixture
import { execSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const FIXTURE = "apps/api/tests/fixtures/compose/enrich-worker.prod.env.json";
const KID = "prod-fixture";
const PUBLIC = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const FORBIDDEN = [/^JWT_/, /^MINIO_/, /^REDIS_URL$/, /^TEST_REDIS_URL$/, /^COOKIE_SECURE$/, /^TEST_/];

function render(command, service) {
  return JSON.parse(
    execSync(`${command} config --format json ${service}`, { stdio: ["ignore", "pipe", "inherit"] }).toString(),
  ).services[service];
}

const problems = [];
const prod = render("docker compose -f docker-compose.yml -f docker-compose.prod.yml", "enrich-worker");
const workers = {
  "prod enrich-worker": prod,
  "dev enrich-worker": render("docker compose", "enrich-worker"),
  "enrich-worker-test": render("docker compose --profile test", "enrich-worker-test"),
};
for (const [name, service] of Object.entries(workers)) {
  const leaked = Object.keys(service.environment ?? {}).filter((key) => FORBIDDEN.some((re) => re.test(key)));
  if (leaked.length) problems.push(`${name} holds ${leaked.join(", ")}`);
  if (service.environment?.PROCESS_ROLE !== "enrich") problems.push(`${name}: PROCESS_ROLE is not enrich`);
  const networks = Object.keys(service.networks ?? {}).sort().join(",");
  if (networks !== "egress,enrich") problems.push(`${name}: networks ${networks} (expected egress,enrich)`);
}
if (prod.environment?.ENV !== "prod") problems.push(`prod enrich-worker: ENV=${prod.environment?.ENV}`);
if (prod.image !== "cyberlab/api:prod") problems.push(`prod enrich-worker: image ${prod.image}`);
if (problems.length) {
  console.error(`enrich-worker configuration problems:\n  ${problems.join("\n  ")}`);
  process.exit(1);
}

const env = prod.environment ?? {};
const masked = {};
for (const name of Object.keys(env).sort()) {
  let value = String(env[name] ?? "");
  value = value.replace(/\/\/([^:/@]+):[^@]*@/, "//$1:masked@");
  if (name === "TI_SEAL_ACTIVE_KID") value = KID;
  if (name === "TI_SEAL_PUBLIC_KEYS") value = JSON.stringify({ [KID]: PUBLIC });
  masked[name] = value;
}
const text = `${JSON.stringify(masked, null, 2)}\n`;

if (process.argv.includes("--write")) {
  writeFileSync(FIXTURE, text);
  console.log(`wrote ${FIXTURE}`);
} else if (readFileSync(FIXTURE, "utf8") !== text) {
  console.error(`prod enrich-worker env drifted from ${FIXTURE}:\n${text}`);
  console.error("Review it, then run: node scripts/check-enrich-env.mjs --write");
  process.exit(1);
} else {
  console.log("enrich-worker envs hold no api secrets; prod env matches the tested fixture");
}
