#!/usr/bin/env node
// The AI analyst worker's environment (M5 phase 11), as `docker compose config` renders it:
// - the prod analyst-worker env equals the fixture apps/api/tests/unit/test_config.py builds
//   `Settings` from (a missing or extra variable crash-loops the prod worker; review H1 of M4).
//   Passwords and the site's AI seal key are masked;
// - no analyst worker (dev, test, prod) holds a JWT secret, MinIO credentials, the app Redis
//   URL or the TI private key file, and each runs PROCESS_ROLE=analyst on `enrich` + `egress`;
// - no other service anywhere holds the AI private key file or the platform key file, nor
//   the `ai_seal_private` / `ai_platform_key` secrets (and no analyst the `ti_seal_private`);
// - prod: ENV=prod, the prod image, the mock off, no platform key, no ai-mock service.
//   node scripts/check-analyst-env.mjs           # compare (exit 1 on drift)
//   node scripts/check-analyst-env.mjs --write   # regenerate the fixture
import { execSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const FIXTURE = "apps/api/tests/fixtures/compose/analyst-worker.prod.env.json";
const KID = "prod-ai-fixture";
const PUBLIC = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
const FORBIDDEN = [
  /^JWT_/,
  /^MINIO_/,
  /^REDIS_URL$/,
  /^TEST_REDIS_URL$/,
  /^COOKIE_SECURE$/,
  /^TEST_/,
  /^TI_SEAL_PRIVATE_KEYS_FILE$/,
];
const AI_ONLY = ["AI_SEAL_PRIVATE_KEYS_FILE", "AI_PLATFORM_KEY_FILE"];
const AI_SECRETS = ["ai_seal_private", "ai_platform_key"];
const ANALYSTS = new Set(["analyst-worker", "analyst-worker-test"]);

function render(command) {
  return JSON.parse(execSync(`${command} config --format json`, { stdio: ["ignore", "pipe", "inherit"] }).toString())
    .services;
}

function secretsOf(service) {
  return (service.secrets ?? []).map((s) => (typeof s === "string" ? s : s.source));
}

const problems = [];
const stacks = {
  dev: render("docker compose"),
  test: render("docker compose --profile test --profile e2e"),
  prod: render("docker compose -f docker-compose.yml -f docker-compose.prod.yml"),
};
for (const [stack, services] of Object.entries(stacks)) {
  for (const [name, service] of Object.entries(services)) {
    const env = service.environment ?? {};
    const label = `${stack} ${name}`;
    if (ANALYSTS.has(name)) {
      const leaked = Object.keys(env).filter((key) => FORBIDDEN.some((re) => re.test(key)));
      if (leaked.length) problems.push(`${label} holds ${leaked.join(", ")}`);
      if (env.PROCESS_ROLE !== "analyst") problems.push(`${label}: PROCESS_ROLE is not analyst`);
      const networks = Object.keys(service.networks ?? {}).sort().join(",");
      if (networks !== "egress,enrich") problems.push(`${label}: networks ${networks} (expected egress,enrich)`);
      if (secretsOf(service).includes("ti_seal_private")) problems.push(`${label} holds the TI private key`);
      if (!secretsOf(service).includes("ai_seal_private")) problems.push(`${label} lacks ai_seal_private`);
      continue;
    }
    const held = AI_ONLY.filter((key) => key in env);
    if (held.length) problems.push(`${label} holds ${held.join(", ")}`);
    const secrets = secretsOf(service).filter((s) => AI_SECRETS.includes(s));
    if (secrets.length) problems.push(`${label} holds the secret(s) ${secrets.join(", ")}`);
  }
}
const prod = stacks.prod["analyst-worker"];
const env = prod?.environment ?? {};
if (!prod) problems.push("prod: no analyst-worker service");
if (env.ENV !== "prod") problems.push(`prod analyst-worker: ENV=${env.ENV}`);
if (prod?.image !== "cyberlab/api:prod") problems.push(`prod analyst-worker: image ${prod?.image}`);
if (env.AI_MOCK_ENABLED !== "false") problems.push("prod analyst-worker: AI_MOCK_ENABLED is not false");
if (env.AI_PLATFORM_PROVIDER) problems.push("prod analyst-worker: AI_PLATFORM_PROVIDER is set");
if ("AI_PLATFORM_KEY_FILE" in env) problems.push("prod analyst-worker: AI_PLATFORM_KEY_FILE is set");
if (secretsOf(prod ?? {}).includes("ai_platform_key")) problems.push("prod analyst-worker: platform key secret");
if (stacks.prod["ai-mock"]) problems.push("prod: the ai-mock service is part of the default stack");
if (stacks.prod.api?.environment?.AI_MOCK_ENABLED !== "false") problems.push("prod api: AI_MOCK_ENABLED is not false");
if (problems.length) {
  console.error(`analyst-worker configuration problems:\n  ${problems.join("\n  ")}`);
  process.exit(1);
}

const masked = {};
for (const name of Object.keys(env).sort()) {
  let value = String(env[name] ?? "");
  value = value.replace(/\/\/([^:/@]+):[^@]*@/, "//$1:masked@");
  if (name === "AI_SEAL_ACTIVE_KID") value = KID;
  if (name === "AI_SEAL_PUBLIC_KEYS") value = JSON.stringify({ [KID]: PUBLIC });
  masked[name] = value;
}
const text = `${JSON.stringify(masked, null, 2)}\n`;

if (process.argv.includes("--write")) {
  writeFileSync(FIXTURE, text);
  console.log(`wrote ${FIXTURE}`);
} else if (readFileSync(FIXTURE, "utf8") !== text) {
  console.error(`prod analyst-worker env drifted from ${FIXTURE}:\n${text}`);
  console.error("Review it, then run: node scripts/check-analyst-env.mjs --write");
  process.exit(1);
} else {
  console.log("analyst-worker envs: no api/TI secrets, AI keys only there, prod env matches the tested fixture");
}
