#!/usr/bin/env node
// M7 gate check (phase 11, `verify:prod`): the retention role stays least-privilege, as
// `docker compose config` renders the dev, test and prod stacks (names and roles are compared;
// secret values are never printed):
// - retention-worker (dev, prod) and retention-worker-test hold only their own settings: the
//   `cyberlab_retention` DB URL, the `retention` broker user, the purge MinIO keys and the
//   bucket / delay settings. No JWT secret, app Redis, api or root MinIO keys, seal / signing /
//   AI / TI / platform key or metrics token; PROCESS_ROLE=retention; the `backend` network
//   only; no secret mounted; read-only root, every capability dropped. Prod: the prod image,
//   ENV=prod, no source mount, and no change-me password.
// - no other runtime service holds the purge keys, the retention DB password or URL, or the
//   retention broker password. Allowed: the services that create those users (postgres and
//   db-bootstrap: the DB role; redis-broker: the broker ACL; minio-init: the purge user) and
//   the test profile (`api-test` runs the purge in-process with the test equivalents, as it
//   already holds the MinIO root, RT27).
// - the api MinIO policy grants no legal-hold or governance-bypass action (RT5); the gateway
//   routes nothing outside /api and the web app (/internal/metrics is unreachable);
// - the KMS key is mounted on minio (and minio-init, which only reads its name) only, the
//   metrics token on api only; prod uses the .secrets/ files, whose KMS key is not the
//   committed dev key and whose metrics token is not the dev token.
//   node scripts/check-retention-worker-env.mjs
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const WORKERS = ["retention-worker", "retention-worker-test"];
const ALLOWED = new Set([
  "ENV",
  "PROCESS_ROLE",
  "DATABASE_URL",
  "BROKER_URL",
  "QUEUE_PREFIX",
  "UV_NO_SYNC",
  "UV_OFFLINE",
  "MINIO_ENDPOINT",
  "MINIO_BUCKET",
  "RESULTS_BUCKET",
  "REPORTS_BUCKET",
  "MINIO_PURGE_ACCESS_KEY",
  "MINIO_PURGE_SECRET_KEY",
  "EVIDENCE_LOCK_DAYS",
  "RETENTION_POLICY_DELAY_DAYS",
]);
const FORBIDDEN = [
  /^JWT_/,
  /^REDIS_URL$/,
  /^MINIO_(ACCESS|SECRET)_KEY$/,
  /^MINIO_ROOT_/,
  /SEAL/,
  /SIGNING/,
  /^AI_/,
  /^TI_/,
  /^GEMINI_/,
  /METRICS_TOKEN/,
  /_KEYS?_FILE$/,
  /MIGRATION/,
];
// Services that create the retention users (and so hold their secrets), and the test profile.
const CREATORS = {
  postgres: ["POSTGRES_RETENTION_PASSWORD"],
  "db-bootstrap": ["POSTGRES_RETENTION_PASSWORD"],
  "redis-broker": ["BROKER_RETENTION_PASSWORD"],
  "minio-init": ["MINIO_PURGE_ACCESS_KEY", "MINIO_PURGE_SECRET_KEY"],
};
const TEST_PROFILE = new Set(["api-test", "e2e"]);
const RETENTION_NAMES = ["MINIO_PURGE_ACCESS_KEY", "MINIO_PURGE_SECRET_KEY", "POSTGRES_RETENTION_PASSWORD", "BROKER_RETENTION_PASSWORD"];
const KMS_HOLDERS = new Set(["minio", "minio-init"]);
const DEV_KMS_KEY_NAME = "cyberlab-dev-kms";

function render(command) {
  return JSON.parse(execSync(`${command} config --format json`, { stdio: ["ignore", "pipe", "inherit"] }).toString());
}

function secretsOf(service) {
  return (service.secrets ?? []).map((s) => (typeof s === "string" ? s : s.source));
}

function userOf(url) {
  return /^[a-z+]+:\/\/([^:@/]+)[:@]/.exec(String(url ?? ""))?.[1] ?? "";
}

function passwordOf(url) {
  return /^[a-z+]+:\/\/[^:@/]+:([^@]*)@/.exec(String(url ?? ""))?.[1] ?? "";
}

const problems = [];
const configs = {
  dev: render("docker compose"),
  test: render("docker compose --profile test --profile e2e"),
  prod: render("docker compose -f docker-compose.yml -f docker-compose.prod.yml"),
};

for (const [stack, config] of Object.entries(configs)) {
  const services = config.services;
  if (!services["retention-worker"]) problems.push(`${stack}: no retention-worker service`);
  if (stack === "test" && !services["retention-worker-test"]) problems.push("test: no retention-worker-test service");
  // The values that identify the retention role in this stack (compared, never printed).
  const secretValues = new Set();
  for (const name of WORKERS) {
    const service = services[name];
    if (!service) continue;
    const env = service.environment ?? {};
    const label = `${stack} ${name}`;
    const keys = Object.keys(env).sort();
    const extra = keys.filter((key) => !ALLOWED.has(key));
    if (extra.length) problems.push(`${label} holds ${extra.join(", ")} (not a retention-worker setting)`);
    const leaked = keys.filter((key) => FORBIDDEN.some((re) => re.test(key)));
    if (leaked.length) problems.push(`${label} holds the forbidden ${leaked.join(", ")}`);
    if (env.PROCESS_ROLE !== "retention") problems.push(`${label}: PROCESS_ROLE is not retention`);
    if (userOf(env.DATABASE_URL) !== "cyberlab_retention") problems.push(`${label}: DATABASE_URL is not the cyberlab_retention role`);
    if (userOf(env.BROKER_URL) !== "retention") problems.push(`${label}: BROKER_URL is not the retention broker user`);
    if (!env.MINIO_PURGE_ACCESS_KEY || !env.MINIO_PURGE_SECRET_KEY) problems.push(`${label}: no purge MinIO keys`);
    const networks = Object.keys(service.networks ?? {}).sort().join(",");
    if (networks !== "backend") problems.push(`${label}: networks ${networks || "(none)"} (expected backend only)`);
    if (secretsOf(service).length) problems.push(`${label} mounts the secret(s) ${secretsOf(service).join(", ")}`);
    if (service.read_only !== true) problems.push(`${label}: root filesystem is not read-only`);
    if (!(service.cap_drop ?? []).includes("ALL")) problems.push(`${label}: capabilities are not dropped`);
    if (service.ports?.length) problems.push(`${label} publishes ports`);
    for (const value of [env.MINIO_PURGE_SECRET_KEY, passwordOf(env.DATABASE_URL), passwordOf(env.BROKER_URL)]) {
      if (value) secretValues.add(String(value));
    }
    if (name === "retention-worker") {
      const api = services.api?.environment ?? {};
      if (api.MINIO_ACCESS_KEY && api.MINIO_ACCESS_KEY === env.MINIO_PURGE_ACCESS_KEY) {
        problems.push(`${label}: the purge MinIO user is the api user`);
      }
    }
  }

  for (const [name, service] of Object.entries(services)) {
    if (WORKERS.includes(name) || TEST_PROFILE.has(name)) continue;
    const env = service.environment ?? {};
    const allowed = CREATORS[name] ?? [];
    const held = RETENTION_NAMES.filter((key) => key in env && !allowed.includes(key));
    if (held.length) problems.push(`${stack} ${name} holds ${held.join(", ")}`);
    for (const [key, value] of Object.entries(env)) {
      const text = String(value ?? "");
      if (allowed.includes(key)) continue;
      if (/cyberlab_retention[:@]/.test(text) || /redis:\/\/retention:/.test(text)) {
        problems.push(`${stack} ${name}: ${key} carries a retention credential`);
      } else if ([...secretValues].some((secret) => secret.length >= 8 && text.includes(secret))) {
        problems.push(`${stack} ${name}: ${key} carries a retention secret value`);
      }
    }
    if (secretsOf(service).includes("minio_kms_key") && !KMS_HOLDERS.has(name)) {
      problems.push(`${stack} ${name} mounts minio_kms_key`);
    }
    if (secretsOf(service).includes("metrics_token") && name !== "api") {
      problems.push(`${stack} ${name} mounts metrics_token`);
    }
  }
}

// Prod: the prod image, ENV=prod, no source mount, no change-me password.
const prodWorker = configs.prod.services["retention-worker"];
const prodEnv = prodWorker?.environment ?? {};
if (prodWorker?.image !== "cyberlab/api:prod") problems.push(`prod retention-worker: image ${prodWorker?.image}`);
if (prodEnv.ENV !== "prod") problems.push("prod retention-worker: ENV is not prod");
if ((prodWorker?.volumes ?? []).length) problems.push("prod retention-worker mounts volumes (the source tree)");
for (const [what, value] of [
  ["the DB password", passwordOf(prodEnv.DATABASE_URL)],
  ["the broker password", passwordOf(prodEnv.BROKER_URL)],
  ["the purge secret", prodEnv.MINIO_PURGE_SECRET_KEY],
]) {
  if (!value || String(value).startsWith("change-me")) problems.push(`prod retention-worker: ${what} is empty or a change-me default`);
}
if (configs.dev.services["retention-worker"]?.image !== "cyberlab/api:dev") problems.push("dev retention-worker: not the dev image");

// RT5: the api MinIO user can never clear (or set) an S3 legal hold or bypass GOVERNANCE.
const apiPolicy = readFileSync(resolve("infra/minio/api-policy.template.json"), "utf8");
if (/LegalHold|BypassGovernance|s3:\*/.test(apiPolicy)) {
  problems.push("infra/minio/api-policy.template.json grants a legal-hold, bypass or wildcard action");
}
const purgePolicy = readFileSync(resolve("infra/minio/purge-policy.template.json"), "utf8");
if (/BypassGovernance|PutObject"|PutObjectRetention|s3:\*/.test(purgePolicy)) {
  problems.push("infra/minio/purge-policy.template.json grants PutObject, retention, bypass or a wildcard");
}

// The gateway proxies /api/* (and the evidence upload under it) to the api, the rest to web:
// /internal/metrics is never routed to the api.
const caddy = ["Caddyfile", "Caddyfile.prod", "common.caddy"]
  .map((name) => readFileSync(resolve("infra/caddy", name), "utf8"))
  .join("\n");
if (/\/internal/.test(caddy)) problems.push("infra/caddy routes an /internal path");
const apiHandles = [...caddy.matchAll(/handle\s+(\S+)\s*\{[^}]*?reverse_proxy\s+api:8000/gs)].map((m) => m[1]);
const unexpected = apiHandles.filter((h) => h !== "/api/*" && h !== "@evidence_upload");
if (unexpected.length) problems.push(`infra/caddy proxies ${unexpected.join(", ")} to the api`);
if (!/@evidence_upload\s*\{[^}]*path_regexp \^\/api\//s.test(caddy)) problems.push("infra/caddy: @evidence_upload is not under /api/");

// Prod secrets: the .secrets/ files; the KMS key is not the committed dev key, the metrics token
// is not the dev token (contents are read, never printed).
const prodSecrets = configs.prod.secrets ?? {};
const fileOf = (name) => String(prodSecrets[name]?.file ?? "").replaceAll("\\", "/");
if (!fileOf("minio_kms_key").endsWith(".secrets/minio_kms_key")) problems.push("prod: minio_kms_key is not .secrets/minio_kms_key");
if (!fileOf("metrics_token").endsWith(".secrets/metrics_token")) problems.push("prod: metrics_token is not .secrets/metrics_token");
function contents(path) {
  try {
    return readFileSync(path, "utf8").trim();
  } catch {
    return null;
  }
}
const kms = contents(fileOf("minio_kms_key"));
if (kms === null) problems.push("prod: the KMS key file is missing");
else if (kms.split(":")[0] === DEV_KMS_KEY_NAME || kms === contents(resolve("infra/minio/dev-kms-key"))) {
  problems.push(`prod: the KMS key is the committed dev key (${DEV_KMS_KEY_NAME})`);
}
const token = contents(fileOf("metrics_token"));
const devToken = contents(resolve("infra/ops/dev-metrics-token"));
if (token !== null && (token === "" || token === devToken)) problems.push("prod: the metrics token is empty or the dev token");

if (problems.length) {
  console.error(`retention-worker configuration problems:\n  ${problems.join("\n  ")}`);
  process.exit(1);
}
console.log(
  "retention-worker envs: retention DB role, retention broker user and purge keys only, backend only, no secrets; retention credentials on their creators and the test profile only; api policy without legal hold; no /internal route; prod KMS key and metrics token are not the dev ones",
);
