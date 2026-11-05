#!/usr/bin/env node
// The untrusted report renderer's configuration (M6 phase 9, RT21), as `docker compose
// config` renders the dev, test and prod stacks:
// - report-worker (dev) holds only BROKER_URL, the prod one only BROKER_URL and ENV=prod,
//   report-worker-test only BROKER_URL plus its non-secret test settings; each is on the
//   `analysis` network only, with no secret mounted and a `report` broker user;
// - none of them holds a DB URL, JWT, MinIO keys, signing material, AI or TI keys, or the
//   app Redis URL (names only are compared: values are never printed);
// - the signing private key (REPORT_SIGNING_KEYS_FILE, secret `report_signing_private`)
//   is on `api` only; the public signing settings on `api` and `api-test` only;
// - prod: the prod image, ENV=prod, and the api's active kid and public keys carry no
//   `dev-` kid and not the committed dev public key (the startup check refuses it too).
//   node scripts/check-report-worker-env.mjs
import { execSync } from "node:child_process";

const DEV_PUBLIC = "zS2iP9napZDeshJwfCiTwYl8amzPuWJEJwHK8CpnF2k=";
const ALLOWED = {
  "report-worker": { dev: ["BROKER_URL"], prod: ["BROKER_URL", "ENV"] },
  "report-worker-test": {
    test: ["BROKER_URL", "MYPY_CACHE_DIR", "QUEUE_PREFIX", "RUFF_CACHE_DIR", "WORKER_QUEUE"],
  },
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
  /_KEY(S)?(_FILE)?$/,
  /PASSWORD/,
  /SECRET/,
];
const PRIVATE_ONLY = new Set(["api"]);
const PUBLIC_ONLY = new Set(["api", "api-test"]);

function render(command) {
  return JSON.parse(execSync(`${command} config --format json`, { stdio: ["ignore", "pipe", "inherit"] }).toString());
}

function secretsOf(service) {
  return (service.secrets ?? []).map((s) => (typeof s === "string" ? s : s.source));
}

const problems = [];
const configs = {
  dev: render("docker compose"),
  test: render("docker compose --profile test --profile e2e"),
  prod: render("docker compose -f docker-compose.yml -f docker-compose.prod.yml"),
};
const stacks = Object.fromEntries(Object.entries(configs).map(([stack, config]) => [stack, config.services]));
for (const [stack, services] of Object.entries(stacks)) {
  for (const [name, service] of Object.entries(services)) {
    const env = service.environment ?? {};
    const label = `${stack} ${name}`;
    if (name in ALLOWED) {
      // The test stack also renders the dev report-worker (dev rules apply to it).
      const allowed = ALLOWED[name][stack] ?? Object.values(ALLOWED[name])[0];
      const keys = Object.keys(env).sort();
      const extra = keys.filter((key) => !allowed.includes(key));
      if (extra.length) problems.push(`${label} holds ${extra.join(", ")} (allowed: ${allowed.join(", ")})`);
      const leaked = keys.filter((key) => key !== "BROKER_URL" && FORBIDDEN.some((re) => re.test(key)));
      if (leaked.length) problems.push(`${label} holds the secret-like ${leaked.join(", ")}`);
      if (!String(env.BROKER_URL ?? "").startsWith("redis://report:")) problems.push(`${label}: BROKER_URL is not the report user`);
      const networks = Object.keys(service.networks ?? {}).sort().join(",");
      if (networks !== "analysis") problems.push(`${label}: networks ${networks} (expected analysis)`);
      if (secretsOf(service).length) problems.push(`${label} mounts the secret(s) ${secretsOf(service).join(", ")}`);
      if (service.read_only !== true) problems.push(`${label}: root filesystem is not read-only`);
      if (!(service.cap_drop ?? []).includes("ALL")) problems.push(`${label}: capabilities are not dropped`);
      continue;
    }
    if (!PRIVATE_ONLY.has(name)) {
      if ("REPORT_SIGNING_KEYS_FILE" in env) problems.push(`${label} holds REPORT_SIGNING_KEYS_FILE`);
      if (secretsOf(service).includes("report_signing_private")) problems.push(`${label} mounts report_signing_private`);
    }
    if (!PUBLIC_ONLY.has(name)) {
      const signing = Object.keys(env).filter((key) => key.startsWith("REPORT_SIGNING_"));
      if (signing.length) problems.push(`${label} holds ${signing.join(", ")}`);
    }
  }
  const api = services.api;
  if (!api) problems.push(`${stack}: no api service`);
  else if (!secretsOf(api).includes("report_signing_private") || !api.environment?.REPORT_SIGNING_KEYS_FILE) {
    problems.push(`${stack} api: no signing private key file`);
  }
}

const prod = stacks.prod["report-worker"];
if (!prod) problems.push("prod: no report-worker service");
if (prod?.environment?.ENV !== "prod") problems.push("prod report-worker: ENV is not prod");
if (prod?.image !== "cyberlab/report-worker:prod") problems.push(`prod report-worker: image ${prod?.image}`);
if (stacks.dev["report-worker"]?.image !== "cyberlab/report-worker:dev") problems.push("dev report-worker: not the dev image");
const apiEnv = stacks.prod.api?.environment ?? {};
const kid = String(apiEnv.REPORT_SIGNING_ACTIVE_KID ?? "");
if (!kid || kid.startsWith("dev-")) problems.push("prod api: the active signing kid is empty or a dev- kid");
let publicKeys = {};
try {
  publicKeys = JSON.parse(String(apiEnv.REPORT_SIGNING_PUBLIC_KEYS ?? "{}"));
} catch {
  problems.push("prod api: REPORT_SIGNING_PUBLIC_KEYS is not JSON");
}
const devKids = Object.keys(publicKeys).filter((k) => k.startsWith("dev-"));
if (devKids.length) problems.push(`prod api: public signing keys list the dev kid(s) ${devKids.join(", ")}`);
if (Object.values(publicKeys).includes(DEV_PUBLIC)) problems.push("prod api: public signing keys hold the dev public key");
if (kid && !(kid in publicKeys)) problems.push("prod api: the active kid has no public key");
// The prod secret is the generated pair, never the committed dev file.
const prodFile = String(configs.prod.secrets?.report_signing_private?.file ?? "").replaceAll("\\", "/");
if (!prodFile.endsWith(".secrets/report_signing_private.json")) {
  problems.push(`prod: the report_signing_private secret is not .secrets/report_signing_private.json`);
}

if (problems.length) {
  console.error(`report-worker configuration problems:\n  ${problems.join("\n  ")}`);
  process.exit(1);
}
console.log(
  "report-worker envs: BROKER_URL only (+ENV=prod in prod), analysis only, no secrets; signing key on api only; prod kid is not dev",
);
