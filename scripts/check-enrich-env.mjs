#!/usr/bin/env node
// The prod enrich-worker environment, as `docker compose -f docker-compose.yml -f
// docker-compose.prod.yml config` renders it, must equal the fixture that
// apps/api/tests/unit/test_config.py builds `Settings` from (review H1: a missing or extra
// variable there crash-looped the prod worker). Passwords and the site's seal key are masked.
//   node scripts/check-enrich-env.mjs           # compare (exit 1 on drift)
//   node scripts/check-enrich-env.mjs --write   # regenerate the fixture
import { execSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const FIXTURE = "apps/api/tests/fixtures/compose/enrich-worker.prod.env.json";
const KID = "prod-fixture";
const PUBLIC = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

const rendered = JSON.parse(
  execSync("docker compose -f docker-compose.yml -f docker-compose.prod.yml config --format json enrich-worker", {
    stdio: ["ignore", "pipe", "inherit"],
  }).toString(),
);
const env = rendered.services["enrich-worker"].environment ?? {};
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
  console.log("prod enrich-worker env matches the tested fixture");
}
