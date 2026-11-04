#!/usr/bin/env node
// One command for the whole M1 gate: `pnpm verify` (add `--prod` to also check the prod stack).
// Runs on the host with Node 22 + Docker; every tool runs inside containers.
// Set COMPOSE_PROJECT_NAME to run against a separate project with fresh volumes.
import { spawnSync } from "node:child_process";

const PROD = process.argv.includes("--prod");
const COMPOSE_PROD = "docker compose -f docker-compose.yml -f docker-compose.prod.yml";
const started = Date.now();

class StepFailed extends Error {}

function fail(step, detail = "") {
  throw new StepFailed(detail ? `${step}\n  ${detail}` : step);
}

function run(step, command) {
  console.log(`\n▶ ${step}\n  $ ${command}`);
  const result = spawnSync(command, { shell: true, stdio: "inherit" });
  if (result.status !== 0) fail(step, `exit ${result.status}`);
  console.log(`✔ ${step}`);
}

// HTTP probes: a refused connection is a step failure too, not an unhandled rejection.
async function probe(step, check) {
  console.log(`\n▶ ${step}`);
  let problems;
  try {
    problems = await check();
  } catch (error) {
    fail(step, `${error.message} ${error.cause?.code ?? ""}`.trim());
  }
  if (problems.length) fail(step, problems.join("\n  "));
  console.log(`✔ ${step}`);
}

async function headerProblems(base, { hsts }) {
  const problems = [];
  const page = await fetch(`${base}/login`, { redirect: "manual" });
  const expected = {
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
  };
  for (const [name, value] of Object.entries(expected)) {
    if (!(page.headers.get(name) ?? "").includes(value)) problems.push(`${name} should contain ${value}`);
  }
  if (page.headers.has("x-powered-by")) problems.push("x-powered-by must be absent");
  if (hsts && !page.headers.has("strict-transport-security")) problems.push("strict-transport-security missing");
  // A declared oversize body must be refused at the gateway with the JSON error envelope.
  const big = await fetch(`${base}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: new Uint8Array(2 * 1024 * 1024),
  });
  const body = await big.text();
  if (big.status !== 413 || !body.includes('"payload_too_large"')) {
    problems.push(`2 MiB body must get JSON 413, got ${big.status} ${body.slice(0, 80)}`);
  }
  return problems;
}

async function healthProblems(base) {
  const health = await (await fetch(`${base}/api/v1/health`)).text();
  return ['"db":"ok"', '"redis":"ok"', '"minio":"ok"'].every((s) => health.includes(s)) ? [] : [health];
}

// A crash-looping worker can look "running" between restarts: let it settle, then require
// a running state and no restart at all (review H1: the prod enrich-worker crash-looped).
async function workerProblems(service) {
  await new Promise((resolve) => setTimeout(resolve, 15_000));
  const id = spawnSync(`${COMPOSE_PROD} ps -q ${service}`, { shell: true }).stdout.toString().trim();
  if (!id) return [`${service}: no container`];
  const state = spawnSync(`docker inspect -f "{{.State.Status}} {{.RestartCount}}" ${id}`, { shell: true })
    .stdout.toString()
    .trim();
  return state === "running 0" ? [] : [`${service}: ${state} (expected "running 0")`];
}

async function verifyProd() {
  run("Prod enrich-worker env: matches the tested fixture", "node scripts/check-enrich-env.mjs");
  run("Prod stack up", `${COMPOSE_PROD} up -d --build --wait --wait-timeout 400`);
  await probe("Prod enrich-worker: running, never restarted", () => workerProblems("enrich-worker"));
  // The prod-like stack uses Caddy's internal CA: skip certificate checks for these probes.
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  await probe("Prod health", () => healthProblems("https://localhost:8443"));
  await probe("Prod gateway: security headers, HSTS, 413", () =>
    headerProblems("https://localhost:8443", { hsts: true }),
  );
  run("Prod E2E: Playwright smoke over TLS", "node scripts/e2e.mjs --prod");
}

// Always put the dev stack back, even when a prod step failed (both share one compose project).
function restoreDev() {
  console.log("\n▶ Prod stack down, dev stack back");
  const down = spawnSync(`${COMPOSE_PROD} down`, { shell: true, stdio: "inherit" });
  const up = spawnSync("docker compose up -d --wait --wait-timeout 300", { shell: true, stdio: "inherit" });
  if (down.status !== 0 || up.status !== 0) {
    console.error("✖ Could not restore the dev stack: run `pnpm prod:down` then `pnpm dev`");
    process.exitCode = 1;
  } else {
    console.log("✔ Dev stack restored");
  }
}

try {
  run("Dev stack up", "docker compose up -d --build --renew-anon-volumes --wait --wait-timeout 300");
  // Celery workers do not hot-reload: recreate them so the gate tests the current code.
  run(
    "Workers: reload code",
    "docker compose --profile test up -d --force-recreate --no-deps pcap-worker pcap-worker-test static-worker static-worker-test ingest-worker ingest-beat enrich-worker enrich-worker-test",
  );
  run(
    "API: ruff, format, mypy --strict, pytest",
    'docker compose --profile test run --rm api-test sh -c "uv run ruff check . && uv run ruff format --check . && uv run mypy app && uv run pytest -q"',
  );
  run(
    "Enrich worker network: only Postgres, the broker and egress (review M2)",
    "docker compose --profile test run --rm --no-deps -e PYTHONDONTWRITEBYTECODE=1 enrich-worker-test python -m pytest --noconftest -q -p no:cacheprovider tests/container/test_enrich_network.py",
  );
  run("Workers (pcap, static, kit): ruff, format, mypy, sandbox + engine tests", "pnpm -s test:workers");
  run(
    "Web: typecheck, eslint, unit tests",
    'docker compose run --rm --no-deps web sh -c "pnpm typecheck && pnpm exec eslint . && pnpm test"',
  );
  run("Web: production build", "docker compose run --rm --no-deps -e NEXT_WATCH_POLL_MS= web pnpm build");
  run("Contracts: regenerate", "node scripts/gen-contracts.mjs");
  run("Contracts: no drift", "git diff --exit-code -- packages/contracts");
  await probe("Gateway: health", () => healthProblems("http://localhost:8080"));
  await probe("Gateway: security headers + 413", () => headerProblems("http://localhost:8080", { hsts: false }));
  run("E2E: Playwright smoke", "node scripts/e2e.mjs");

  if (PROD) {
    try {
      await verifyProd();
    } finally {
      restoreDev();
    }
  }
} catch (error) {
  if (!(error instanceof StepFailed)) throw error;
  console.error(`\n✖ FAILED: ${error.message}`);
  process.exit(1);
}

if (process.exitCode) process.exit(process.exitCode);
console.log(`\n✅ verify passed in ${Math.round((Date.now() - started) / 1000)} s`);
