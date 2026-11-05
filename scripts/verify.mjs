#!/usr/bin/env node
// One command for the whole M1 gate: `pnpm verify` (add `--prod` to also check the prod stack).
// Runs on the host with Node 22 + Docker; every tool runs inside containers.
// Set COMPOSE_PROJECT_NAME to run against a separate project with fresh volumes.
import { spawnSync } from "node:child_process";

const PROD = process.argv.includes("--prod");
// Live threat-intel tests (real providers, real keys) are never part of the gate: they are
// skipped unless CYBERLAB_LIVE_TI=1, so make sure no child process inherits it.
delete process.env.CYBERLAB_LIVE_TI;
// Nor are live AI tests or the live AI evaluation (M5): real keys, real money.
delete process.env.AI_EVAL_LIVE;
const COMPOSE_PROD = "docker compose -f docker-compose.yml -f docker-compose.prod.yml";
// The committed dev report signing public key (kid dev-report-1, refused in prod).
const DEV_REPORT_PUBLIC = "zS2iP9napZDeshJwfCiTwYl8amzPuWJEJwHK8CpnF2k=";
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
// `env` lists NAME=value pairs the running container must have (M4: the prod enrich-worker
// runs ENV=prod, so the mock and the dev-only MISP flags are refused). Only those names are
// compared: the container's other variables hold secrets and are never printed.
// Every replica is checked (the prod analyst-worker runs two, M5).
async function workerProblems(service, env = {}, image = null) {
  await new Promise((resolve) => setTimeout(resolve, 15_000));
  const ids = spawnSync(`${COMPOSE_PROD} ps -q ${service}`, { shell: true }).stdout.toString().split(/\s+/).filter(Boolean);
  if (!ids.length) return [`${service}: no container`];
  const inspect = spawnSync(`docker inspect ${ids.join(" ")}`, { shell: true, maxBuffer: 16 * 1024 * 1024 });
  const containers = JSON.parse(inspect.stdout.toString() || "[{}]");
  const problems = [];
  for (const container of containers) {
    const name = `${service} (${container?.Name ?? "?"})`;
    const state = `${container?.State?.Status} ${container?.RestartCount}`;
    if (state !== "running 0") problems.push(`${name}: ${state} (expected "running 0")`);
    if (image && container?.Config?.Image !== image) problems.push(`${name}: image ${container?.Config?.Image}`);
    const actual = new Map(
      (container?.Config?.Env ?? []).map((pair) => [pair.slice(0, pair.indexOf("=")), pair.slice(pair.indexOf("=") + 1)]),
    );
    for (const [key, value] of Object.entries(env)) {
      if (actual.get(key) !== value) problems.push(`${name}: ${key} is not ${value}`);
    }
  }
  return problems;
}

// The public signing keys route (M6): the prod api never lists the committed dev pair.
async function signingKeyProblems(base) {
  const response = await fetch(`${base}/api/v1/report-signing-keys`);
  if (!response.ok) return [`report-signing-keys: HTTP ${response.status}`];
  const { keys = [] } = await response.json();
  const problems = [];
  if (!keys.some((k) => k.active)) problems.push("report-signing-keys: no active key");
  const dev = keys.filter((k) => k.kid.startsWith("dev-") || k.public_key === DEV_REPORT_PUBLIC);
  if (dev.length) problems.push(`report-signing-keys lists the dev key(s) ${dev.map((k) => k.kid).join(", ")}`);
  return problems;
}

async function verifyProd() {
  run(
    "Enrich-worker envs: no api secrets (dev, test, prod), prod env matches the tested fixture",
    "node scripts/check-enrich-env.mjs",
  );
  run(
    "Analyst-worker envs: no api/TI secrets, AI keys only there, prod env matches the tested fixture",
    "node scripts/check-analyst-env.mjs",
  );
  run(
    "Report-worker envs: BROKER_URL only (+ENV=prod), analysis only, signing key on api only, no dev kid in prod",
    "node scripts/check-report-worker-env.mjs",
  );
  run("Prod stack up", `${COMPOSE_PROD} up -d --build --wait --wait-timeout 400`);
  await probe("Prod enrich-worker: running, never restarted, ENV=prod, no mock", () =>
    workerProblems(
      "enrich-worker",
      { ENV: "prod", PROCESS_ROLE: "enrich", TI_MOCK_ENABLED: "false" },
      "cyberlab/api:prod",
    ),
  );
  await probe("Prod analyst-worker: every replica running, never restarted, ENV=prod, no mock or platform key", () =>
    workerProblems(
      "analyst-worker",
      { ENV: "prod", PROCESS_ROLE: "analyst", AI_MOCK_ENABLED: "false", AI_PLATFORM_PROVIDER: "" },
      "cyberlab/api:prod",
    ),
  );
  // The untrusted renderer has no mock: the prod e2e renders a real PDF through it (M6).
  await probe("Prod report-worker: running, never restarted, ENV=prod, prod image", () =>
    workerProblems("report-worker", { ENV: "prod" }, "cyberlab/report-worker:prod"),
  );
  // The prod-like stack uses Caddy's internal CA: skip certificate checks for these probes.
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  await probe("Prod health", () => healthProblems("https://localhost:8443"));
  await probe("Prod report signing keys: an active key, no dev- kid or dev public key", () =>
    signingKeyProblems("https://localhost:8443"),
  );
  await probe("Prod gateway: security headers, HSTS, 413", () =>
    headerProblems("https://localhost:8443", { hsts: true }),
  );
  run("Prod E2E: Playwright smoke over TLS (incl. the report flow on the real renderer)", "node scripts/e2e.mjs --prod");
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
    "docker compose --profile test up -d --force-recreate --no-deps pcap-worker pcap-worker-test static-worker static-worker-test ingest-worker ingest-beat enrich-worker enrich-worker-test ti-mock analyst-worker analyst-worker-test ai-mock report-worker report-worker-test",
  );
  run(
    "API: ruff, format, mypy --strict, pytest",
    // Includes tests/container/test_egress.py (api-test: no route, no ti-mock / ai-mock) and
    // the real AI pipeline (analyst-worker-test + ai-mock); live TI / AI tests skip.
    // REPORT_E2E=1 (M6): the render pipeline tests go through report-worker-test, which the
    // reload step started on the default lane's broker db.
    'docker compose --profile test run --rm -e CYBERLAB_LIVE_TI=0 -e AI_EVAL_LIVE=0 -e REPORT_E2E=1 api-test sh -c "uv run ruff check . && uv run ruff format --check . && uv run mypy app && uv run pytest -q"',
  );
  run(
    "Enrich worker network: only Postgres, the broker and egress (review M2)",
    "docker compose --profile test run --rm --no-deps -e PYTHONDONTWRITEBYTECODE=1 enrich-worker-test python -m pytest --noconftest -q -p no:cacheprovider tests/container/test_enrich_network.py",
  );
  run(
    "Ingest worker network: no route out, no ti-mock (M4 egress suite)",
    "docker compose exec -T -e PYTHONDONTWRITEBYTECODE=1 ingest-worker python -m pytest --noconftest -q -p no:cacheprovider tests/container/test_egress.py",
  );
  run(
    "Analyst worker network: only Postgres, the broker and egress (ai-mock); no TI key (M5)",
    "docker compose --profile test run --rm --no-deps -e PYTHONDONTWRITEBYTECODE=1 analyst-worker-test python -m pytest --noconftest -q -p no:cacheprovider tests/container/test_analyst_network.py",
  );
  run("TI key leak: a fresh sentinel key is absent from every container log", "node scripts/check-ti-key-leak.mjs");
  run("AI key leak: a fresh sentinel key is absent from every container log", "node scripts/check-ai-key-leak.mjs");
  // test:workers includes the report renderer (M6): ruff, mypy and its pytest in
  // report-worker-test (sandbox EACCES, isolation, PDF/A-3a, determinism, hostile escapes).
  run("Workers (pcap, static, report, kit): ruff, format, mypy, sandbox + engine tests", "pnpm -s test:workers");
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
