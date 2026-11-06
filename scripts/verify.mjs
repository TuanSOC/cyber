#!/usr/bin/env node
// One command for the whole gate: `pnpm verify` (add `--prod` to also check the prod stack and
// run the M7 restore drill as its last, exclusive step). Runs on the host with Node 22 +
// Docker; every tool runs inside containers, except the host-side dynamic gate checks (Python
// 3 with pytest and PyYAML). `pnpm ops:metrics` (the heavy replay), `pnpm disk:fuzz` and
// `pnpm disk:metrics` (M9 heavy steps, run alone) are never part of the gate.
// Set COMPOSE_PROJECT_NAME to run against a separate project with fresh volumes. The prod
// phase always runs in its own project, `<dev project>-prod` (scripts/lib/gate.mjs): dev MinIO
// writes its IAM with the dev KMS key, which the prod key cannot read.
import { spawnSync } from "node:child_process";

import { composeCommand, gateProjects, prodE2eEnv, withoutComposeEnv } from "./lib/gate.mjs";

const PROD = process.argv.includes("--prod");
// Live threat-intel tests (real providers, real keys) are never part of the gate: they are
// skipped unless CYBERLAB_LIVE_TI=1, so make sure no child process inherits it.
delete process.env.CYBERLAB_LIVE_TI;
// Nor are live AI tests or the live AI evaluation (M5): real keys, real money.
delete process.env.AI_EVAL_LIVE;
// The disk worker test service runs the real Plaso engine except in the replay pass (M9).
delete process.env.DISK_TEST_TIMELINE_ENGINE;
const PROJECTS = gateProjects();
const COMPOSE_DEV = composeCommand(PROJECTS.dev);
const COMPOSE_PROD = composeCommand(PROJECTS.prod, { prod: true });
// The committed dev report signing public key (kid dev-report-1, refused in prod).
const DEV_REPORT_PUBLIC = "zS2iP9napZDeshJwfCiTwYl8amzPuWJEJwHK8CpnF2k=";
const started = Date.now();

class StepFailed extends Error {}

function fail(step, detail = "") {
  throw new StepFailed(detail ? `${step}\n  ${detail}` : step);
}

// `env`: extra variables for this step only (set here, not as a `NAME=value cmd` prefix,
// which cmd.exe does not understand). `base`: the env they are added to (default: this
// process's). Returns the step's duration in seconds.
function run(step, command, env = {}, base = process.env) {
  const shown = Object.entries(env).map(([k, v]) => `${k}=${v} `).join("");
  console.log(`\n▶ ${step}\n  $ ${shown}${command}`);
  const begun = Date.now();
  const result = spawnSync(command, { shell: true, stdio: "inherit", env: { ...base, ...env } });
  if (result.status !== 0) fail(step, `exit ${result.status}`);
  const seconds = Math.round((Date.now() - begun) / 1000);
  console.log(`✔ ${step} (${seconds} s)`);
  return seconds;
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
  run(
    "Retention-worker envs: retention role, broker user and purge keys only, backend only; no api policy legal hold; prod secrets not dev",
    "node scripts/check-retention-worker-env.mjs",
  );
  run(
    "Disk envs: worker BROKER_URL only on analysis, hash sets read-only; ingest_disk on backend; hash-set tools offline; no privileged / loop / FUSE (M9)",
    "node scripts/check-disk-worker-env.mjs",
  );
  // The dev stack stops first (host memory; containers and volumes kept): the prod stack runs
  // in its own project with its own volumes, and `restoreDev()` starts the dev stack again.
  run(
    `Dev stack stopped (project ${PROJECTS.dev}, containers and volumes kept)`,
    `${COMPOSE_DEV} --profile test --profile e2e stop`,
  );
  run(`Prod stack up (project ${PROJECTS.prod}, its own volumes)`, `${COMPOSE_PROD} up -d --build --wait --wait-timeout 400`);
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
  // M7: the least-privilege purge worker runs the prod image with ENV=prod.
  await probe("Prod retention-worker: running, never restarted, ENV=prod, PROCESS_ROLE=retention", () =>
    workerProblems("retention-worker", { ENV: "prod", PROCESS_ROLE: "retention" }, "cyberlab/api:prod"),
  );
  // The untrusted renderer has no mock: the prod e2e renders a real PDF through it (M6).
  await probe("Prod report-worker: running, never restarted, ENV=prod, prod image", () =>
    workerProblems("report-worker", { ENV: "prod" }, "cyberlab/report-worker:prod"),
  );
  // M9: the disk analyzer runs the prod image (no image tools, no compiler; only BROKER_URL in
  // its compose env, checked above), its trusted ingest the prod api image on ingest_disk.
  await probe("Prod disk-worker: running, never restarted, prod image", () =>
    workerProblems("disk-worker", {}, "cyberlab/disk-worker:prod"),
  );
  await probe("Prod disk-ingest-worker: running, never restarted, ENV=prod, PROCESS_ROLE=ingest", () =>
    workerProblems("disk-ingest-worker", { ENV: "prod", PROCESS_ROLE: "ingest" }, "cyberlab/api:prod"),
  );
  run(
    "Prod disk image: versions.json target prod, no TSK / ewf / mkfs / ntfs-3g / sfdisk tool or compiler, tool uid 10007",
    "node scripts/check-disk-worker-env.mjs --image cyberlab/disk-worker:prod",
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
  // COMPOSE_PROJECT_NAME is the prod project here, so the e2e runner reaches its gateway.
  run(
    "Prod E2E: Playwright smoke over TLS (incl. the report flow on the real renderer)",
    "node scripts/e2e.mjs --prod",
    { COMPOSE_PROJECT_NAME: PROJECTS.prod },
    prodE2eEnv(PROJECTS.prod),
  );
  // M7 phase 11: the restore drill is the LAST step, alone. It takes every lane slot and
  // refuses while the main project's heavy services run, so stop the prod stack first
  // (never `-v`: the prod project's volumes stay); `restoreDev()` brings the dev stack back
  // afterwards. The drill names its own project and its down -v guard refuses any other
  // COMPOSE_PROJECT_NAME: it runs with no COMPOSE_* variable at all.
  run(`Prod stack down (project ${PROJECTS.prod}, volumes kept) before the restore drill`, `${COMPOSE_PROD} down`);
  const drill = run(
    "Restore drill (--prod): seed, backup, destroy, restore, verify, download; 0 mismatches",
    "pnpm -s restore:drill --prod",
    {},
    withoutComposeEnv(),
  );
  console.log(`  restore drill: ${drill} s (record it in the M7 gate addendum)`);
}

// Always put the dev stack back, even when a prod step failed: the prod project's containers
// go (never its volumes), the dev project starts (explicit -p, so COMPOSE_PROJECT_NAME works).
function restoreDev() {
  console.log(`\n▶ Prod stack down (project ${PROJECTS.prod}), dev stack back (project ${PROJECTS.dev})`);
  const down = spawnSync(`${COMPOSE_PROD} down`, { shell: true, stdio: "inherit" });
  const up = spawnSync(`${COMPOSE_DEV} up -d --wait --wait-timeout 300`, { shell: true, stdio: "inherit" });
  if (down.status !== 0 || up.status !== 0) {
    console.error(`✖ Could not restore the dev stack: run \`${COMPOSE_PROD} down\` then \`${COMPOSE_DEV} up -d --wait\``);
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
    "docker compose --profile test up -d --force-recreate --no-deps pcap-worker pcap-worker-test static-worker static-worker-test ingest-worker ingest-beat enrich-worker enrich-worker-test ti-mock analyst-worker analyst-worker-test ai-mock report-worker report-worker-test retention-worker retention-worker-test disk-worker disk-worker-test disk-ingest-worker disk-ingest-worker-test",
  );
  // M9 phase 13: the generated disk images (our own content, never downloaded) and the test
  // hash sets (one known-good and one known-bad file of `ext4_linux`) for the disk pipeline
  // tests and the engine tests below; the operator's hash-set store is never touched.
  run(
    "Disk images: generate the synthetic set and import the test hash sets (M9)",
    "node scripts/disk-gen.mjs --test-hashsets",
  );
  run(
    "API: ruff, format, mypy --strict, pytest",
    // Includes tests/container/test_egress.py (api-test: no route, no ti-mock / ai-mock) and
    // the real AI pipeline (analyst-worker-test + ai-mock); live TI / AI tests skip.
    // REPORT_E2E=1 (M6): the render pipeline tests go through report-worker-test, which the
    // reload step started on the default lane's broker db.
    // DISK_PIPELINE_IMAGES (M9): the disk pipeline tests upload the generated images to
    // disk-worker-test (real TSK / libewf / Plaso, the test hash sets) and ingest on
    // disk-ingest-worker-test, both started by the reload step on the default lane.
    'docker compose --profile test run --rm -e CYBERLAB_LIVE_TI=0 -e AI_EVAL_LIVE=0 -e REPORT_E2E=1 -v cyberlab_e2e_samples:/samples:ro -e DISK_PIPELINE_IMAGES=/samples/disk api-test sh -c "uv run ruff check . && uv run ruff format --check . && uv run mypy app && uv run pytest -q"',
  );
  // M9 phase 13: the second disk pipeline pass, with the test-profile replay timeline engine
  // (the Windows psort fixtures over `ntfs_windows`: the EVTX / registry / Prefetch / LNK
  // normalizers, detections and tables end to end, labelled `timeline_engine: replay`). The
  // engine is a worker setting, so disk-worker-test is recreated for the pass and back after.
  run(
    "Disk worker test: replay timeline engine (M9 replay pass)",
    "docker compose --profile test up -d --force-recreate --no-deps disk-worker-test",
    { DISK_TEST_TIMELINE_ENGINE: "replay" },
  );
  try {
    run(
      "API: disk pipeline, replay pass (Windows artifacts replay-tested only)",
      'docker compose --profile test run --rm -v cyberlab_e2e_samples:/samples:ro -e DISK_PIPELINE_IMAGES=/samples/disk -e DISK_PIPELINE_TIMELINE_ENGINE=replay api-test uv run pytest -q tests/integration/test_disk_pipeline.py -k replay',
    );
  } finally {
    run(
      "Disk worker test: back to the Plaso engine",
      "docker compose --profile test up -d --force-recreate --no-deps disk-worker-test",
      { DISK_TEST_TIMELINE_ENGINE: "plaso" },
    );
  }
  // The dynamic-analysis gate's broker and compose checks (M7 phase 7) read repository files
  // that api-test does not mount, so they skip there: run them on the host (stdlib, pytest
  // and PyYAML only, no app import; see the test's docstring).
  run(
    "Dynamic gate (host): no dynamic / sandbox broker user, compose service or export",
    'python -m pytest --noconftest -q -p no:cacheprovider apps/api/tests/unit/test_dynamic_gate.py -k "broker or compose or enabled or export"',
    { PYTHONPATH: "packages/py-jobs/src" },
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
  run("Workers (pcap, static, report, memory, disk, kit): ruff, format, mypy, sandbox + engine tests", "pnpm -s test:workers");
  // M9: the disk engine tests on the generated set (TSK / libewf against each image's ground
  // truth, the generators' own tool checks, Plaso on the Linux tree, the stage proofs).
  // Fuzz-lite and the metric run are heavy steps of their own, never part of the gate.
  run(
    "Disk engine tests: TSK / libewf / Plaso on the generated images (M9)",
    "docker compose --profile test run --rm --no-deps -v cyberlab_e2e_samples:/samples:ro -e DISK_ENGINE_IMAGES=/samples/disk -e DISKGEN_ENGINE=1 disk-worker-test pytest -q -p no:cacheprovider tests/engine",
  );
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
