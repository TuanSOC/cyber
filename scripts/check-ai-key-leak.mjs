#!/usr/bin/env node
// Key-leak suite, the log part (M5 phase 11): run the AI key-leak tests against the real
// analyst pipeline with a fresh, random provider key, then scan what every involved container
// logged meanwhile for it.
//
// The key is the one `ai-mock` expects (AI_MOCK_EXPECTED_KEY), so it is sealed through the
// API, unsealed by `analyst-worker-test`, sent over `egress` in a header and echoed back by the
// mock in a 401 body (`ai-mock:401`). It must appear in no log line of the api, the analyst
// workers, ai-mock, the ingest worker/beat, Postgres or the broker, nor in the test run's own
// output (the in-process API). Tests inside api-test cannot read `docker logs`, hence this
// host-side script (wired into scripts/verify.mjs). Never a live provider.
//   node scripts/check-ai-key-leak.mjs
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";

const SENTINEL = `CYBERLAB-AI-LEAK-SENTINEL-${randomBytes(12).toString("hex")}`;
// The in-process sentinel of tests/ai_helpers.py (used across the AI API and worker tests).
const STATIC_SENTINEL = "CYBERLAB-AI-SENTINEL-KEY-00000000000000000";
const SERVICES = [
  "api",
  "analyst-worker",
  "analyst-worker-test",
  "ai-mock",
  "ingest-worker",
  "ingest-beat",
  "postgres",
  "redis-broker",
];
const TESTS = ["tests/integration/test_ai_key_leak.py"];
const COMPOSE = "docker compose --profile test";

function sh(command, env = process.env, capture = false) {
  console.log(`  $ ${command}`);
  const result = spawnSync(command, {
    shell: true,
    env,
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
    stdio: capture ? ["ignore", "pipe", "pipe"] : "inherit",
  });
  return { status: result.status, out: `${result.stdout ?? ""}${result.stderr ?? ""}` };
}

function needles(key) {
  const bytes = Buffer.from(key);
  return [key, bytes.toString("base64"), bytes.toString("hex"), encodeURIComponent(key)];
}

function scan(label, text) {
  const hits = [];
  for (const line of text.split(/\r?\n/)) {
    for (const key of [SENTINEL, STATIC_SENTINEL]) {
      if (needles(key).some((n) => line.includes(n))) hits.push(`${label}: ${line.replaceAll(key, "<KEY>").slice(0, 200)}`);
    }
  }
  return hits;
}

// Logs from a little before the start (host and engine clocks may differ by a second or two).
const since = new Date(Date.now() - 5_000).toISOString();
const keyed = { ...process.env, AI_MOCK_EXPECTED_KEY: SENTINEL };
let failed = false;
try {
  console.log("▶ ai-mock with a fresh sentinel key");
  if (sh(`${COMPOSE} up -d --wait --force-recreate --no-deps ai-mock`, keyed).status !== 0) throw new Error("ai-mock did not start");

  console.log("▶ AI key-leak tests (the api-test run passes the same key to the tests)");
  const run = sh(`${COMPOSE} run --rm -T api-test uv run pytest -q -p no:cacheprovider -rs ${TESTS.join(" ")}`, keyed, true);
  process.stdout.write(run.out);
  if (run.status !== 0) throw new Error(`key-leak tests failed (exit ${run.status})`);
  if (/\bskipped\b/.test(run.out) && !/\bpassed\b/.test(run.out)) throw new Error("the key-leak tests were skipped");

  console.log(`▶ scanning logs since ${since}: ${SERVICES.join(", ")}`);
  const logs = sh(`${COMPOSE} logs --no-color --since ${since} ${SERVICES.join(" ")}`, process.env, true);
  if (logs.status !== 0) throw new Error("docker compose logs failed");
  const hits = [...scan("test output", run.out), ...scan("logs", logs.out)];
  // Positive control: the worker really ran these runs (its log lines are in what was scanned).
  if (!/analyst-worker-test.*ai run /.test(logs.out)) throw new Error("no analyst-worker-test run log lines captured");
  if (hits.length) {
    console.error(`✖ the AI provider key leaked (${hits.length} lines):\n  ${hits.slice(0, 20).join("\n  ")}`);
    failed = true;
  } else {
    console.log(`✔ sentinel absent from ${logs.out.split("\n").length} log lines and the test output`);
  }
} catch (error) {
  console.error(`✖ ${error.message}`);
  failed = true;
} finally {
  console.log("▶ ai-mock back to its configured key");
  if (sh(`${COMPOSE} up -d --wait --force-recreate --no-deps ai-mock`).status !== 0) failed = true;
}
process.exit(failed ? 1 : 0);
