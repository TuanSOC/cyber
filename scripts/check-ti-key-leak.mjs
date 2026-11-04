#!/usr/bin/env node
// Key-leak suite, the log part (M4 phase 7): run the real TI pipeline tests with a fresh,
// random provider key, then scan what every involved container logged meanwhile for it.
//
// The key is the one `ti-mock` expects (TI_MOCK_EXPECTED_KEY), so it is sealed through the
// API path, unsealed by `enrich-worker-test`, sent over `egress` and echoed back by the mock
// in 401 bodies (`echo401*` values and wrong-key runs). It must appear in no log line of the
// api, the enrich workers, the ingest worker/beat, Postgres or the broker, nor in the test
// run's own output (the in-process API). Tests inside api-test cannot read `docker logs`,
// hence this host-side script (wired into scripts/verify.mjs).
//   node scripts/check-ti-key-leak.mjs
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";

const SENTINEL = `CYBERLAB-LEAK-SENTINEL-${randomBytes(12).toString("hex")}`;
// The in-process sentinel of tests/ti_helpers.py (used by test_ti_key_leak.py).
const STATIC_SENTINEL = "CYBERLAB-TEST-SENTINEL-KEY-0000000000000000";
// The wrong key of test_ti_pipeline.py: ti-mock echoes it in its 401 body.
const WRONG_KEY = "definitely-not-the-mock-key";
const SERVICES = ["api", "enrich-worker", "enrich-worker-test", "ingest-worker", "ingest-beat", "postgres", "redis-broker"];
const TESTS = ["tests/integration/test_ti_pipeline.py", "tests/integration/test_ti_key_leak.py"];
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
    for (const key of [SENTINEL, STATIC_SENTINEL, WRONG_KEY]) {
      if (needles(key).some((n) => line.includes(n))) hits.push(`${label}: ${line.replaceAll(key, "<KEY>").slice(0, 200)}`);
    }
  }
  return hits;
}

// Logs from a little before the start (host and engine clocks may differ by a second or two).
const since = new Date(Date.now() - 5_000).toISOString();
const keyed = { ...process.env, TI_MOCK_EXPECTED_KEY: SENTINEL };
let failed = false;
try {
  console.log("▶ ti-mock with a fresh sentinel key");
  if (sh(`${COMPOSE} up -d --wait --force-recreate --no-deps ti-mock`, keyed).status !== 0) throw new Error("ti-mock did not start");

  console.log("▶ TI pipeline + key-leak tests (the api-test run passes the same key to the tests)");
  const run = sh(`${COMPOSE} run --rm -T api-test uv run pytest -q -p no:cacheprovider ${TESTS.join(" ")}`, keyed, true);
  process.stdout.write(run.out);
  if (run.status !== 0) throw new Error(`pipeline tests failed (exit ${run.status})`);

  console.log(`▶ scanning logs since ${since}: ${SERVICES.join(", ")}`);
  const logs = sh(`${COMPOSE} logs --no-color --since ${since} ${SERVICES.join(" ")}`, process.env, true);
  if (logs.status !== 0) throw new Error("docker compose logs failed");
  const hits = [...scan("test output", run.out), ...scan("logs", logs.out)];
  // Positive control: the logs being scanned are the ones of this run.
  if (!logs.out.includes("enrich-worker-test")) throw new Error("no enrich-worker-test log lines captured");
  if (hits.length) {
    console.error(`✖ the provider key leaked (${hits.length} lines):\n  ${hits.slice(0, 20).join("\n  ")}`);
    failed = true;
  } else {
    console.log(`✔ sentinel absent from ${logs.out.split("\n").length} log lines and the test output`);
  }
} catch (error) {
  console.error(`✖ ${error.message}`);
  failed = true;
} finally {
  console.log("▶ ti-mock back to its configured key");
  if (sh(`${COMPOSE} up -d --wait --force-recreate --no-deps ti-mock`).status !== 0) failed = true;
}
process.exit(failed ? 1 : 0);
