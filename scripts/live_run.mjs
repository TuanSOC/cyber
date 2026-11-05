#!/usr/bin/env node
// `pnpm live:run` (M7 phase 5): the budgeted live TI / AI provider runs. Never part of the gate;
// running it needs the user's own provider keys and budget (a user decision).
//
//   CYBERLAB_LIVE=1 pnpm live:run --max-calls 20 --max-usd 2 [--runs 1] [--only ti|ai|eval]
//   node scripts/live_run.mjs --plan --max-calls --max-usd    # print the plan, call nothing
//
// Refuses (exit 2) unless CYBERLAB_LIVE=1, `.secrets/live.env` exists, and both `--max-calls`
// and `--max-usd` are given (a bare flag takes its default: 20 calls, 2 USD). A refusal still
// writes `plans/reports/live-run-YYMMDD.md` with `status: not run` and the reason, unless a
// report of that day already says `status: run` (it is never overwritten).
//
// Keys (all under the git-ignored `.secrets/`):
// - TI: `.secrets/live.env` holds `CYBERLAB_TI_KEY_<PROVIDER>=...` (VIRUSTOTAL, ABUSEIPDB,
//   URLHAUS, MALWAREBAZAAR, OTX; ABUSECH covers URLhaus and MalwareBazaar). Only providers with
//   a key are run. The file goes to the container through `docker compose run
//   --env-from-file` (compose's own `--env-file` would replace `.env`), never on a command line.
// - AI: one key per file, `.secrets/ai_eval_<provider>.key` (anthropic, gemini; the
//   scripts/ai_eval.py convention), mounted read-only; optional `AI_LIVE_<PROVIDER>_MODEL=` in
//   live.env (else the catalog default for the smoke test; the evaluation needs a model).
//
// Network (recorded in the phase notes): the live tests need egress, and `api-test` has none
// (`backend` is internal). So the TI smoke test runs in a one-off `enrich-worker-test`
// container and the AI smoke test in `analyst-worker-test` (both on `egress`), with pytest's
// `--noconftest` (the suite conftest needs the test DB, which those networks cannot reach). The
// AI evaluation reuses scripts/ai_eval.py (collect / score in api-test, the provider calls in
// analyst-worker-test). Egress is never added to api-test.
//
// Budget: calls are planned before anything runs: TI 2 per provider (verify, lookup), AI smoke
// 3 per provider (verify, count tokens, analyze), the evaluation 1 per case and run (4 for an
// incident case: map and reduce). Evaluation cases are added only while the plan stays within
// --max-calls and --max-usd (USD_PER_CALL below: conservative per-call estimates). Nothing is
// run when even the smoke tests do not fit. `AI_LIVE_MAX_CALLS` is passed to the AI steps.
//
// Report: providers, model ids, planned and counted calls, cost estimate, citation accuracy
// (the evaluation's live floors line), enrichment success (TI tests passed / run) and the
// failing test ids. Never a key, never raw provider output (only pytest's per-test outcome
// lines and ai_eval.py's metric lines are parsed).
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SECRETS = resolve(ROOT, ".secrets");
const LIVE_ENV = resolve(SECRETS, "live.env");
const CASES_DIR = resolve(ROOT, "apps/api/tests/fixtures/ai_eval/cases");
const DEFAULTS = { "max-calls": 20, "max-usd": 2 };
const TI_PROVIDERS = ["virustotal", "abuseipdb", "urlhaus", "malwarebazaar", "otx"];
const ABUSECH = new Set(["urlhaus", "malwarebazaar"]);
const AI_PROVIDERS = ["anthropic", "gemini"];
const USD_PER_CALL = { anthropic: 0.05, gemini: 0.02, ti: 0 };
const AI_SMOKE_CALLS = { anthropic: 3, gemini: 2 };
// Small, mixed evaluation set first (clean and injected twins), then the rest.
const PREFERRED_CASES = [
  "pcap_beacon", "pcap_beacon__injected", "static_benign_pe32", "static_benign_pe32__injected",
  "pcap_dns_anomalies", "pcap_suspicious_http__injected",
];
const COMPOSE_RUN = ["compose", "--profile", "test", "run", "--rm", "--no-deps"];
const PYTEST = ["python", "-m", "pytest", "-q", "-rA", "-p", "no:cacheprovider", "--noconftest"];

function parseArgs(argv) {
  const args = { only: null, runs: 1, plan: false, given: new Set() };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const key = arg.replace(/^--/, "").split("=")[0];
    const inline = arg.includes("=") ? arg.split("=").slice(1).join("=") : undefined;
    const next = argv[i + 1];
    const value = () => {
      if (inline !== undefined) return inline;
      if (next !== undefined && !next.startsWith("--")) return argv[++i];
      return undefined;
    };
    if (key in DEFAULTS) {
      args.given.add(key);
      const raw = value();
      args[key] = raw === undefined ? DEFAULTS[key] : Number(raw);
      if (!Number.isFinite(args[key]) || args[key] <= 0) fail(`--${key} must be a positive number`);
    } else if (key === "runs") {
      args.runs = Number(value());
      if (!Number.isInteger(args.runs) || args.runs < 1) fail("--runs must be an integer >= 1");
    } else if (key === "only") {
      args.only = value();
      if (!["ti", "ai", "eval"].includes(args.only)) fail("--only takes ti, ai or eval");
    } else if (key === "plan") {
      args.plan = true;
    } else {
      fail(`unknown argument ${arg}`);
    }
  }
  return args;
}

function fail(message) {
  console.error(`live:run: ${message}`);
  process.exit(2);
}

function readEnvFile(path) {
  const env = {};
  for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
    const match = /^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (match && !line.trimStart().startsWith("#")) env[match[1]] = match[2].replace(/^"(.*)"$/, "$1");
  }
  return env;
}

function today() {
  return new Date().toISOString().slice(2, 10).replaceAll("-", "");
}

function reportPath() {
  return resolve(ROOT, "plans", "reports", `live-run-${today()}.md`);
}

function writeReport(lines, { force = false } = {}) {
  const path = reportPath();
  if (!force && existsSync(path) && /^status: run$/m.test(readFileSync(path, "utf8"))) {
    console.error(`live:run: ${path} already records a run; not overwritten`);
    return;
  }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, lines.join("\n") + "\n", { encoding: "utf8" });
  console.log(`written: plans/reports/live-run-${today()}.md`);
}

function header(status, args) {
  return [
    "# Live TI / AI provider run (M7 phase 5)",
    "",
    `status: ${status}`,
    `date: ${new Date().toISOString().slice(0, 16).replace("T", " ")} UTC`,
    `command: \`node scripts/live_run.mjs ${process.argv.slice(2).join(" ")}\``,
    `budget: ${args["max-calls"] ?? "-"} calls, ${args["max-usd"] ?? "-"} USD`,
    "",
  ];
}

function notRun(args, reason) {
  writeReport([
    ...header("not run", args),
    `reason: ${reason}`,
    "",
    "The live provider tests (`tests/unit/test_ti_provider_live.py`,",
    "`tests/unit/test_ai_provider_live.py`, `tests/ai_eval/test_ai_eval_live.py`) need the",
    "user's own provider keys and budget. Without them the live TI enrichment success and the",
    "live AI citation accuracy stay unmeasured; the offline harnesses (`scripts/ti_eval.py`,",
    "`scripts/ai_eval.py` replay) are the recorded numbers. See `scripts/live_run.mjs` for the",
    "keys, the network path and the budget rules.",
  ]);
  fail(`refused: ${reason}`);
}

// --- plan --------------------------------------------------------------------------------------

function tiProviders(env) {
  return TI_PROVIDERS.filter(
    (p) => env[`CYBERLAB_TI_KEY_${p.toUpperCase()}`] || (ABUSECH.has(p) && env.CYBERLAB_TI_KEY_ABUSECH),
  );
}

function aiProviders() {
  return AI_PROVIDERS.filter((p) => existsSync(resolve(SECRETS, `ai_eval_${p}.key`)));
}

function evalCases() {
  if (!existsSync(CASES_DIR)) return [];
  const all = readdirSync(CASES_DIR).filter((f) => f.endsWith(".json")).map((f) => f.slice(0, -5)).sort();
  return [...PREFERRED_CASES.filter((c) => all.includes(c)), ...all.filter((c) => !PREFERRED_CASES.includes(c))];
}

const caseCalls = (name) => (name.startsWith("incident_") ? 4 : 1);

function makePlan(args, env) {
  const steps = [];
  let calls = 0;
  let usd = 0;
  const fits = (c, rate) => calls + c <= args["max-calls"] && usd + c * rate <= args["max-usd"] + 1e-9;
  const take = (step) => {
    calls += step.calls;
    usd += step.calls * step.rate;
    steps.push(step);
  };
  const want = (kind) => !args.only || args.only === kind;
  if (want("ti")) {
    for (const provider of tiProviders(env)) {
      const step = { kind: "ti", provider, model: "-", calls: 2, rate: USD_PER_CALL.ti };
      if (fits(step.calls, step.rate)) take(step);
    }
  }
  const ai = aiProviders();
  if (want("ai")) {
    for (const provider of ai) {
      const model = env[`AI_LIVE_${provider.toUpperCase()}_MODEL`] || "catalog default";
      const step = { kind: "ai", provider, model, calls: AI_SMOKE_CALLS[provider], rate: USD_PER_CALL[provider] };
      if (fits(step.calls, step.rate)) take(step);
    }
  }
  if (want("eval")) {
    for (const provider of ai) {
      const model = env[`AI_LIVE_${provider.toUpperCase()}_MODEL`];
      if (!model) continue; // the evaluation needs an explicit model id
      const cases = [];
      let cost = 0;
      for (const name of evalCases()) {
        const c = caseCalls(name) * args.runs;
        if (!fits(cost + c, USD_PER_CALL[provider])) break;
        cases.push(name);
        cost += c;
      }
      if (cases.length) take({ kind: "eval", provider, model, cases, calls: cost, rate: USD_PER_CALL[provider] });
    }
  }
  return { steps, calls, usd };
}

// --- run ---------------------------------------------------------------------------------------

function docker(args, extraEnv = {}) {
  const result = spawnSync("docker", args, {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...process.env, MSYS_NO_PATHCONV: "1", ...extraEnv },
    maxBuffer: 64 * 1024 * 1024,
  });
  return { status: result.status ?? 1, out: `${result.stdout ?? ""}\n${result.stderr ?? ""}` };
}

// pytest -rA lines: "PASSED tests/...::test[x]", "FAILED ...", "SKIPPED [1] file:line: reason".
function outcomes(out) {
  const found = { passed: [], failed: [], skipped: 0 };
  for (const line of out.split(/\r?\n/)) {
    let m;
    if ((m = /^PASSED (\S+)/.exec(line))) found.passed.push(m[1]);
    else if ((m = /^(?:FAILED|ERROR) (\S+)/.exec(line))) found.failed.push(m[1]);
    else if (/^SKIPPED \[(\d+)\]/.test(line)) found.skipped += Number(/^SKIPPED \[(\d+)\]/.exec(line)[1]);
  }
  return found;
}

function runTi(step, args) {
  const result = docker([
    ...COMPOSE_RUN, "--env-from-file", LIVE_ENV,
    "-e", "CYBERLAB_LIVE_TI=1", "-e", "PYTHONDONTWRITEBYTECODE=1",
    "-e", `AI_LIVE_MAX_CALLS=${args["max-calls"]}`,
    "enrich-worker-test", ...PYTEST, "tests/unit/test_ti_provider_live.py", "-k", step.provider,
  ]);
  const o = outcomes(result.out);
  return { ...step, ok: result.status === 0 && o.failed.length === 0 && o.passed.length > 0, counted: 2 * (o.passed.length + o.failed.length), ...o };
}

function runAi(step, args) {
  const upper = step.provider.toUpperCase();
  const key = resolve(SECRETS, `ai_eval_${step.provider}.key`);
  const env = ["-e", "AI_EVAL_LIVE=1", "-e", `AI_LIVE_${upper}_KEY_FILE=/run/live/${step.provider}.key`,
    "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", `AI_LIVE_MAX_CALLS=${args["max-calls"]}`,
    // The test service's 8 s call timeout is for ai-mock; a real provider needs longer.
    "-e", "AI_CALL_TIMEOUT_S=120"];
  if (step.model !== "catalog default") env.push("-e", `AI_LIVE_${upper}_MODEL=${step.model}`);
  const result = docker([
    ...COMPOSE_RUN, "-v", `${key}:/run/live/${step.provider}.key:ro`, ...env,
    "analyst-worker-test", ...PYTEST, "tests/unit/test_ai_provider_live.py", "-k", step.provider,
  ]);
  const o = outcomes(result.out);
  return { ...step, ok: result.status === 0 && o.failed.length === 0 && o.passed.length > 0, counted: o.passed.length + o.failed.length ? step.calls : 0, ...o };
}

function runEval(step, args) {
  const python = process.env.PYTHON || (process.platform === "win32" ? "python" : "python3");
  const result = spawnSync(python, [
    "scripts/ai_eval.py", "--provider", step.provider, "--model", step.model,
    "--runs", String(args.runs), "--cases", step.cases.join(","),
  ], {
    cwd: ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, AI_EVAL_LIVE: "1", AI_LIVE_MAX_CALLS: String(args["max-calls"]) },
  });
  const out = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  const counted = [...out.matchAll(/round \d+: (\d+) provider calls pending/g)].reduce((n, m) => n + Number(m[1]), 0);
  const floors = /LIVE FLOORS[^\n]*/.exec(out)?.[0] ?? null;
  const accuracy = /citation accuracy min ([0-9.]+|None)/.exec(out)?.[1] ?? null;
  return { ...step, ok: result.status === 0, counted, floors, accuracy, passed: [], failed: result.status === 0 ? [] : ["scripts/ai_eval.py"], skipped: 0 };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const missing = Object.keys(DEFAULTS).filter((k) => !args.given.has(k));
  if (missing.length) notRun(args, `missing ${missing.map((k) => `--${k}`).join(" and ")} (budget flags are required)`);
  if (process.env.CYBERLAB_LIVE !== "1") notRun(args, "CYBERLAB_LIVE=1 is not set (live provider calls are opt-in)");
  if (!existsSync(LIVE_ENV)) notRun(args, "no provider keys: .secrets/live.env does not exist");
  const env = readEnvFile(LIVE_ENV);
  const plan = makePlan(args, env);
  console.log(`plan: ${plan.calls} calls, about ${plan.usd.toFixed(2)} USD (budget ${args["max-calls"]} calls, ${args["max-usd"]} USD)`);
  for (const s of plan.steps) {
    console.log(`  ${s.kind} ${s.provider} ${s.model}: ${s.calls} calls${s.cases ? ` (${s.cases.length} cases)` : ""}`);
  }
  if (!plan.steps.length) notRun(args, "no configured provider fits the budget (or no keys in .secrets/)");
  if (args.plan) return;

  const results = [];
  for (const step of plan.steps) {
    console.log(`running ${step.kind} ${step.provider} ...`);
    const r = step.kind === "ti" ? runTi(step, args) : step.kind === "ai" ? runAi(step, args) : runEval(step, args);
    console.log(`  ${r.ok ? "ok" : "FAILED"} (${r.passed.length} passed, ${r.failed.length} failed, ${r.skipped} skipped)`);
    results.push(r);
  }
  const counted = results.reduce((n, r) => n + r.counted, 0);
  const cost = results.reduce((n, r) => n + r.counted * r.rate, 0);
  const ti = results.filter((r) => r.kind === "ti");
  const evals = results.filter((r) => r.kind === "eval");
  const failures = results.flatMap((r) => r.failed.map((id) => `- ${r.kind} ${r.provider}: \`${id}\``));
  const lines = [
    ...header("run", args),
    `calls: ${counted} counted (${plan.calls} planned); cost estimate: ${cost.toFixed(2)} USD (per-call estimates, not provider invoices)`,
    `enrichment success: ${ti.length ? `${ti.filter((r) => r.ok).length} / ${ti.length} TI providers passed verify + lookup` : "not run"}`,
    `citation accuracy: ${evals.length ? evals.map((r) => `${r.provider} ${r.model}: min ${r.accuracy ?? "n/a"}`).join("; ") : "not run"}`,
    "",
    "## Providers",
    "",
    "| Step | Provider | Model | Calls (planned / counted) | Cost estimate | Result |",
    "|---|---|---|---|---|---|",
    ...results.map((r) => `| ${r.kind} | ${r.provider} | ${r.model} | ${r.calls} / ${r.counted} | ${(r.counted * r.rate).toFixed(2)} USD | ${r.ok ? "ok" : "failed"} |`),
    "",
    "## AI evaluation (live floors, reported, gate-free)",
    "",
    ...(evals.length ? evals.map((r) => `- ${r.provider} ${r.model} (${r.cases.length} cases x ${args.runs} runs): ${r.floors ?? "no floors line (see the terminal)"}`) : ["- not run (no AI key file or no AI_LIVE_<PROVIDER>_MODEL in live.env, or over budget)"]),
    "",
    "## Failures",
    "",
    ...(failures.length ? failures : ["- none"]),
    "",
    "Keys came from `.secrets/` (never printed); no raw provider responses are recorded here.",
  ];
  writeReport(lines, { force: true });
  process.exit(results.every((r) => r.ok) ? 0 : 1);
}

main();
