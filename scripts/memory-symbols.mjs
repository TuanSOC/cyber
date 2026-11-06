#!/usr/bin/env node
// `pnpm memory:symbols -- [--store test] <command> [args...]` (M8): run the trusted
// memory-symbols tool (compose profile `tools`, its own `symbols_egress` network only) against
// the operator's symbol store, or with `--store test` against the test store. Both stores are
// mounted at /symbols inside the tool, so `reindex` always records `file:///symbols/...`
// locations (RT5). Commands: fetch-windows --pdb --guid --age | import --file | reindex |
// verify | list (`memory_worker/symbols/__main__.py`). Never run by a test, gate or worker.
import { spawnSync } from "node:child_process";

const args = process.argv.slice(2).filter((a, i) => !(i === 0 && a === "--"));
let service = "memory-symbols";
if (args[0] === "--store") {
  const store = args[1];
  if (store !== "test" && store !== "default") {
    console.error("--store must be `test` or `default`");
    process.exit(2);
  }
  if (store === "test") service = "memory-symbols-test";
  args.splice(0, 2);
}
if (args.length === 0) {
  console.error("usage: pnpm memory:symbols -- [--store test] <fetch-windows|import|reindex|verify|list> ...");
  process.exit(2);
}

// MSYS_NO_PATHCONV: Git Bash on Windows would rewrite `/import/x.json.xz` into a host path.
const run = spawnSync("docker", ["compose", "--profile", "tools", "run", "--rm", service, ...args], {
  stdio: "inherit",
  env: { ...process.env, MSYS_NO_PATHCONV: "1" },
});
process.exit(run.status ?? 1);
