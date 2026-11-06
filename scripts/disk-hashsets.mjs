#!/usr/bin/env node
// `pnpm disk:hashsets -- [--store test] <command> [args...]` (M9): run the trusted, offline
// disk-hashsets tool (compose profile `tools`, `network_mode: none`, uid 10008) against the
// operator's known-file hash-set store, or with `--store test` against the test store. Both
// stores are mounted at /hashsets inside the tool; the operator's files are read from
// `./.disk-import` (mounted read-only at /import). Commands: import-nsrl --file --name |
// import-list --file --name --kind --algo | list | verify | remove --name
// (`disk_worker/hashsets/__main__.py`). Nothing is ever downloaded; never run by a test, gate
// or worker.
import { spawnSync } from "node:child_process";

const args = process.argv.slice(2).filter((a, i) => !(i === 0 && a === "--"));
let service = "disk-hashsets";
if (args[0] === "--store") {
  const store = args[1];
  if (store !== "test" && store !== "default") {
    console.error("--store must be `test` or `default`");
    process.exit(2);
  }
  if (store === "test") service = "disk-hashsets-test";
  args.splice(0, 2);
}
if (args.length === 0) {
  console.error(
    "usage: pnpm disk:hashsets -- [--store test] <import-nsrl|import-list|list|verify|remove> ...",
  );
  process.exit(2);
}

// MSYS_NO_PATHCONV: Git Bash on Windows would rewrite `/import/x.db` into a host path.
const run = spawnSync("docker", ["compose", "--profile", "tools", "run", "--rm", service, ...args], {
  stdio: "inherit",
  env: { ...process.env, MSYS_NO_PATHCONV: "1" },
});
process.exit(run.status ?? 1);
