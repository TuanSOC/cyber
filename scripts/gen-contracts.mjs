#!/usr/bin/env node
// `pnpm gen:contracts`: dump the API's OpenAPI schema offline and regenerate the TS types.
// Pure Node (no shell redirection or `mv`), so it behaves the same under cmd.exe and sh.
import { spawnSync } from "node:child_process";
import { renameSync, writeFileSync } from "node:fs";

const OUT = "packages/contracts/openapi.json";

const dump = spawnSync(
  "docker",
  ["compose", "--profile", "test", "run", "--rm", "--no-deps", "-T", "api-test", "python", "-m", "app.scripts.dump_openapi"],
  { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "inherit"] },
);
if (dump.status !== 0) process.exit(dump.status ?? 1);
JSON.parse(dump.stdout); // refuse to write anything that is not a complete schema

// Write-then-rename so a failed dump never leaves a truncated contract behind.
writeFileSync(`${OUT}.tmp`, dump.stdout);
renameSync(`${OUT}.tmp`, OUT);

const gen = spawnSync("pnpm --filter @cyberlab/contracts gen", { shell: true, stdio: "inherit" });
process.exit(gen.status ?? 1);
