#!/usr/bin/env node
// `pnpm e2e` (add `--prod` for the prod-like stack over TLS): Playwright golden path against
// the running stack. Each run registers a fresh user, so the per-IP register rate limit is
// cleared first; that is the only state this touches besides the data the test itself creates.
import { spawnSync } from "node:child_process";

const PROD = process.argv.includes("--prod");
const COMPOSE = PROD ? "docker compose -f docker-compose.yml -f docker-compose.prod.yml" : "docker compose";
const TARGET = PROD ? "-e E2E_BASE_URL=https://gateway:8443 -e E2E_IGNORE_HTTPS_ERRORS=1" : "";

function sh(command) {
  console.log(`  $ ${command}`);
  const result = spawnSync(command, { shell: true, stdio: "inherit" });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

// A Lua one-liner avoids shell pipes, so it behaves the same under cmd.exe and sh.
sh(
  `${COMPOSE} exec -T redis redis-cli EVAL "for _,k in ipairs(redis.call('KEYS', ARGV[1])) do redis.call('DEL', k) end return 1" 0 "rl:register:*"`,
);
sh(`${COMPOSE} --profile e2e run --rm --build ${TARGET} e2e`);
