// node --test scripts/lib/gate.test.mjs (host; no container is started).
// The gate's compose projects: the prod phase never shares the dev project (and so its MinIO
// volume), the restore drill never sees a COMPOSE_* variable, and every compose command names
// its project explicitly.
import assert from "node:assert/strict";
import { test } from "node:test";

import { DEFAULT_PROJECT, composeCommand, gateProjects, prodE2eEnv, withoutComposeEnv } from "./gate.mjs";

test("gate projects: default cyberlab, prod in its own project", () => {
  assert.equal(DEFAULT_PROJECT, "cyberlab");
  assert.deepEqual(gateProjects({}), { dev: "cyberlab", prod: "cyberlab-prod" });
  assert.deepEqual(gateProjects({ COMPOSE_PROJECT_NAME: "" }), { dev: "cyberlab", prod: "cyberlab-prod" });
  assert.deepEqual(gateProjects({ COMPOSE_PROJECT_NAME: "cyberlab-clean" }), {
    dev: "cyberlab-clean",
    prod: "cyberlab-clean-prod",
  });
});

test("gate projects: refuses the drill project, a -prod name and invalid names", () => {
  assert.throws(() => gateProjects({ COMPOSE_PROJECT_NAME: "cyberlab-drill" }), /restore drill/);
  assert.throws(() => gateProjects({ COMPOSE_PROJECT_NAME: "cyberlab-prod" }), /adds -prod/);
  assert.throws(() => gateProjects({ COMPOSE_PROJECT_NAME: "Cyber Lab" }), /invalid/);
  assert.throws(() => gateProjects({ COMPOSE_PROJECT_NAME: "x; rm -rf /" }), /invalid/);
});

test("withoutComposeEnv strips every COMPOSE_* variable and keeps the rest", () => {
  const env = {
    COMPOSE_PROJECT_NAME: "cyberlab-clean",
    COMPOSE_FILE: "a.yml",
    COMPOSE_PROFILES: "test",
    compose_project_name: "lower",
    PATH: "/bin",
    MINIO_IMAGE: "img",
  };
  assert.deepEqual(withoutComposeEnv(env), { PATH: "/bin", MINIO_IMAGE: "img" });
  assert.equal(env.COMPOSE_PROJECT_NAME, "cyberlab-clean", "the input is not modified");
});

test("composeCommand names the project explicitly; prod adds the overlay", () => {
  assert.equal(composeCommand("cyberlab"), "docker compose -p cyberlab");
  assert.equal(
    composeCommand("cyberlab-prod", { prod: true }),
    "docker compose -p cyberlab-prod -f docker-compose.yml -f docker-compose.prod.yml",
  );
  assert.throws(() => composeCommand("bad name"), /invalid/);
});

test("prod e2e env targets the prod project only", () => {
  const env = prodE2eEnv("cyberlab-clean-prod", { COMPOSE_PROJECT_NAME: "cyberlab-clean", COMPOSE_FILE: "x", HOME: "/h" });
  assert.deepEqual(env, { COMPOSE_PROJECT_NAME: "cyberlab-clean-prod", HOME: "/h" });
});
