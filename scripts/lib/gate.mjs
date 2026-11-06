// Compose project helpers of the gate (`scripts/verify.mjs`, M7 phase 11).
//
// - The dev phase runs in the gate's project: COMPOSE_PROJECT_NAME, or `cyberlab` (the
//   `name:` of docker-compose.yml).
// - The prod phase runs in its own project, `<dev>-prod`, with its own volumes: dev MinIO
//   writes its IAM with the committed dev KMS key, which the prod overlay's key cannot read.
// - The restore drill gets an env without any COMPOSE_* variable: it names its project
//   (`cyberlab-drill`) itself and its down -v guard refuses any other COMPOSE_PROJECT_NAME.
// Nothing here removes a volume.

export const DEFAULT_PROJECT = "cyberlab";
const DRILL_PROJECT = "cyberlab-drill";
const PROJECT_RE = /^[a-z0-9][a-z0-9_-]*$/;

export function gateProjects(env = process.env) {
  const dev = (env.COMPOSE_PROJECT_NAME ?? "").trim() || DEFAULT_PROJECT;
  if (!PROJECT_RE.test(dev)) throw new Error(`invalid COMPOSE_PROJECT_NAME ${JSON.stringify(dev)}`);
  if (dev === DRILL_PROJECT || dev.startsWith(`${DRILL_PROJECT}_`)) {
    throw new Error(`the gate does not run in the restore drill's project ${DRILL_PROJECT}`);
  }
  if (dev.endsWith("-prod")) throw new Error(`COMPOSE_PROJECT_NAME=${dev}: name the dev project, the gate adds -prod`);
  return { dev, prod: `${dev}-prod` };
}

// A copy of `env` without COMPOSE_PROJECT_NAME, COMPOSE_FILE, COMPOSE_PROFILES or any other
// COMPOSE_* variable.
export function withoutComposeEnv(env = process.env) {
  return Object.fromEntries(Object.entries(env).filter(([name]) => !/^COMPOSE_/i.test(name)));
}

// The compose command line of a project (`prod`: the prod overlay too). Explicit -p, so
// COMPOSE_PROJECT_NAME in the env cannot redirect it.
export function composeCommand(project, { prod = false } = {}) {
  if (!PROJECT_RE.test(project)) throw new Error(`invalid compose project ${JSON.stringify(project)}`);
  const files = prod ? " -f docker-compose.yml -f docker-compose.prod.yml" : "";
  return `docker compose -p ${project}${files}`;
}

// The env of `node scripts/e2e.mjs --prod`: its plain `docker compose` calls (redis exec, the
// e2e runner reaching https://gateway:8443) then target the prod project.
export function prodE2eEnv(prodProject, env = process.env) {
  return { ...withoutComposeEnv(env), COMPOSE_PROJECT_NAME: prodProject };
}
