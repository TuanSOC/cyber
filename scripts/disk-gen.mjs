#!/usr/bin/env node
// `pnpm disk:gen -- [--only ID,...] [--hostile N --seed S] [--ntfs-route auto|libntfs|fat32]`
// (M9 phase 4): build the synthetic disk images and their ground truth with
// `python -m samples.diskgen` inside `disk-worker-test` (the dev / test image: its GPL image
// tools never reach prod). Unprivileged: no loop device, no FUSE, no mount (parent decision,
// RT26). The output goes to the named volume `cyberlab_e2e_samples` (docker-compose.yml
// `e2e_samples`, the e2e convention: synthetic data never lands on the host disk) under `disk/`,
// replacing the previous set; nothing is committed. The engine tests then read it, e.g.
//   docker compose --profile test run --rm --no-deps -v cyberlab_e2e_samples:/samples:ro \
//     -e DISK_ENGINE_IMAGES=/samples/disk disk-worker-test pytest -q tests/engine/test_tsk_images.py
// Note: `pnpm e2e` clears the volume first; run this again afterwards when needed.
import { spawnSync } from "node:child_process";

const args = process.argv.slice(2).filter((a, i) => !(i === 0 && a === "--"));
const VOLUME = "cyberlab_e2e_samples";

function docker(argv) {
  console.log(`  $ docker ${argv.join(" ")}`);
  // MSYS_NO_PATHCONV: Git Bash on Windows would rewrite `/samples/disk` into a host path.
  const run = spawnSync("docker", argv, {
    stdio: "inherit",
    env: { ...process.env, MSYS_NO_PATHCONV: "1" },
  });
  if (run.status !== 0) process.exit(run.status ?? 1);
}

docker(["volume", "create", VOLUME]);
const service = [
  "compose", "--profile", "test", "run", "--rm", "--no-deps", "-v", `${VOLUME}:/samples`,
  "disk-worker-test", "sh", "-c",
];
// Generate in the 1 GiB /work tmpfs, then replace /samples/disk with the result.
const quoted = args.map((a) => `'${a.replaceAll("'", "'\\''")}'`).join(" ");
docker([
  ...service,
  `python -m samples.diskgen --out /work/diskgen ${quoted} && rm -rf /samples/disk && ` +
    "cp -r /work/diskgen /samples/disk && chmod -R a+rX /samples/disk && ls /samples/disk",
]);
