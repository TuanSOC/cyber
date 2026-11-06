#!/usr/bin/env node
// `pnpm disk:gen -- [--only ID,...] [--hostile N --seed S] [--ntfs-route auto|libntfs|fat32]
// [--test-hashsets]` (M9 phase 4): build the synthetic disk images and their ground truth with
// `python -m samples.diskgen` inside `disk-worker-test` (the dev / test image: its GPL image
// tools never reach prod). Unprivileged: no loop device, no FUSE, no mount (parent decision,
// RT26). The output goes to the named volume `cyberlab_e2e_samples` (docker-compose.yml
// `e2e_samples`, the e2e convention: synthetic data never lands on the host disk) under `disk/`,
// replacing the previous set; nothing is committed. The engine tests then read it, e.g.
//   docker compose --profile test run --rm --no-deps -v cyberlab_e2e_samples:/samples:ro \
//     -e DISK_ENGINE_IMAGES=/samples/disk disk-worker-test pytest -q tests/engine/test_tsk_images.py
// `--test-hashsets` (M9 phase 13, the gate's pipeline run; needs `ext4_linux` in the set):
// `python -m samples.diskgen.hashlists` writes `disk/hashsets/` (one known-good and one
// known-bad sha256 list taken from the ground truth, plus `expected.json`), then the trusted
// `disk-hashsets-test` tool (no network, uid 10008) replaces the sets `test-known-good` and
// `test-known-bad` in the TEST store (`disk_hashsets_test`, which disk-worker-test mounts
// read-only). The operator's store is never touched.
// Note: `pnpm e2e` clears the volume first; run this again afterwards when needed.
import { spawnSync } from "node:child_process";

let args = process.argv.slice(2).filter((a, i) => !(i === 0 && a === "--"));
const TEST_HASHSETS = args.includes("--test-hashsets");
args = args.filter((a) => a !== "--test-hashsets");
const VOLUME = "cyberlab_e2e_samples";
// MSYS_NO_PATHCONV: Git Bash on Windows would rewrite `/samples/disk` into a host path.
const ENV = { ...process.env, MSYS_NO_PATHCONV: "1" };

function docker(argv, { allowFail = false } = {}) {
  console.log(`  $ docker ${argv.join(" ")}`);
  const run = spawnSync("docker", argv, { stdio: "inherit", env: ENV });
  if (run.status !== 0 && !allowFail) process.exit(run.status ?? 1);
  return run.status;
}

docker(["volume", "create", VOLUME]);
const service = [
  "compose", "--profile", "test", "run", "--rm", "--no-deps", "-v", `${VOLUME}:/samples`,
  "disk-worker-test", "sh", "-c",
];
// Generate in the 1 GiB /work tmpfs, then replace /samples/disk with the result.
const quoted = args.map((a) => `'${a.replaceAll("'", "'\\''")}'`).join(" ");
const lists = TEST_HASHSETS ? " && python -m samples.diskgen.hashlists --out /work/diskgen" : "";
docker([
  ...service,
  `python -m samples.diskgen --out /work/diskgen ${quoted}${lists} && rm -rf /samples/disk && ` +
    "cp -r /work/diskgen /samples/disk && chmod -R a+rX /samples/disk && ls /samples/disk",
]);

if (TEST_HASHSETS) {
  // The import dir is the generated list directory (read-only); `--file` is a single name
  // under it (the importer's rule). A missing set on `remove` is fine (first run).
  const tool = [
    "compose", "--profile", "tools", "run", "--rm", "-v", `${VOLUME}:/samples:ro`,
    "-e", "DISK_HASHSETS_IMPORT_DIR=/samples/disk/hashsets", "disk-hashsets-test",
  ];
  for (const [name, kind, file] of [
    ["test-known-good", "known_good", "test_known_good.sha256"],
    ["test-known-bad", "known_bad", "test_known_bad.sha256"],
  ]) {
    docker([...tool, "remove", "--name", name], { allowFail: true });
    docker([...tool, "import-list", "--file", file, "--name", name, "--kind", kind, "--algo", "sha256"]);
  }
  docker([...tool, "list"]);
}
