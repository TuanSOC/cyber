---
phase: 5
title: "Known file hash sets and YARA file scan"
status: pending
priority: P2
effort: "15h"
dependencies: [1]
---

# Phase 5: Known-file hash sets and YARA file scan (group B, 2c, lane 4)

## Overview
Two worker-side enrichments of the file listing, both fully offline:
1. **Known-file hash sets:**
   - an operator-run, **network-less** tool `disk-hashsets` that imports NSRL RDSv3 SQLite files and plain hash lists into a compact sorted store on the `disk_hashsets` volume;
   - the read-only store the worker binary-searches through `mmap`.
2. **YARA on selected files:** candidate selection per profile (PE files: every M3 baseline rule is `pe`-anchored), the in-probe `yara-python` call compiling the baked M3 rule sources (the M3 `yarascan.py` pattern), and parsing the hits into findings input with the lifted (file sha256, rule) allow-list (RT8).

**Owns:**
- `apps/workers/disk/disk_worker/hashsets/**` (`store.py`, `manifest.py`, `importer.py`, `extsort.py`, `__main__.py` CLI);
- `disk_worker/scan.py` (`build_candidates`, `parse_scan_output`);
- `disk_worker/probe/scan_yara.py` (called by phase 2's `scan` stage shell);
- `tests/unit/test_hashsets_*.py`, `test_scan_*.py`;
- `tests/integration/test_hashsets_tool.py`.

## Requirements
- **Store format** (`store.py`; `HashSetManifestV1` frozen in phase 1):
  - `<root>/<name>/{sha256,sha1,md5}.bin`: sorted, unique, fixed-width raw digests (32 / 20 / 16 bytes), no header;
  - `<root>/manifest.json`: written atomically (temp + rename).
  - **`HashSetStore(root)`:**
    - loads the manifest;
    - checks every file's size against `count × width` (cheap; the full re-hash is `verify`);
    - mmaps read-only;
    - `match(sha256, sha1, md5) -> HashSetHit | None` binary-searches in `known_bad` → `notable` → `known_good` order, first hit wins, and reports the set name and kind.
  - A missing or empty store is valid (no sets). A manifest that fails validation disables matching and is reported in the header (`hashsets_status: invalid`), never a job failure.
- **Tool** (`python -I -m disk_worker.hashsets`, service `disk-hashsets`, `network_mode: none`, uid 10008):
  - **`import-nsrl --file /import/<f> --name <n> [--kind known_good]`:**
    - opens the RDSv3 SQLite **read-only** (`file:…?mode=ro&immutable=1`) in a forked child (RLIMIT_AS 2 GiB, timeout 4 h, the kit's seccomp filter, **no uid change**: the tool already runs as 10008 without capabilities, so `sandbox.run_tool` is not used; RT25; `sqlite3` with `trusted_schema=OFF`, no extensions);
    - streams the distinct `sha256` (and `sha1`, `md5` where present) values from the `FILE` view (`sha256`, `sha1`, `md5`, `file_name`, `file_size`, `package_id`; the minimal set may also offer a `DISTINCT_HASH` view, used when present). The red team read these names in NIST's README; this phase re-verifies them against NIST's schema documentation, and the importer checks the schema and refuses unknown layouts;
    - validates each digest as hex of the exact length (others counted and skipped);
    - external-sorts into the temp dir (chunks of 64 Mi records, k-way merge, dedupe);
    - verifies count and order, writes the files, hashes them, and moves them atomically under `<name>/`;
    - updates the manifest with `source_sha256` (the import file's sha256) and the tool version.
  - **`import-list --file /import/<f> --name <n> --kind known_good|known_bad|notable --algo sha256|sha1|md5`:** one digest per line, optional `*name` / whitespace suffix (md5sum style), `#` comments; the same validation and sort.
  - **`list`** (names, kinds, counts, imported_at); **`verify`** (re-hash every file against the manifest; exit 1 on mismatch); **`remove --name <n>`** (manifest first, then files).
  - **Input safety:** `--file` must be a single path component under `/import` (no `..`, no symlink: `O_NOFOLLOW`, regular file). Names match the manifest regex. The tool never opens a network socket (`network_mode: none`; a test asserts the compose service has no networks).
  - **Size note** (DEPLOYMENT, phase 12): the full RDSv3 Modern set is hundreds of GB uncompressed (≈ 457 GB at 2026.03.1), so operators import the `minimal` set; the sorted sha256 file is 32 bytes per distinct hash. The import needs temp space ≈ 2 × the output.
- **Worker matching** (called by phase 2's root after `walk`): every hashed file gets `known` / `known_set`. The header records every set (name, kind, count, manifest file sha256s) and `hashsets_status`. `known = good` means "in a reference set", not benign (NSRL also lists dual-use tools and vulnerable drivers; RT18).
- **YARA candidates** (`scan.build_candidates(files, profile, limits)`):
  - allocated regular files and named streams with `hash_status = hashed` and a magic class in `cyberlab_jobs.disk.YARA_MAGIC_CLASSES` (`{pe}`: every M3 baseline rule is anchored on `pe.*` / `MZ`, so ELF or script files can never match; widened when such rules exist; RT8);
  - triage: ≤ 32 MiB, ≤ 20 000 files, total ≤ 4 GiB;
  - full: ≤ 64 MiB, ≤ 100 000 files, ≤ 16 GiB;
  - deterministic order: user-writable path classes first, then size ascending, then path;
  - files whose `known = good` are skipped (counted) **unless** they sit in a user-writable path class (phase 6's `paths.py`; RT18).
- **In-probe scan** (`probe/scan_yara.py`, inside phase 2's sandboxed `scan` stage):
  - compiles the rule sources with `cyberlab_worker.yara_rules.rule_files([/opt/rules/image, <test dir>])` and `yara.compile(filepaths=…)` (namespaces `image.<stem>` / `test.<stem>`; a file that does not compile is dropped and reported, the M3 rule); no `.yarc`, because the allow-list is keyed on each **source** file's sha256 (RT8);
  - root hashes the same files (`rule_hashes`, never parsing them) and checks the baked file's sha256 against `versions.json`, refusing on mismatch;
  - `rules.match(data=<bytes>, timeout=10, fast=False)` per candidate;
  - emits `{natural key, rule, namespace, tags (≤ 8), strings_count (≤ 1 000)}`. The matched string data is **never** emitted (file contents stay in the image);
  - a per-file timeout or error is counted and the scan continues.
- **Hit parsing** (`scan.parse_scan_output`, root): bounded rows, namespaces checked against the rule files root hashed, severities through `cyberlab_worker.yara_rules.yara_ceilings(rule_hashes, test_rules=…)` / `yara_severity` (the lifted M3 functions; unknown → `low`). Each hit sets `disk_files.yara_rules` and feeds phase 6's `signature:yara@1`.
- **Test rules:** the M3 test marker rule (`tests/rules/yara/cyberlab_test.yar`, `TEST_RULES_SHA256`) is mounted as the `test` source directory in the test profile only, exactly as the static worker does; the production rule path never contains test rules.

## Implementation Steps
1. Read the M8 symbol tool (the trusted-tool pattern), `cyberlab_worker.yara_rules`, the M3 `probe/yarascan.py` and `detections/signatures.py`, and the NIST RDSv3 schema documentation (record the column names and the documentation URL in the code).
2. Store, manifest, external sort, importer, CLI; a generated RDSv3-schema SQLite fixture (our own rows, a few thousand random digests) and md5sum lists.
3. `test_hashsets_tool.py`: the compose run with `--store test` and the generated files mounted at `/import`, then `list` / `verify` / `remove`, and the negative cases (symlink, `..`, a bad schema, bad digests, an interrupted import leaving no partial set).
4. Candidates, the in-probe scan, hit parsing; tests with the temp marker rule over generated files (via phase 4's images in lane 4 with `--heavy`, or synthetic byte buffers for unit tests).
5. Lane 4, `ruff`, `mypy`.

## Success Criteria
- [ ] Imports of an RDSv3-schema SQLite and of md5sum / sha256 lists produce sorted unique stores with a verifiable manifest, offline, with bounded memory (a 50 M-digest synthetic list imports within 2 GiB RSS).
- [ ] Matching is correct for each kind and precedence; an invalid store disables matching without failing the job.
- [ ] The YARA scan respects every budget, scans PE candidates only (known-good ones in user-writable paths included), never emits matched bytes, refuses a tampered rules file, and maps severities through the lifted M3 allow-list (the baseline's medium ceilings and the test marker in the test profile).
- [ ] The tool service has no network, and its input paths cannot escape `/import`.

## Risk Assessment
- **RDSv3 schema details** are unverified [I] (research §8): the importer checks the schema explicitly and refuses unknown layouts; the generated fixture follows the documented schema.
- **Large imports on the dev host:** external sort with bounded memory; temp space is documented; the operator runs it once per NSRL release.
- **Operator-supplied "known bad" lists are unverified:** findings cap at `medium` and name the set, so an analyst can judge the source.
