# Research: Volatility 3 for an offline memory worker (M8)

Date: 2026-11-07. Method: GitHub and PyPI APIs, plus the `volatility3` source read at tag **v2.28.2** and at `develop` (77ff0b1, 2026-10-12). **[V]** means verified at the cited source. **[I]** means inferred or unverified. This is not legal advice.

## 1. Version and packaging
- **Latest release: v2.28.2 (2026-09-17)** [V GitHub releases API].
  - Earlier releases: 2.28.0 (2026-04), 2.27.0 (2026-01), 2.26.x (2025).
  - There is **no 3.x**. "Volatility 3" is the product name; the package version is 2.x [V].
- **Python:** `requires-python >= 3.8`. CI runs only Python 3.8. Python 3.12 works in practice: issue #2050 ran on 3.12, and the 3.12 `imp` break (#1220) was fixed [V]. Every dependency we need publishes cp312 / py3 manylinux wheels [V PyPI].
- **Installing:**
  - `pip install volatility3` installs the package with its `LICENSE.txt` in `dist-info`, about 9 MB, without symbol packs [V wheel].
  - The only hard dependency is `pefile` (MIT).
  - The `[full]` extra pulls in yara-python (Apache-2.0), capstone, pycryptodome, pillow and **leechcorepyc (GPLv3)** [V pyproject, PyPI].
  - **Decision input:** install the needed dependencies explicitly and never `[full]`. Recommended set: `volatility3==2.28.2 pefile yara-python capstone jsonschema`.
  - Leave out pycryptodome. It is needed only by hashdump, lsadump and cachedump, which we never want to run.
  - `libsnappy1v5` is needed only for compressed AVML images [V `layers/avml.py`].
- **YARA engine:** `yarascan.py` imports `yara_x` first and falls back to `yara` (>= 3.8) [V]. Do not install yara-x, so the engine stays yara-python, the same as M3. Compiled rules are engine-specific.

## 2. License: Volatility Software License v1.0
Source: `LICENSE.txt` and https://www.volatilityfoundation.org/license/vsl-v1.0 [V]. The license:
- is free to use, irrevocable, includes a patent grant, and may terminate on violation;
- requires that the license or its link reach every recipient, and that copyright notices are kept;
- has a copyleft clause: "If you make any Additions available to others, such as by providing copies of them **or providing access to them over the Internet**, you must make them publicly available" under the VSL;
- defines Additions to include changes, ports and "**any software designed to execute the software and parse its results, such as a wrapper**". It excludes generic shell or execution-menu software.

Status:
- not OSI-approved and not on the SPDX list [V];
- Fedora rejected it as "too broad" (BZ 1767234, 2028876) [V];
- not in Debian; Kali dropped it in 2020; Arch, Alpine, Nix, FreeBSD and others ship it [V repology].

Implications [I]:
- **Pip-install at build, for our own use:** fine. The copyleft applies only when Additions are made available to others.
- **Publishing the image:** redistributing *unmodified* volatility3 is allowed with the license text. Add a NOTICE file as well.
- **Our adapter:** the code that runs Volatility and parses its output matches the "wrapper" definition. If anyone else gets it, or uses it over a network, its source must be published under the VSL. **Mitigation:**
  - keep the adapter in one directory (`apps/workers/memory/`) with its own license notice;
  - do not patch volatility3 (patches are Additions too);
  - keep the rest of the platform tool-agnostic (versioned contract, generic ingest);
  - never ship leechcorepyc, which would add GPLv3.
- The repository currently has **no license file**. Whether and how to publish is a **user decision**, required before the platform is offered to anyone else.

## 3. Symbols
- **Windows:**
  - The `pdbscan` automagic finds the kernel PDB name, GUID and age. Volatility then looks for `windows/<pdb>/<GUID-AGE>.json.xz` under the symbol dirs [V `doc/source/symbol-tables.rst`, `pdbutil.py`].
  - If no ISF is found, it downloads the PDB from `http://msdl.microsoft.com/download/symbols` (**plain HTTP**), converts it with `pdbconv`, and writes the ISF into the first writable symbols path [V]. On an SSL error it **retries with certificate verification off** [V `resources.py`].
  - **Decision input:** always run offline. Our own fetch tool uses HTTPS with verification and runs `pdbconv` on the downloaded file.
- **Linux / macOS:**
  - ISFs are built with `dwarf2json` (v0.9.0, 2024-10) from a vmlinux with DWARF debug info; System.map is optional [V].
  - A match needs an **exact banner match** (`banners` plugin), narrowed by VMCOREINFO [V `automagic/linux.py`].
  - ISFs from dwarf2json older than 0.9.0 trigger an accuracy warning [V].
- **Packs** (legacy URLs `downloads.volatilityfoundation.org/volatility3/symbols/`, all HTTP 200; SHA256SUMS published) [V]:
  - `windows.zip`: 839 727 133 B, Last-Modified 2019-10-16. Likely **lacks Windows 10 20H1+ and every Windows 11 build** [I].
  - `mac.zip`: 84.8 MB.
  - `linux.zip`: 2.98 MB, 2024-11.
  - New in `volatility3-test-data` v0.0.1 (2026-03-12): `symbols_win-10_19041-2025_03.zip`, 789 KB, matching its Win10 test dump.
  - The packs are "© Volatility Foundation, VSL" [V]. Whether ISF derived from Microsoft PDBs may be redistributed is **unverified**.
- **Cache:**
  - The identifier cache is SQLite at `$XDG_CACHE_HOME/volatility3/identifier.cache`; it must be writable.
  - `--cache-path` is applied after import, so **set `XDG_CACHE_HOME`** instead [V code].
  - Indexing the full windows pack "may take some time" [V README].
  - Open bugs:
    - #2050: installs that share the cache evict each other's entries (3.1 s warm vs 13.3 s after an eviction);
    - #2042: a SIGTERM during a download leaves a truncated cache file, and later runs fail [V].
  - → One cache per process, seeded from a read-only prebuilt copy, discarded after the run.
- **CLI:**
  - `-s/--symbol-dirs` (`;`-separated, prepended to the defaults);
  - `--offline` (blocks http(s) through `OfflineHandler`; mutually exclusive with `-u/--remote-isf-url`);
  - `--clear-cache` [V `cli/__init__.py`].
- **Remote ISF:**
  - The index format is a JSON with `version: 1` and base64 banner → URLs [V `symbol_cache.py`].
  - `Abyss-W4tcher/volatility3-symbols` has about 11.7 k Linux / macOS ISFs [V]. Caveats:
    - **it has no license file** [V];
    - its ISFs moved to GitHub Releases on 2026-10-20, and the old raw paths stop working on 2026-11-21 [V];
    - its macOS 11+ ISFs were removed [V].
  - A "JPCERT" ISF server was not found [I].

## 4. Plugins in 2.28.2 [V plugin tree]
- **Present:**
  - `windows.info`, `pslist`, `pstree`, `psscan`, `cmdline`, `netscan`, `netstat`, `dlllist`, `handles`, `svcscan`, `envars`;
  - `windows.registry.hivelist`, `windows.registry.userassist`;
  - `windows.vadyarascan`, `yarascan.YaraScan`;
  - `linux.pslist`, `pstree`, `psaux`, `bash`, `lsof`, `sockstat`, `elfs`, `linux.vmayarascan`.
- **Renamed** (the old names are deprecated shims whose removal dates have passed but which still exist):
  - `windows.malfind` → **`windows.malware.malfind`** (capstone for `Disasm`);
  - `windows.ldrmodules` → `windows.malware.ldrmodules`;
  - `windows.psxview` → `windows.malware.psxview`, plus the other `windows.malware.*` plugins;
  - `linux.malfind` → `linux.malware.malfind`;
  - `linux.check_syscall` → `linux.malware.check_syscall`;
  - `linux.hidden_modules` → `linux.malware.hidden_modules`;
  - hashdump / lsadump / cachedump / amcache / scheduled_tasks → `windows.registry.*` (the first three need pycryptodome).
- **New:** `windows.malware.pebmasquerade` (2.27); `linux.sockscan` and `linux.malware.process_spoofing` (2.28).
- **macOS:** deprecated in 2.28.2 [V release notes].
- **Architectures:** x86 / x64 only; the ARM64 PRs were not merged [V].
- **Decision input:** use the new names only; keep macOS and ARM64 out of scope.

## 5. Output [V `cli/text_renderer.py`]
- `-r json`: a JSON array of row dicts keyed by column name, each with `__children`, in which tree plugins nest their rows.
- `-r jsonl`: one top-level row per line.
- **Both buffer the whole result** (no streaming).
- Value types:
  - Hex columns are plain ints;
  - datetimes are ISO-8601 `+00:00`;
  - `Hexdump` is a space-separated hex string;
  - `Disasm` is capstone text;
  - `windows.info` values are strings.
- Flags: `-q` (quiet); `-f` (= `--single-location=file://…`); `-o` (dump dir, sanitized names); `--filters`.
- TreeGrid keeps every row in memory (#1725) [V].
- → Use our own visitor in library mode: stream rows with caps and stop at the cap.

## 6. Runtime, formats, I/O
- **Timings:**
  - `windows.pslist`: about 3 s warm, 9–13 s on a cache rebuild [V #2050];
  - a 32 GB image: about 51 s first run, about 15 s afterwards (the kernel-locating scan dominates) [V blog 2025-01];
  - pool and physical scanners (`psscan`, `netscan`, `yarascan`) scale roughly linearly with image size [I];
  - `--parallelism` exists and is off by default [V].
- **Formats** [V `framework/layers/`]:
  - raw / padded, LiME, AVML, ELF64 core, VMware `.vmem` (+ `.vmss` / `.vmsn` next to it), QEMU, Xen;
  - Windows crash dumps: **full (0x1) and bitmap (0x5) only**;
  - **no hiberfil.sys** (PR #1036 is still open).
- **I/O:**
  - `file://` gives random access;
  - `http(s)://` images are **downloaded in full** into the cache;
  - `s3://` needs the `[cloud]` extra.
  - → Download to local disk (hash-verified), open as a file.

## 7. Security
- **No CVEs:** NVD and OSV have none, and there are no GitHub advisories [V].
- **Robustness bugs, so treat a hostile image as a DoS risk:**
  - infinite loops (#646, #1482, #1489, #2024 open);
  - recursion (#441);
  - smear-induced bad pointers (#1243 open).
  - → wall clock, `RLIMIT_AS` and output caps.
- **Tar-slip** in `linux.pagecache.RecoverFs` (PR #1996 open) → never run extraction plugins.
- **ISF:**
  - ISFs are JSON with no eval or pickle [V];
  - **schema validation is silently skipped if `jsonschema` is missing** [V `schemas/__init__.py`] → install it.
- **Plugins are Python, and every plugin file is imported on every run**, even unselected ones [V `framework/__init__.py`]. Imports come from:
  - `-p` dirs;
  - `site-packages/volatility3/plugins`;
  - `framework/plugins`.

  `~/.config/volatility3/vol.json` can set plugin and symbol dirs [V].

  Required controls:
  - a read-only, root-owned site-packages;
  - `HOME` set to an empty read-only dir;
  - never accept `-p`, a config file, `--yara-compiled-file` or a URL for `--yara-file`.

## 8. Test images
- **`volatility3-test-data` v0.0.1** [V; licence stated "VSL, © Volatility Foundation" in its README]:
  - `win-10_19041-2025_03.dmp.gz`: 693 MB, plus its 789 KB symbol zip;
  - `linux-sample-1.bin.gz`: 144 MB, plus `linux.zip`;
  - `win-xp-laptop-2005-06-25.img.gz`: 180 MB.

  Upstream CI runs `-r json` against these images, fully offline [V workflow]. Whether they hold malware is **unverified**; they are regression images.
- **Avoid:**
  - the Volatility 2 wiki samples (Cridex, Shylock, R2D2, Malware Cookbook);
  - Ali Hadi's Memory #01 (ransomware);
  - MemLabs (CTF artefacts) [V / I].
- **Unreviewed:** the Digital Corpora M57 RAM images ("freely available") and NIST CFReDS; their terms were not reviewed [I].
- **Synthetic images:** **no public project builds a fake layer plus a matching ISF** [unverified after searching]. `BufferDataLayer` exists. A tiny synthetic **Linux** image (banner, page tables, an `init_task` list, a hand-written ISF) is feasible but laborious [I]. A synthetic Windows image (PDB scan, kernel discovery) is harder [I].
- **Decision input:**
  - unit tests on our own Volatility-shaped JSON rows;
  - a time-boxed synthetic Linux image;
  - an **opt-in reference corpus** (the test-data images, sha256-pinned, downloaded by an operator into a Docker volume, never committed).

## 9. YARA in memory [V `yarascan.py`, `vadyarascan.py`, `vmayarascan.py`]
- `yarascan.YaraScan` scans the kernel / primary layer (Intel 32/64).
- `windows.vadyarascan` and `linux.vmayarascan` scan process memory and accept `--pid`.
- Options: `--yara-string`, `--yara-file`, `--yara-compiled-file`, `--insensitive`, `--wide`, `--max-size` (default 1 GiB).
- `--yara-file` accepts paths or URIs → pass a local root-owned file only.

## Sources
- https://github.com/volatilityfoundation/volatility3 (tag v2.28.2: README, LICENSE.txt, pyproject.toml, `.github/workflows/test.yaml`, `volatility3/cli/__init__.py`, `cli/text_renderer.py`, `framework/constants`, `framework/layers/*`, `framework/automagic/symbol_cache.py`, `symbols/windows/pdbutil.py`, `plugins/yarascan.py`, `framework/__init__.py`, `schemas/__init__.py`, `doc/source/symbol-tables.rst`, `doc/source/vol-cli.rst`)
- https://api.github.com/repos/volatilityfoundation/volatility3/releases ; https://pypi.org/project/volatility3/
- https://www.volatilityfoundation.org/license/vsl-v1.0
- https://github.com/volatilityfoundation/volatility3-test-data/releases/tag/v0.0.1 ; https://downloads.volatilityfoundation.org/volatility3/symbols/
- https://github.com/volatilityfoundation/dwarf2json ; https://github.com/Abyss-W4tcher/volatility3-symbols
- Issues / PRs #2050, #2042, #1996, #2024, #1482, #1725, #1243, #1036, #2014, #1220 on the volatility3 repository
- https://bugzilla.redhat.com/show_bug.cgi?id=2028876 ; https://bugzilla.redhat.com/show_bug.cgi?id=1767234 ; https://repology.org/project/volatility3 ; https://pkg.kali.org/pkg/volatility3 ; https://opensource.org/api/licenses
- https://services.nvd.nist.gov (keyword volatility3: 0) ; https://api.osv.dev (PyPI volatility3: none) ; https://pypi.org/project/leechcorepyc/
- https://danking555.github.io/posts/making-volatility-15x-faster-lessons-from-reverse-engineering-windows-internals
- https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples ; https://github.com/stuxnet999/MemLabs ; https://digitalcorpora.org/ ; https://cfreds-archive.nist.gov/ ; https://www.ashemery.com/dfir.html
