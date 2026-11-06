CyberLab memory analyzer: third-party notice and licence scope
==============================================================

This directory (`apps/workers/memory/`) holds every Volatility-specific line of CyberLab: the
probe that drives the Volatility 3 framework in library mode, the normalizers of its plugin
output, the engines, and the `memory-symbols` symbol-store tool.

Volatility 3
------------
- The memory worker image installs **Volatility 3 v2.28.2** (`volatility3==2.28.2`, pinned in
  `pyproject.toml` / `uv.lock`), unmodified: nothing is removed, patched or re-packaged.
- Volatility 3 is licensed under the **Volatility Software License (VSL) v1.0**, Copyright the
  Volatility Foundation. Its licence text is the `LICENSE.txt` of the installed wheel; the
  image keeps it at `/usr/share/doc/volatility3/LICENSE.txt` (`docker/finalize_image.py`), and
  this notice at `/usr/share/doc/cyberlab-memory/NOTICE`.
- Upstream: https://github.com/volatilityfoundation/volatility3 and the licence at
  https://www.volatilityfoundation.org/license/vsl-v1.0 . This repository does not reproduce
  the licence text or any Volatility source (RT27); fixtures and row shapes here are our own.

What the VSL means for this directory (not legal advice)
--------------------------------------------------------
- Under the VSL, software "designed to execute the software and parse its results, such as a
  wrapper" is an **Addition**. The code in this directory is such an Addition.
- If an Addition is made available to others (by copies or **over the Internet**, e.g. as a
  hosted service), its source must be made available under the VSL. Running CyberLab for your
  own use creates no such obligation.
- To keep that scope narrow, M8 keeps every Volatility-specific line here; the `memory.v1`
  contract (`packages/py-jobs`), the trusted ingest, the API and the web UI are tool-agnostic.
- **Open decision (repository owner):** before CyberLab is offered to anyone else, decide
  whether to publish `apps/workers/memory/` under the VSL (the plan recommends it, alongside
  whatever licence is chosen for the rest of the repository, which has none today).

Never installed
---------------
`volatility3[full]`, `leechcorepyc` (GPLv3), `pycryptodome`, `pillow`, `pysmb`, `yara-python`,
`yara-x`: the image build fails if any of them is importable.
