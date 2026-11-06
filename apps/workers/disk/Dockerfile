# syntax=docker/dockerfile:1
# Disk forensics analyzer (M9): The Sleuth Kit through pytsk3 (library mode, no CLI), libewf
# through libewf-python, Plaso on the extracted artifact tree only, and the M3 YARA rules, over
# an attacker-controlled disk image, fully offline, one sandboxed process per stage. The Celery
# process (root, few capabilities, see docker-compose.yml) never parses image bytes; every
# probe and Plaso process runs as the unprivileged `tool` user (uid 10007: its own uid, RLIMIT
# NPROC is per uid; the worker kit reads CYBERLAB_TOOL_UID / GID) under seccomp (AF_UNIX only,
# no io_uring). The same image runs the trusted `disk-hashsets` operator tool as uid 10008
# (`hashsets`, network_mode none; RT25).
#
# Never installed in the prod target: the Debian `sleuthkit`, `python3-tsk`, `ewf-tools`
# packages (TSK 4.12.1, CVE exposure; plan "Engines"), any mkfs / mtools / ntfs-3g / sfdisk
# (the dev target only, for the phase-4 image generator) and any compiler: the Plaso builder
# stage compiles the sdist-only libyal bindings into wheels and only the wheels reach the
# runtime stages (RT11). docker/finalize_image.py asserts all of it.
#
# Licenses: TSK (inside the pytsk3 wheel) IBM-PL / CPL, pytsk3 Apache-2.0, libewf-python and
# the libyal bindings LGPL-3.0+, Plaso / dfVFS / artifacts Apache-2.0, yara-python Apache-2.0
# (YARA BSD-3): license texts and NOTICE in /usr/share/doc/cyberlab-disk/ (finalize_image.py).
#
# Build from the repo root (static_rules: the M3 baseline rule sources, compiled by the probe
# at scan start; their sha256 must equal BASELINE_SHA256, RT8):
#   docker build --build-context jobs=packages/py-jobs \
#     --build-context worker_kit=packages/py-worker-kit \
#     --build-context static_rules=apps/workers/static/rules/yara \
#     -t cyberlab/disk-worker:dev --target dev apps/workers/disk

ARG PYTHON_IMAGE=python:3.12-slim-trixie

# --- Plaso builder (RT11): compiles the sdist-only Plaso dependencies (libevtx, libregf,
# libfsntfs, libfsext, libfsfat, libbde, libfsapfs, libvsgpt at their 20261027-compatible
# versions; the phase-3a spike pins the full set with hashes in plaso.lock) into wheels. The
# download is hash-checked (`--require-hashes`); the built wheels get a SHA256SUMS manifest the
# runtime stages verify. Nothing of this stage but /wheels is copied out.
FROM ${PYTHON_IMAGE} AS plaso-builder
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       build-essential zlib1g-dev pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY plaso.lock /build/plaso.lock
RUN python -m pip download --no-cache-dir --require-hashes --no-deps \
       -r /build/plaso.lock -d /build/dl \
    && python -m pip wheel --no-cache-dir --no-index --no-deps \
       --find-links /build/dl -w /wheels /build/dl/* \
    && (cd /wheels && sha256sum ./*.whl > SHA256SUMS)

# --- runtime base ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS base
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       libmagic1 libseccomp2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:0.9.30 /uv /bin/
RUN groupadd --system --gid 10007 tool \
    && useradd --system --uid 10007 --gid 10007 --no-create-home --shell /usr/sbin/nologin tool \
    && groupadd --system --gid 10008 hashsets \
    && useradd --system --uid 10008 --gid 10008 --no-create-home --shell /usr/sbin/nologin hashsets
# HOME / XDG_CONFIG_HOME point nowhere: no user config of any tool can ever apply.
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_FROZEN=1 \
    UV_PYTHON=/usr/local/bin/python3 \
    UV_PYTHON_DOWNLOADS=never \
    UV_NO_CACHE=1 \
    PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/nonexistent \
    XDG_CONFIG_HOME=/nonexistent \
    CYBERLAB_TOOL_UID=10007 \
    CYBERLAB_TOOL_GID=10007 \
    DISK_HASHSETS_DIR=/hashsets \
    DISK_TIMELINE_ENGINE=plaso \
    DISK_RULES_DIR=/opt/rules/image
WORKDIR /srv/workers/disk
COPY --from=jobs . /packages/py-jobs
COPY --from=worker_kit . /packages/py-worker-kit
COPY pyproject.toml uv.lock ./
COPY docker/finalize_image.py /usr/local/lib/cyberlab/finalize_image.py
COPY NOTICE.md /usr/share/doc/cyberlab-disk/NOTICE.md
# The M3 baseline rule sources (root-owned, read-only; compiled by the probe at scan start).
COPY --from=static_rules --chown=0:0 --chmod=0444 . /opt/rules/image/
RUN chmod 0555 /opt/rules /opt/rules/image
# /opt/plaso: its own venv (Plaso's ~53 dependencies never mix with the worker's), installed
# from the builder's verified wheels only (no index, no compiler).
COPY --from=plaso-builder /wheels /tmp/plaso-wheels
RUN (cd /tmp/plaso-wheels && sha256sum -c SHA256SUMS) \
    && python -m venv /opt/plaso \
    && /opt/plaso/bin/python -m pip install --no-cache-dir --no-index --no-deps \
       /tmp/plaso-wheels/*.whl \
    && rm -rf /tmp/plaso-wheels
# The Plaso launcher and the single-process event exporter (phase 3), as single modules of
# /opt/plaso (under `-I` that interpreter cannot see the worker's package; RT24).
COPY plaso/cyberlab_plaso_launch.py plaso/cyberlab_plaso_export.py /tmp/plaso-modules/
RUN cp /tmp/plaso-modules/*.py \
       "$(/opt/plaso/bin/python -c 'import site; print(site.getsitepackages()[0])')/" \
    && rm -rf /tmp/plaso-modules

# --- virtualenvs (pytsk3, libewf-python and yara-python ship manylinux wheels) --------------
FROM base AS venv-dev
RUN uv sync --no-install-project

FROM base AS venv-prod
RUN uv sync --no-install-project --no-dev

# --- dev / test image: adds the phase-4 image generator's tools (GPL test tools never reach
# the prod target) and the tests / samples. Probes run as `python -I -s -m disk_worker.probe`
# (isolated mode ignores PYTHONPATH and the cwd), so the package dir reaches the venv through a
# root-owned .pth file.
FROM base AS dev
COPY docker/diskgen-packages.txt /tmp/diskgen-packages.txt
RUN apt-get update \
    && grep -v '^\s*#' /tmp/diskgen-packages.txt | xargs -r \
       env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* /tmp/diskgen-packages.txt
COPY --from=venv-dev /opt/venv /opt/venv
RUN python /usr/local/lib/cyberlab/finalize_image.py --target dev \
    && echo /srv/workers/disk > "$(python -c 'import site; print(site.getsitepackages()[0])')/cyberlab_disk.pth"
COPY disk_worker ./disk_worker
COPY tests ./tests
COPY samples ./samples
COPY dataset ./dataset
CMD ["celery", "-A", "disk_worker.celery_app", "worker", "--concurrency", "1", \
     "--max-tasks-per-child", "1", "--without-gossip", "--without-mingle", \
     "--without-heartbeat", "--loglevel", "INFO"]

# --- production image ----------------------------------------------------------------------
FROM base AS prod
COPY --from=venv-prod /opt/venv /opt/venv
RUN python /usr/local/lib/cyberlab/finalize_image.py --target prod \
    && echo /srv/workers/disk > "$(python -c 'import site; print(site.getsitepackages()[0])')/cyberlab_disk.pth"
COPY disk_worker ./disk_worker
CMD ["celery", "-A", "disk_worker.celery_app", "worker", "--concurrency", "1", \
     "--max-tasks-per-child", "1", "--without-gossip", "--without-mingle", \
     "--without-heartbeat", "--loglevel", "INFO"]
