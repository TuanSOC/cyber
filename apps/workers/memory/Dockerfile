# syntax=docker/dockerfile:1
# Memory forensics analyzer (M8): runs an allow-listed set of Volatility 3 triage plugins over an
# attacker-controlled memory image, fully offline, one sandboxed process per plugin. The Celery
# process (root, few capabilities, see docker-compose.yml) never parses image bytes; every
# Volatility call runs as the unprivileged `tool` user (uid 10006: its own uid, not the
# analyzers' 10003, whose RLIMIT_NPROC count it would share, RT18; the worker kit reads
# CYBERLAB_TOOL_UID / CYBERLAB_TOOL_GID) under seccomp (AF_UNIX only, no io_uring, RT7).
# The same image runs the trusted `memory-symbols` operator tool as uid 10005 (`symbols`).
#
# Volatility 3 is redistributed unmodified under the Volatility Software License (VSL) v1.0:
# the wheel's LICENSE.txt is kept at /usr/share/doc/volatility3/ and our NOTICE (the adapter in
# memory_worker/ is an "Addition"; NOTICE.md) at /usr/share/doc/cyberlab-memory/NOTICE.
# Nothing in volatility3 is removed or patched; the image ships no symbol tables (they come
# from the read-only `memory_symbols` volume, written only by memory-symbols).
#
# Build from the repo root:
#   docker build --build-context jobs=packages/py-jobs \
#     --build-context worker_kit=packages/py-worker-kit \
#     -t cyberlab/memory-worker:dev --target dev apps/workers/memory

ARG PYTHON_IMAGE=python:3.12-slim-trixie

FROM ${PYTHON_IMAGE} AS base
# libsnappy1v5: AVML images (snappy-compressed pages); xz-utils: ISF .json.xz tables.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       libmagic1 libseccomp2 xz-utils ca-certificates libsnappy1v5 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:0.9.30 /uv /bin/
RUN groupadd --system --gid 10006 tool \
    && useradd --system --uid 10006 --gid 10006 --no-create-home --shell /usr/sbin/nologin tool \
    && groupadd --system --gid 10005 symbols \
    && useradd --system --uid 10005 --gid 10005 --no-create-home --shell /usr/sbin/nologin symbols
# HOME / XDG_CONFIG_HOME point nowhere: no `vol.json` or user config can ever apply. The probe
# gets a fresh XDG_CACHE_HOME per plugin (phase 2); MEMORY_SYMBOLS_DIR is the read-only store.
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
    CYBERLAB_TOOL_UID=10006 \
    CYBERLAB_TOOL_GID=10006 \
    MEMORY_SYMBOLS_DIR=/symbols \
    MEMORY_ENGINE=volatility3
WORKDIR /srv/workers/memory
COPY --from=jobs . /packages/py-jobs
COPY --from=worker_kit . /packages/py-worker-kit
COPY pyproject.toml uv.lock ./
COPY docker/finalize_image.py /usr/local/lib/cyberlab/finalize_image.py
COPY NOTICE.md /usr/share/doc/cyberlab-memory/NOTICE

# --- virtualenvs (every dependency ships a manylinux wheel: no toolchain needed) ------------
FROM base AS venv-dev
RUN uv sync --no-install-project

FROM base AS venv-prod
RUN uv sync --no-install-project --no-dev

# --- dev / test image ----------------------------------------------------------------------
# Probes run as `python -I -s -m memory_worker.probe` (isolated mode ignores PYTHONPATH and the
# cwd), so the package dir reaches the venv through a root-owned .pth file.
FROM base AS dev
COPY --from=venv-dev /opt/venv /opt/venv
RUN python /usr/local/lib/cyberlab/finalize_image.py \
    && echo /srv/workers/memory > "$(python -c 'import site; print(site.getsitepackages()[0])')/cyberlab_memory.pth"
COPY memory_worker ./memory_worker
COPY tests ./tests
COPY samples ./samples
COPY dataset ./dataset
CMD ["celery", "-A", "memory_worker.celery_app", "worker", "--concurrency", "1", \
     "--max-tasks-per-child", "1", "--without-gossip", "--without-mingle", \
     "--without-heartbeat", "--loglevel", "INFO"]

# --- production image ----------------------------------------------------------------------
FROM base AS prod
COPY --from=venv-prod /opt/venv /opt/venv
RUN python /usr/local/lib/cyberlab/finalize_image.py \
    && echo /srv/workers/memory > "$(python -c 'import site; print(site.getsitepackages()[0])')/cyberlab_memory.pth"
COPY memory_worker ./memory_worker
CMD ["celery", "-A", "memory_worker.celery_app", "worker", "--concurrency", "1", \
     "--max-tasks-per-child", "1", "--without-gossip", "--without-mingle", \
     "--without-heartbeat", "--loglevel", "INFO"]
