# syntax=docker/dockerfile:1
# Static malware analyzer: parses attacker-controlled PE/ELF samples. Nothing is ever executed.
# The Celery process (root, few capabilities, see docker-compose.yml) never parses sample
# bytes itself; every parser/engine runs as the unprivileged `tool` user (uid 10003).
#
# Build from the repo root:
#   docker build --build-context jobs=packages/py-jobs \
#     --build-context worker_kit=packages/py-worker-kit \
#     -t cyberlab/static-worker:dev --target dev apps/workers/static

ARG PYTHON_IMAGE=python:3.12-slim-trixie

# --- ClamAV signature DB (early, separately cached stage) ---------------------------------
# freshclam is rate-limited by the ClamAV CDN (HTTP 429); keeping it in its own stage means a
# code change never re-downloads the DB. Bump CLAMAV_DB_REFRESH to force a refresh.
# Without network the build still succeeds with an empty DB dir and versions.json records
# clamav_db = "unavailable" (clamscan then refuses to scan: the worker must report an engine
# error, never "clean").
FROM ${PYTHON_IMAGE} AS clamav-db
ARG CLAMAV_DB_REFRESH=2026-11-04
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       clamav-freshclam ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN echo "db refresh ${CLAMAV_DB_REFRESH}" \
    && mkdir -p /var/lib/clamav /var/log/clamav \
    && chown clamav:clamav /var/lib/clamav /var/log/clamav \
    && (freshclam --stdout --foreground --no-warnings \
        || echo "WARNING: freshclam failed; image ships without a ClamAV DB") \
    && ls -la /var/lib/clamav

# --- capa rules + FLIRT signatures (pinned tag, sha256 verified) --------------------------
FROM ${PYTHON_IMAGE} AS capa-assets
COPY docker/fetch_capa_assets.py /tmp/fetch_capa_assets.py
RUN python /tmp/fetch_capa_assets.py

# --- shared runtime base -------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS base
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       clamav libmagic1 libseccomp2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:0.9.30 /uv /bin/
RUN groupadd --system --gid 10003 tool \
    && useradd --system --uid 10003 --gid 10003 --no-create-home --shell /usr/sbin/nologin tool
COPY --from=clamav-db /var/lib/clamav /var/lib/clamav
COPY --from=capa-assets /opt/capa /opt/capa
# capa uses $XDG_CACHE_HOME itself (no /capa suffix) as its rule-cache dir; the cache is
# precomputed at build (finalize_image.py) so capa only reads it on the read-only rootfs.
# Probes run as `python -I -m static_worker.probe` (isolated mode ignores PYTHONPATH and the
# cwd), so the dev/prod stages add /srv/workers/static to the venv via a root-owned .pth file.
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
    XDG_CACHE_HOME=/opt/capa/cache \
    CAPA_RULES=/opt/capa/rules \
    CAPA_SIGS=/opt/capa/sigs \
    YARA_RULES=/opt/yara/rules
WORKDIR /srv/workers/static
COPY --from=jobs . /packages/py-jobs
COPY --from=worker_kit . /packages/py-worker-kit
COPY pyproject.toml uv.lock ./
COPY docker/finalize_image.py /usr/local/lib/cyberlab/finalize_image.py

# --- virtualenvs (built with a C++ toolchain that never reaches the final images) ----------
# flare-floss depends on binary2strings, which ships no Linux wheel (pybind11 sdist).
FROM base AS venv-builder
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends g++ \
    && rm -rf /var/lib/apt/lists/*

FROM venv-builder AS venv-dev
RUN uv sync --no-install-project

FROM venv-builder AS venv-prod
RUN uv sync --no-install-project --no-dev

# --- dev / test image ----------------------------------------------------------------------
# mingw cross-compilers build benign C samples for tests (never executed). Not in prod.
FROM base AS dev
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       gcc-mingw-w64-x86-64 gcc-mingw-w64-i686 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=venv-dev /opt/venv /opt/venv
RUN python /usr/local/lib/cyberlab/finalize_image.py \
    && echo /srv/workers/static > "$(python -c 'import site; print(site.getsitepackages()[0])')/cyberlab_static.pth"
# Rules last: editing a rule never rebuilds the virtualenvs.
COPY rules/yara /opt/yara/rules
COPY static_worker ./static_worker
COPY tests ./tests
COPY samples ./samples
CMD ["celery", "-A", "static_worker.celery_app", "worker", "--concurrency", "1", \
     "--max-tasks-per-child", "1", "--without-gossip", "--without-mingle", \
     "--without-heartbeat", "--loglevel", "INFO"]

# --- production image ----------------------------------------------------------------------
FROM base AS prod
COPY --from=venv-prod /opt/venv /opt/venv
RUN python /usr/local/lib/cyberlab/finalize_image.py \
    && echo /srv/workers/static > "$(python -c 'import site; print(site.getsitepackages()[0])')/cyberlab_static.pth"
COPY rules/yara /opt/yara/rules
COPY static_worker ./static_worker
CMD ["celery", "-A", "static_worker.celery_app", "worker", "--concurrency", "1", \
     "--max-tasks-per-child", "1", "--without-gossip", "--without-mingle", \
     "--without-heartbeat", "--loglevel", "INFO"]
