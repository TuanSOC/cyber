# syntax=docker/dockerfile:1
# Report renderer (M6): renders a signed report snapshot (attacker-controlled text) to
# PDF/A-3a, HTML and Markdown. The Celery process (root, few capabilities, see
# docker-compose.yml) never renders itself; the renderer runs as the unprivileged `tool` user
# (uid 10003) in a sandboxed subprocess (phase 4).
#
# No Ghostscript in the image (RT16: EPS images reached Ghostscript through Pillow before
# WeasyPrint 70); a build step fails if `gs` is present. Fontconfig lists only the bundled
# Noto fonts and its cache is built here (the runtime rootfs is read-only).
#
# Build from the repo root:
#   docker build --build-context jobs=packages/py-jobs \
#     --build-context worker_kit=packages/py-worker-kit \
#     -t cyberlab/report-worker:dev --target dev apps/workers/report

ARG PYTHON_IMAGE=python:3.12-slim-trixie

FROM ${PYTHON_IMAGE} AS base
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 libseccomp2 fontconfig \
       fonts-noto-core fonts-noto-mono ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && if command -v gs >/dev/null 2>&1; then echo "ghostscript must not be installed" >&2; exit 1; fi
COPY --from=ghcr.io/astral-sh/uv:0.9.30 /uv /bin/
RUN groupadd --system --gid 10003 tool \
    && useradd --system --uid 10003 --gid 10003 --no-create-home --shell /usr/sbin/nologin tool
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
    FONTCONFIG_FILE=/app/assets/fonts.conf
WORKDIR /srv/workers/report
COPY --from=jobs . /packages/py-jobs
COPY --from=worker_kit . /packages/py-worker-kit
COPY pyproject.toml uv.lock ./
COPY assets /app/assets
# The font cache for exactly the bundled fonts, read-only at runtime.
RUN mkdir -p /var/cache/fontconfig \
    && fc-cache -f \
    && chmod -R a+rX,go-w /var/cache/fontconfig /app/assets

FROM base AS venv-dev
RUN uv sync --no-install-project

FROM base AS venv-prod
RUN uv sync --no-install-project --no-dev

# --- dev / test image ----------------------------------------------------------------------
# The render subprocess runs `python -I -B -m report_worker.render` (isolated mode ignores
# PYTHONPATH and the cwd), so the package dir reaches the venv through a root-owned .pth file.
FROM base AS dev
COPY --from=venv-dev /opt/venv /opt/venv
RUN echo /srv/workers/report > "$(python -c 'import site; print(site.getsitepackages()[0])')/cyberlab_report.pth"
COPY report_worker ./report_worker
COPY tests ./tests
CMD ["celery", "-A", "report_worker.app", "worker", "--concurrency", "1", \
     "--max-tasks-per-child", "1", "--without-gossip", "--without-mingle", \
     "--without-heartbeat", "--loglevel", "INFO"]

# --- production image ----------------------------------------------------------------------
FROM base AS prod
COPY --from=venv-prod /opt/venv /opt/venv
RUN echo /srv/workers/report > "$(python -c 'import site; print(site.getsitepackages()[0])')/cyberlab_report.pth"
COPY report_worker ./report_worker
CMD ["celery", "-A", "report_worker.app", "worker", "--concurrency", "1", \
     "--max-tasks-per-child", "1", "--without-gossip", "--without-mingle", \
     "--without-heartbeat", "--loglevel", "INFO"]
