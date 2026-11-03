FROM python:3.12-slim AS base
COPY --from=ghcr.io/astral-sh/uv:0.9.30 /uv /uvx /bin/
RUN apt-get update \
    && apt-get install -y --no-install-recommends libmagic1 \
    && rm -rf /var/lib/apt/lists/*
# Virtualenv lives outside /app so the dev bind mount never hides it.
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_FROZEN=1 \
    PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1
# Fixed UID so dev and prod seed the upload_tmp volume with the same owner.
RUN useradd --system --uid 10001 --no-create-home cyberlab \
    && mkdir -p /var/lib/cyberlab/upload-tmp \
    && chown 10001:10001 /var/lib/cyberlab/upload-tmp
WORKDIR /app
COPY pyproject.toml uv.lock ./

FROM base AS dev
RUN uv sync --no-install-project
ENV WATCHFILES_FORCE_POLLING=true
CMD ["uvicorn", "app.main:app", "--reload", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips=*"]

FROM base AS prod
RUN uv sync --no-install-project --no-dev
COPY alembic.ini ./
COPY alembic ./alembic
COPY app ./app
USER cyberlab
# Only the gateway shares the api's network (see docker-compose.yml), so trusting
# forwarded headers from any peer is safe.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips=*"]
