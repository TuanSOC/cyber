# PCAP analyzer: parses attacker-controlled captures.
# The Celery process (root, few capabilities, see docker-compose.yml) never parses capture
# bytes itself; every tool runs as the unprivileged `tool` user (uid 10003).
FROM zeek/zeek:8.0 AS base
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       tshark suricata suricata-update python3 ca-certificates libseccomp2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:0.9.30 /uv /bin/
RUN groupadd --system --gid 10003 tool \
    && useradd --system --uid 10003 --gid 10003 --no-create-home --shell /usr/sbin/nologin tool
# ET Open rules are fetched at build time only: the analysis network has no egress.
RUN suricata-update --no-test --no-reload \
    && mkdir -p /etc/cyberlab \
    && printf '{"zeek":"%s","tshark":"%s","suricata":"%s","rules_sha256":"%s"}\n' \
       "$(zeek --version | awk '{print $3}')" \
       "$(tshark --version | head -1 | awk '{print $3}' | sed 's/[.]$//')" \
       "$(suricata -V | awk '{print $5}')" \
       "$(sha256sum /var/lib/suricata/rules/suricata.rules | cut -d' ' -f1)" \
       > /etc/cyberlab/versions.json
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_FROZEN=1 \
    UV_PYTHON=/usr/bin/python3 \
    UV_PYTHON_DOWNLOADS=never \
    PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /srv/workers/pcap
COPY --from=jobs . /packages/py-jobs
COPY pyproject.toml uv.lock ./

FROM base AS dev
RUN uv sync --no-install-project
COPY pcap_worker ./pcap_worker
COPY tests ./tests
COPY dataset ./dataset
CMD ["celery", "-A", "pcap_worker.celery_app", "worker", "--concurrency", "1", \
     "--max-tasks-per-child", "1", "--without-gossip", "--without-mingle", \
     "--without-heartbeat", "--loglevel", "INFO"]

FROM base AS prod
RUN uv sync --no-install-project --no-dev
COPY pcap_worker ./pcap_worker
CMD ["celery", "-A", "pcap_worker.celery_app", "worker", "--concurrency", "1", \
     "--max-tasks-per-child", "1", "--without-gossip", "--without-mingle", \
     "--without-heartbeat", "--loglevel", "INFO"]
