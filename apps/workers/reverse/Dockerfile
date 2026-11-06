# syntax=docker/dockerfile:1
# Reverse-engineering analyzer (M10): Ghidra 12.2 headless driven by PyGhidra 3.2 in library
# mode (JDK 25), and radare2 6.2.6 for the optional `quick` profile, over an attacker-
# controlled PE / ELF sample, fully offline, one sandboxed process per stage. The sample is
# never executed (no debugger, no emulator, no ESIL). The Celery process (root, few
# capabilities, see docker-compose.yml) never parses sample bytes beyond the magic check;
# every JVM and radare2 run is the unprivileged `tool` user (uid 10010: its own uid, RLIMIT_NPROC
# is per uid; the worker kit reads CYBERLAB_TOOL_UID / GID) under seccomp (AF_UNIX only, no
# io_uring), rlimits and the container cgroup.
#
# Artefacts are pinned (supply chain): the JDK by image digest, the Ghidra zip and the radare2
# deb by SHA-256 constants (a mismatch fails the build). The values below were read from the
# GitHub release API and Docker Hub on 2026-11-07 and MUST be re-checked against the release
# pages at the first build (M10 phase 1, "Docker steps pending").
#
# Ghidra is trimmed by DELETION ONLY (docker/trim-ghidra.sh; every LICENSE* and licenses/ kept
# and copied to /usr/share/doc/cyberlab-re/): processors other than x86 and DATA, Jython, the
# debugger, Ghidra Server, the docs and the bundled extensions. Its support/launch.properties is
# replaced by our reviewed copy (docker/launch.properties, RT1): the JVM arguments are exactly
# ours. The trim list and the JVM values are PROVISIONAL until the phase-2 spike reports.
#
# Licenses: Ghidra Apache-2.0 (its GPL native helpers keep their texts), the JDK GPLv2 +
# Classpath Exception, PyGhidra Apache-2.0, JPype Apache-2.0, radare2 LGPL-3.0 (a separate
# process): texts and NOTICE in /usr/share/doc/cyberlab-re/ (finalize_image.py).
#
# Build from the repo root (static_samples_c: the M3 C sources, dev target only, never copied
# into the repo tree of this worker):
#   docker build --build-context jobs=packages/py-jobs \
#     --build-context worker_kit=packages/py-worker-kit \
#     --build-context static_samples_c=apps/workers/static/samples/c \
#     -t cyberlab/re-worker:dev --target dev apps/workers/reverse

ARG PYTHON_IMAGE=python:3.12-slim-trixie
ARG TEMURIN_IMAGE=eclipse-temurin:25-jdk-noble@sha256:95e350ad1eb738f943e141640f7e3d797e483359a3b33c3864255bfd1ad71f8a

# --- JDK 25 (digest-pinned; JRE if the spike proves it enough) -------------------------------
FROM ${TEMURIN_IMAGE} AS jdk

# --- downloads: Ghidra zip and radare2 deb, SHA-256-verified; Ghidra trimmed ---------------
FROM ${PYTHON_IMAGE} AS fetch
ARG GHIDRA_VERSION=12.2
ARG GHIDRA_ZIP=ghidra_12.2_PUBLIC_20261016.zip
ARG GHIDRA_SHA256=2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67
ARG R2_VERSION=6.2.6
ARG R2_DEB=radare2_6.2.6_amd64.deb
ARG R2_SHA256=0dddf90e217e38a6a658881b9ec7e217198487c75b7f82a332b3cbd30834636f
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL --proto '=https' --tlsv1.2 -o /tmp/ghidra.zip \
       "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_ZIP}" \
    && echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c - \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra \
    && rm /tmp/ghidra.zip
RUN curl -fsSL --proto '=https' --tlsv1.2 -o "/tmp/${R2_DEB}" \
       "https://github.com/radareorg/radare2/releases/download/${R2_VERSION}/${R2_DEB}" \
    && echo "${R2_SHA256}  /tmp/${R2_DEB}" | sha256sum -c - \
    && mkdir -p /debs && mv "/tmp/${R2_DEB}" /debs/
COPY docker/trim-ghidra.sh /usr/local/bin/trim-ghidra.sh
COPY docker/launch.properties /tmp/launch.properties
RUN sh /usr/local/bin/trim-ghidra.sh /opt/ghidra /licenses \
    && cp /tmp/launch.properties /opt/ghidra/support/launch.properties \
    && printf '{"ghidra_zip_sha256": "%s", "radare2_deb_sha256": "%s", "jdk_image": "%s"}\n' \
       "${GHIDRA_SHA256}" "${R2_SHA256}" "eclipse-temurin:25-jdk-noble" > /artifacts.json

# --- common runtime --------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS base
# libmagic1: the root magic check; libseccomp2: the kit's filters; procps: `prlimit` for the
# decompiler child (RT4). radare2's runtime dependencies come from Debian (`apt-get install`
# of the local, hash-checked deb resolves them).
COPY --from=fetch /debs /tmp/debs
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       libmagic1 libseccomp2 ca-certificates util-linux procps \
       /tmp/debs/radare2_*_amd64.deb \
    && rm -rf /var/lib/apt/lists/* /tmp/debs
COPY --from=ghcr.io/astral-sh/uv:0.9.30 /uv /bin/
COPY --from=jdk /opt/java/openjdk /opt/java/openjdk
COPY --from=fetch /opt/ghidra /opt/ghidra
COPY --from=fetch /licenses /usr/share/doc/cyberlab-re/licenses
COPY --from=fetch /artifacts.json /usr/local/lib/cyberlab/artifacts.json
RUN groupadd --system --gid 10010 tool \
    && useradd --system --uid 10010 --gid 10010 --no-create-home --shell /usr/sbin/nologin tool
# HOME / XDG_* point nowhere: no user config of Ghidra, the JDK or radare2 can ever apply. The
# probe gives every stage fresh `home`, `tmp` and XDG dirs inside its out dir (phase 2).
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
    JAVA_HOME=/opt/java/openjdk \
    GHIDRA_INSTALL_DIR=/opt/ghidra \
    MALLOC_ARENA_MAX=2 \
    CYBERLAB_TOOL_UID=10010 \
    CYBERLAB_TOOL_GID=10010 \
    RE_ENGINE=ghidra
WORKDIR /srv/workers/reverse
COPY --from=jobs . /packages/py-jobs
COPY --from=worker_kit . /packages/py-worker-kit
COPY pyproject.toml uv.lock ./
COPY docker/finalize_image.py /usr/local/lib/cyberlab/finalize_image.py
COPY docker/launch.properties /usr/local/lib/cyberlab/launch.properties
COPY NOTICE.md /usr/share/doc/cyberlab-re/NOTICE
# The fixed radare2 command script (RT9: one non-interactive run, no r2pipe), root-owned 0444.
COPY --chmod=0444 r2/quick.r2 /opt/re/r2/quick.r2

# --- virtualenvs (JPype1 ships manylinux wheels: no toolchain needed). PyGhidra comes from the
# wheel bundled in the verified Ghidra zip, never from an index (--no-deps --no-index).
FROM base AS venv-dev
RUN uv sync --no-install-project \
    && uv pip install --no-deps --no-index \
       /opt/ghidra/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-*.whl

FROM base AS venv-prod
RUN uv sync --no-install-project --no-dev \
    && uv pip install --no-deps --no-index \
       /opt/ghidra/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-*.whl

# --- dev / test image ----------------------------------------------------------------------
# Probes run as `python -I -s -m re_worker.probe <stage>` (isolated mode ignores PYTHONPATH
# and the cwd), so the package dir reaches the venv through a root-owned .pth file. The dev
# target adds the compilers of the phase-4 synthetic samples (compiled at test time, never
# run) and the M3 C sources (read-only, never copied into this worker's tree).
FROM base AS dev
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       gcc libc6-dev gcc-mingw-w64-x86-64 gcc-mingw-w64-i686 binutils \
    && rm -rf /var/lib/apt/lists/*
COPY --from=venv-dev /opt/venv /opt/venv
COPY --from=static_samples_c . /opt/samples/m3c
RUN python /usr/local/lib/cyberlab/finalize_image.py --target dev \
    && echo /srv/workers/reverse > "$(python -c 'import site; print(site.getsitepackages()[0])')/cyberlab_reverse.pth"
COPY re_worker ./re_worker
COPY tests ./tests
COPY samples ./samples
COPY dataset ./dataset
CMD ["celery", "-A", "re_worker.celery_app", "worker", "--concurrency", "1", \
     "--max-tasks-per-child", "1", "--without-gossip", "--without-mingle", \
     "--without-heartbeat", "--loglevel", "INFO"]

# --- production image ----------------------------------------------------------------------
FROM base AS prod
COPY --from=venv-prod /opt/venv /opt/venv
RUN python /usr/local/lib/cyberlab/finalize_image.py --target prod \
    && echo /srv/workers/reverse > "$(python -c 'import site; print(site.getsitepackages()[0])')/cyberlab_reverse.pth"
COPY re_worker ./re_worker
CMD ["celery", "-A", "re_worker.celery_app", "worker", "--concurrency", "1", \
     "--max-tasks-per-child", "1", "--without-gossip", "--without-mingle", \
     "--without-heartbeat", "--loglevel", "INFO"]
