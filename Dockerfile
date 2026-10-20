# syntax=docker/dockerfile:1
# Base image pinned by tag *and* digest so rebuilds are reproducible. Dependabot bumps both.
ARG PYTHON_IMAGE=python:3.12.15-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258

# ---- build stage: resolve wheels into an isolated venv ------------------------------------
FROM ${PYTHON_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.txt .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --only-binary=:all: -r requirements.txt \
 && /opt/venv/bin/pip uninstall -y pip \
 && find /opt/venv -name "__pycache__" -type d -prune -exec rm -rf {} +

# ---- runtime stage: no compilers, no pip in the venv, non-root -----------------------------
FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.title="FileForensics" \
      org.opencontainers.image.source="https://github.com/VRCHAMPION/Fileforensics-" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}"

RUN groupadd --system --gid 10001 forensics \
 && useradd --system --uid 10001 --gid forensics --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin forensics

WORKDIR /srv
COPY --from=build /opt/venv /opt/venv
COPY app ./app

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import sys, urllib.request as u; sys.exit(0 if u.urlopen('http://127.0.0.1:8000/api/health', timeout=2).status == 200 else 1)"]

# Nothing is written at runtime, so the container can run with --read-only.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--limit-concurrency", "64", "--timeout-keep-alive", "5"]
