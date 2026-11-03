# Cloud scanner image. Build context is the repository root (it needs cloud/ and okf-cloud/); the dedicated
# cloud/Dockerfile.dockerignore admits nothing else. Parses untrusted customer files, so it is deliberately minimal:
# locked dependencies only, no compiler/pip/uv in the runtime stage, non-root user, no shell login, no credentials.
FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30 AS builder
ENV PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 UV_LINK_MODE=copy
WORKDIR /srv/build
COPY cloud/pyproject.toml cloud/uv.lock ./
RUN pip install --upgrade pip uv \
    && uv sync --frozen --no-dev --no-install-project

FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30 AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/srv
WORKDIR /srv
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin scanner
COPY --from=builder /srv/build/.venv /srv/.venv
ENV PATH="/srv/.venv/bin:$PATH"
# Code and virtualenv stay root-owned and read-only for the service user.
COPY cloud /srv/cloud
COPY okf-cloud /srv/okf-cloud
USER 10001:10001
EXPOSE 8100
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8100/healthz', timeout=3).status == 200 else 1)"
CMD ["python", "-m", "uvicorn", "cloud.service:app", "--host", "0.0.0.0", "--port", "8100", "--workers", "1"]
