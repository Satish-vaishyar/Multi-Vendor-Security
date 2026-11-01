# ---- builder: compilers live here only (hdbscan / scipy wheels); nothing from this stage but the virtualenv ships ----
FROM python:3.12-slim AS builder
ENV PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 UV_LINK_MODE=copy
WORKDIR /srv/app
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
# ---- python deps (locked, via uv) ----
COPY backend/pyproject.toml backend/uv.lock* ./
# Reproducible build: install EXACTLY the locked set and fail loudly otherwise
# (the previous `|| pip install -e .` fallback could silently ship different versions).
RUN pip install --upgrade pip uv \
    && uv sync --frozen --no-dev --no-install-project

# ---- runtime: no compiler, no pip/uv, code and virtualenv owned by root (read-only for the service user) ----
FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv/app
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 --shell /usr/sbin/nologin appuser
COPY --from=builder /srv/app/.venv /srv/app/.venv
ENV PATH="/srv/app/.venv/bin:$PATH"

COPY backend/app ./app
COPY okf /srv/okf
COPY models /srv/models
ENV OKF_DIR=/srv/okf MODELS_DIR=/srv/models ENV=production

USER appuser
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/health || exit 1
# --proxy-headers: trust X-Forwarded-For ONLY from the private ranges the nginx/ingress container lives in (port 8000 is not
# published). A wildcard here would let any caller choose the client address used for login throttling and the audit log.
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--proxy-headers", "--forwarded-allow-ips", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.1"]
