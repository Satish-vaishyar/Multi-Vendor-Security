# ---- backend base ----
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv/app

# torch CPU only (keeps image small); runtime deps for hdbscan/scipy
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libgomp1 curl \
    && rm -rf /var/lib/apt/lists/*

# ---- python deps (uv is faster, pip fallback) ----
COPY backend/pyproject.toml backend/uv.lock* ./
RUN pip install --upgrade pip uv 2>/dev/null || pip install --upgrade pip; \
    if [ -f uv.lock ]; then uv sync --frozen --no-dev 2>/dev/null || pip install -e .; else pip install -e .; fi

COPY backend/app ./app
COPY okf /srv/okf
COPY models /srv/models
ENV OKF_DIR=/srv/okf MODELS_DIR=/srv/models ENV=production

RUN useradd -m appuser && chown -R appuser /srv/app
USER appuser
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/health || exit 1
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
