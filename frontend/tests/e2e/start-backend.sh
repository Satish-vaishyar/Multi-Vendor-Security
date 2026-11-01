#!/usr/bin/env bash
# Starts the QA backend on :8000 against the LOCAL test database. Not for production use.
# Usage: bash frontend/tests/e2e/start-backend.sh   (from the repo root)
set -e
cd "$(dirname "$0")/../../../backend"
PY=.venv/Scripts/python
[ -x "$PY" ] || PY=.venv/bin/python
export DATABASE_URL="${QA_DATABASE_URL:-postgresql://postgres:postgres@localhost:55432/auditor_test_c}"
export ENV=development REQUIRE_AUTH=true
export JWT_SECRET="${QA_JWT_SECRET:-$($PY -c 'import secrets;print(secrets.token_hex(32))')}"
export DATA_ENCRYPTION_KEYS="${QA_FERNET:-$($PY -c 'from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())')}"
export ADMIN_EMAIL="${QA_ADMIN_EMAIL:-qa-admin@example.com}"
export ADMIN_PASSWORD="${QA_ADMIN_PASSWORD:-QaAdmin-Passw0rd!2026}"
export PASSWORD_HASH_ITERATIONS=1000 EMBEDDED_WORKER=true
# many parallel specs log in from one IP: relax the per-IP throttle for the test stack only
export LOGIN_IP_MAX_PER_MINUTE=2000
exec $PY -m uvicorn app.main:app --port 8000
