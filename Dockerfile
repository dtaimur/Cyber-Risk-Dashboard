# syntax=docker/dockerfile:1
# ---- Stage 1: build the React frontend -------------------------------------
FROM node:22-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- Stage 2: runtime (API + static frontend in one process) ---------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DASHBOARD_DATA_DIR=/data \
    DASHBOARD_STATIC_DIR=/app/static \
    DASHBOARD_SECURE_COOKIES=1 \
    PORT=8000

WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY backend/app ./app
COPY --from=web /web/dist ./static

# Run as an unprivileged user; only /data (database, key, credentials) is writable
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin dashboard \
    && mkdir -p /data && chown dashboard:dashboard /data
USER dashboard
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8000\")}/api/health', timeout=4)"

# --proxy-headers: trust X-Forwarded-* from the cloud load balancer (real client IP in audit log)
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*'"]
