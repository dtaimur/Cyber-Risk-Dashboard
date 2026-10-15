"""Cyber Risk Dashboard API."""
import logging
import os
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from . import auth, integrations, remediation, seed, threat_intel
from .db import get_conn, init_db
from .routers import alerts, assistant_api, auth_api, compliance, dashboard, metrics_api, remediation_api, settings, threats

# In the container the built React app is served by this same process.
STATIC_DIR = Path(os.environ["DASHBOARD_STATIC_DIR"]) if os.environ.get("DASHBOARD_STATIC_DIR") else None
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

log = logging.getLogger("cyber_risk_dashboard")


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    first_run = seed.seed()
    integrations.ensure_rows()
    auth.ensure_users()
    remediation.seed_tickets()
    if os.environ.get("DASHBOARD_OFFLINE") != "1":
        threading.Thread(target=bootstrap_threat_intel, args=(first_run,), daemon=True).start()
    yield


app = FastAPI(title="Cyber Risk Dashboard API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("DASHBOARD_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(","),
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "X-Requested-With"],
    allow_credentials=True,
)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # CSRF defence in depth (on top of SameSite=Strict cookies): state-changing API
    # calls must carry a custom header, which browsers will not attach cross-site
    # without a CORS preflight that our allow-list rejects.
    if request.url.path.startswith("/api/") and request.method not in SAFE_METHODS \
            and request.headers.get("x-requested-with") != "XMLHttpRequest":
        return JSONResponse({"detail": "Missing anti-CSRF header"}, status_code=403)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = CSP
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if auth.cookie_secure():
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


for r in (auth_api.router, dashboard.router, threats.router, alerts.router, compliance.router, settings.router, metrics_api.router, remediation_api.router, assistant_api.router):
    app.include_router(r)


def bootstrap_threat_intel(first_run: bool):
    """Pull live feeds in the background so startup isn't blocked by the network."""
    results = threat_intel.refresh()
    log.info("Threat feed refresh: %s", {k: v.get("ok") for k, v in results.items()})
    if first_run and results.get("cisa_kev", {}).get("ok"):
        added = seed.inject_recent_kev()
        threat_intel.enrich_cvss(added)
        threat_intel.refresh(["epss"])
        log.info("Simulated exposure to recent KEV CVEs: %s", added)


@app.get("/api/health")
def health():
    """Unauthenticated liveness probe for the container platform; reveals nothing about the data."""
    with get_conn() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok"}


if STATIC_DIR:
    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        """Serve built frontend files; unknown paths fall back to index.html (client-side routing)."""
        if path.startswith("api/"):
            return JSONResponse({"detail": "Not found"}, status_code=404)
        target = (STATIC_DIR / path).resolve()
        if path and target.is_file() and STATIC_DIR.resolve() in target.parents:  # blocks ../ traversal
            return FileResponse(target)
        return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-cache"})
