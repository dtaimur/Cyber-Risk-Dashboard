"""Integration settings and the executive report endpoint."""
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, HttpUrl

from .. import integrations, remediation, report, threat_intel
from ..connectors import CONNECTORS
from ..connectors.base import ConnectorError, persist
from ..db import get_conn
from ..auth import require

router = APIRouter(prefix="/api")


class IntegrationUpdate(BaseModel):
    enabled: bool | None = None
    config: dict[str, str] | None = None
    secret: str | None = Field(None, max_length=512)


def _validate_config(integration_id, config):
    allowed = {f["key"] for f in CONNECTORS[integration_id].fields if not f["secret"]}
    unknown = set(config) - allowed
    if unknown:
        raise HTTPException(422, f"Unknown config keys: {sorted(unknown)}")
    for key, value in config.items():
        if len(value) > 300:
            raise HTTPException(422, f"{key} is too long")
        if "url" in key and value:
            try:
                url = str(HttpUrl(value))
            except ValueError:
                raise HTTPException(422, f"{key} is not a valid URL")
            if not url.startswith("https://"):
                raise HTTPException(422, f"{key} must use https")  # credentials are never sent over plaintext HTTP


@router.get("/integrations", dependencies=[Depends(require("manage_integrations"))])
def list_integrations():
    return integrations.public_view()


@router.put("/integrations/{integration_id}")
def update_integration(integration_id: str, body: IntegrationUpdate, user=Depends(require("manage_integrations"))):
    if integration_id not in {d["id"] for d in integrations.definitions()}:
        raise HTTPException(404, "Unknown integration")
    if body.config is not None:
        if integration_id not in CONNECTORS:
            raise HTTPException(422, "This integration has no configurable settings")
        _validate_config(integration_id, body.config)
    integrations.update(integration_id, body.enabled, body.config, body.secret, actor=user["username"])
    return next(i for i in integrations.public_view() if i["id"] == integration_id)


@router.post("/integrations/{integration_id}/test", dependencies=[Depends(require("manage_integrations"))])
def test_integration(integration_id: str):
    if integration_id not in CONNECTORS:
        if integration_id in integrations.FEEDS:
            return {"ok": all(r["ok"] for r in threat_intel.refresh([integration_id]).values()), "message": "Feed fetched"}
        raise HTTPException(404, "Unknown integration")
    cfg, secret = integrations.credentials(integration_id)
    if not secret:
        return {"ok": False, "message": "No credential saved yet"}
    try:
        return {"ok": True, "message": CONNECTORS[integration_id].test(cfg, secret)}
    except ConnectorError as exc:
        return {"ok": False, "message": str(exc)}
    except Exception as exc:  # network / DNS / TLS errors
        return {"ok": False, "message": f"Connection failed: {type(exc).__name__}"}


@router.post("/integrations/{integration_id}/sync", dependencies=[Depends(require("manage_integrations"))])
def sync_integration(integration_id: str):
    if integration_id in integrations.FEEDS:
        return threat_intel.refresh([integration_id])[integration_id]
    if integration_id not in CONNECTORS:
        raise HTTPException(404, "Unknown integration")
    cfg, secret = integrations.credentials(integration_id)
    if not secret:
        raise HTTPException(400, "Save credentials before syncing")
    if integration_id == "jira":
        try:
            n = remediation.sync_from_jira()
            integrations.set_status("jira", "ok", f"Synced {n} issues", n)
            return {"ok": True, "count": n}
        except Exception as exc:
            msg = str(exc) if isinstance(exc, ConnectorError) else f"Sync failed: {type(exc).__name__}"
            integrations.set_status("jira", "error", msg, None)
            return {"ok": False, "error": msg}
    try:
        result = CONNECTORS[integration_id].sync(cfg, secret)
        persist(integration_id, result)
        integrations.set_status(integration_id, "ok", f"Synced {result.total} records", result.total)
        return {"ok": True, "count": result.total}
    except Exception as exc:
        msg = str(exc) if isinstance(exc, ConnectorError) else f"Sync failed: {type(exc).__name__}"
        integrations.set_status(integration_id, "error", msg, None)
        return {"ok": False, "error": msg}


class ReportRequest(BaseModel):
    period_days: Literal[30, 90] = 30
    audience: Literal["board", "executive", "security"] = "executive"


@router.post("/report", dependencies=[Depends(require("generate_report"))])
def generate_report(req: ReportRequest):
    with get_conn() as conn:
        threats = threat_intel.active_threats(conn)
        return report.generate(conn, threats, req.period_days, req.audience)


@router.post("/report/markdown", response_class=PlainTextResponse, dependencies=[Depends(require("generate_report"))])
def report_markdown(req: ReportRequest):
    return report.to_markdown(generate_report(req))
