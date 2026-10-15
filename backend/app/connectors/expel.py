"""Expel Workbench connector (MDR). Uses the JSON:API v2 endpoints with an API key."""
from .base import Connector, ConnectorError, SyncResult, normalize_sev


class ExpelConnector(Connector):
    id = "expel"
    name = "Expel MDR"
    description = "Managed detection & response: triaged alerts, investigations, and incidents."
    docs_url = "https://workbench.expel.io/api/v2/docs"
    fields = [
        {"key": "base_url", "label": "Workbench URL", "secret": False, "placeholder": "https://workbench.expel.io"},
        {"key": "secret", "label": "API key", "secret": True, "placeholder": "Workbench API key"},
    ]

    def _client(self, cfg, secret):
        base = (cfg.get("base_url") or "https://workbench.expel.io").rstrip("/")
        return self.client(base_url=base, headers={"Authorization": f"Bearer {secret}", "Accept": "application/vnd.api+json"})

    def test(self, cfg, secret):
        with self._client(cfg, secret) as c:
            r = c.get("/api/v2/expel_alerts", params={"page[limit]": 1})
            if r.status_code in (401, 403):
                raise ConnectorError(f"Authentication failed (HTTP {r.status_code})")
            r.raise_for_status()
        return "Authenticated to Expel Workbench."

    def sync(self, cfg, secret):
        out = SyncResult()
        with self._client(cfg, secret) as c:
            alerts = c.get("/api/v2/expel_alerts", params={"page[limit]": 500, "sort": "-created_at"}).raise_for_status().json()
            for a in alerts.get("data", []):
                at = a.get("attributes", {})
                sev = normalize_sev(at.get("expel_severity"), "low")
                closed = at.get("status") == "CLOSED"
                out.alerts.append({
                    "external_id": a.get("id"), "title": at.get("expel_name"), "severity": sev,
                    "status": ("false_positive" if at.get("close_reason") == "FALSE_POSITIVE" else "resolved") if closed else "investigating",
                    "category": (at.get("alert_type") or "mdr").lower(), "tactic": None, "technique": None,
                    "occurred_at": at.get("expel_alert_time"), "detected_at": at.get("created_at"),
                    "resolved_at": at.get("updated_at") if closed else None,
                })
            invs = c.get("/api/v2/investigations", params={"page[limit]": 200, "filter[is_incident]": "true"}).raise_for_status().json()
            for inv in invs.get("data", []):
                at = inv.get("attributes", {})
                out.alerts.append({
                    "external_id": inv.get("id"), "title": at.get("title"), "severity": normalize_sev(at.get("analyst_severity"), "high"),
                    "status": "resolved" if at.get("close_comment") else "investigating", "category": "incident",
                    "occurred_at": at.get("created_at"), "detected_at": at.get("created_at"), "is_incident": 1,
                })
        return out
