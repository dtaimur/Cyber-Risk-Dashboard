"""CrowdStrike Falcon connector (OAuth2 client credentials).

Pulls host/sensor inventory, Falcon Spotlight vulnerabilities, and detections
(Alerts API v2). Required API scopes: Hosts:Read, Vulnerabilities:Read, Alerts:Read.
"""
from .base import Connector, ConnectorError, SyncResult, normalize_sev, sev_from_score


class CrowdStrikeConnector(Connector):
    id = "crowdstrike"
    name = "CrowdStrike Falcon"
    description = "EDR sensor coverage, Spotlight vulnerabilities, and endpoint detections."
    docs_url = "https://falcon.crowdstrike.com/documentation"
    fields = [
        {"key": "base_url", "label": "API base URL", "secret": False, "placeholder": "https://api.crowdstrike.com"},
        {"key": "client_id", "label": "Client ID", "secret": False, "placeholder": "OAuth2 client ID"},
        {"key": "secret", "label": "Client secret", "secret": True, "placeholder": "OAuth2 client secret"},
    ]

    def _session(self, cfg, secret):
        base = (cfg.get("base_url") or "https://api.crowdstrike.com").rstrip("/")
        c = self.client(base_url=base)
        r = c.post("/oauth2/token", data={"client_id": cfg.get("client_id", ""), "client_secret": secret})
        if r.status_code != 201:
            raise ConnectorError(f"Authentication failed (HTTP {r.status_code})")
        c.headers["Authorization"] = f"Bearer {r.json()['access_token']}"
        return c

    def test(self, cfg, secret):
        with self._session(cfg, secret) as c:
            total = c.get("/devices/queries/devices/v1", params={"limit": 1}).raise_for_status().json()["meta"]["pagination"]["total"]
        return f"Authenticated. {total} hosts visible."

    def sync(self, cfg, secret):
        out = SyncResult()
        with self._session(cfg, secret) as c:
            ids = c.get("/devices/queries/devices/v1", params={"limit": 500}).raise_for_status().json()["resources"]
            if ids:
                for h in c.post("/devices/entities/devices/v2", json={"ids": ids}).raise_for_status().json()["resources"]:
                    out.assets.append({
                        "hostname": h.get("hostname"), "ip": h.get("local_ip"), "os": h.get("os_version"),
                        "sensor_version": h.get("agent_version"),
                        "edr_status": "rfm" if h.get("reduced_functionality_mode") == "yes" else "normal",
                        "contained": int(h.get("status") == "contained"),
                    })

            vulns = c.get("/spotlight/combined/vulnerabilities/v1", params={
                "filter": "status:['open','reopen']", "limit": 400, "facet": ["cve", "host_info"]}).raise_for_status().json()
            for v in vulns.get("resources", []):
                cve = v.get("cve", {})
                score = cve.get("base_score") or 0
                out.findings.append({
                    "hostname": v.get("host_info", {}).get("hostname"), "external_id": v.get("id"), "cve": cve.get("id"),
                    "title": cve.get("description", "")[:200] or cve.get("id"), "severity": normalize_sev(cve.get("severity"), sev_from_score(score)),
                    "cvss": score, "vendor_score": cve.get("exprt_rating") and {"CRITICAL": 95, "HIGH": 75, "MEDIUM": 50, "LOW": 20}.get(cve["exprt_rating"]),
                    "status": "open", "first_seen": (v.get("created_timestamp") or "")[:10], "due_date": None,
                })

            alert_ids = c.get("/alerts/queries/alerts/v2", params={"filter": "created_timestamp:>'now-30d'", "limit": 500}).raise_for_status().json()["resources"]
            if alert_ids:
                for a in c.post("/alerts/entities/alerts/v2", json={"composite_ids": alert_ids}).raise_for_status().json()["resources"]:
                    status = {"closed": "resolved", "in_progress": "investigating"}.get(a.get("status"), "new")
                    out.alerts.append({
                        "hostname": a.get("device", {}).get("hostname"), "external_id": a.get("composite_id"),
                        "title": a.get("display_name") or a.get("name"), "severity": normalize_sev(a.get("severity_name")),
                        "status": status, "category": "endpoint", "tactic": a.get("tactic"),
                        "technique": f"{a.get('technique_id', '')} {a.get('technique', '')}".strip(),
                        "user_name": a.get("user_name"), "occurred_at": a.get("timestamp"), "detected_at": a.get("created_timestamp"),
                        "resolved_at": a.get("updated_timestamp") if status == "resolved" else None,
                    })
        return out
