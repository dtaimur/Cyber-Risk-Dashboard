"""Wiz connector (CNAPP). OAuth2 client credentials + GraphQL API."""
from .base import Connector, ConnectorError, SyncResult, normalize_sev, sev_from_score

ISSUES_QUERY = """
query Issues($first: Int) {
  issuesV2(first: $first, filterBy: {status: [OPEN, IN_PROGRESS]}) {
    nodes { id severity status createdAt type
      sourceRule { ... on Control { name } ... on CloudConfigurationRule { name } }
      entitySnapshot { name type cloudPlatform externalId } }
  }
}"""

VULNS_QUERY = """
query Vulns($first: Int) {
  vulnerabilityFindings(first: $first, filterBy: {status: [OPEN]}) {
    nodes { id name CVSSSeverity score firstDetectedAt
      vulnerableAsset { ... on VulnerableAssetBase { name cloudPlatform } } }
  }
}"""


class WizConnector(Connector):
    id = "wiz"
    name = "Wiz"
    description = "Cloud security posture: misconfigurations, toxic combinations, and cloud workload vulnerabilities."
    docs_url = "https://win.wiz.io/reference"
    fields = [
        {"key": "api_url", "label": "GraphQL API endpoint", "secret": False, "placeholder": "https://api.us17.app.wiz.io/graphql"},
        {"key": "client_id", "label": "Client ID", "secret": False, "placeholder": "Service account client ID"},
        {"key": "secret", "label": "Client secret", "secret": True, "placeholder": "Service account secret"},
    ]

    def _session(self, cfg, secret):
        c = self.client()
        r = c.post("https://auth.app.wiz.io/oauth/token", data={
            "grant_type": "client_credentials", "audience": "wiz-api",
            "client_id": cfg.get("client_id", ""), "client_secret": secret})
        if r.status_code != 200:
            raise ConnectorError(f"Authentication failed (HTTP {r.status_code})")
        c.headers["Authorization"] = f"Bearer {r.json()['access_token']}"
        return c

    def _gql(self, c, cfg, query, variables):
        if not cfg.get("api_url"):
            raise ConnectorError("GraphQL API endpoint is required")
        data = c.post(cfg["api_url"], json={"query": query, "variables": variables}).raise_for_status().json()
        if data.get("errors"):
            raise ConnectorError(data["errors"][0].get("message", "GraphQL error"))
        return data["data"]

    def test(self, cfg, secret):
        with self._session(cfg, secret) as c:
            self._gql(c, cfg, ISSUES_QUERY, {"first": 1})
        return "Authenticated to Wiz GraphQL API."

    def sync(self, cfg, secret):
        out = SyncResult()
        with self._session(cfg, secret) as c:
            for i in self._gql(c, cfg, ISSUES_QUERY, {"first": 500})["issuesV2"]["nodes"]:
                ent = i.get("entitySnapshot") or {}
                out.cloud_issues.append({
                    "external_id": i["id"], "resource": ent.get("name"), "resource_type": ent.get("type"),
                    "cloud": (ent.get("cloudPlatform") or "").lower(), "rule": (i.get("sourceRule") or {}).get("name"),
                    "category": "toxic_combination" if i.get("type") == "TOXIC_COMBINATION" else "misconfiguration",
                    "severity": normalize_sev(i.get("severity")), "status": "open", "internet_exposed": 0,
                    "created_at": (i.get("createdAt") or "")[:10],
                })
            for v in self._gql(c, cfg, VULNS_QUERY, {"first": 500})["vulnerabilityFindings"]["nodes"]:
                asset = v.get("vulnerableAsset") or {}
                out.findings.append({
                    "hostname": asset.get("name"), "external_id": v["id"], "cve": v.get("name") if str(v.get("name", "")).startswith("CVE-") else None,
                    "title": v.get("name"), "severity": normalize_sev(v.get("CVSSSeverity"), sev_from_score(v.get("score"))),
                    "cvss": v.get("score"), "status": "open", "first_seen": (v.get("firstDetectedAt") or "")[:10], "due_date": None,
                })
        return out
