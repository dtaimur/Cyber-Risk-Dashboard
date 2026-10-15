"""Qualys VMDR connector (HTTP basic auth, XML API v2).

Pulls host detections, then resolves QIDs to CVEs and CVSS via the
KnowledgeBase API.
"""
import xml.etree.ElementTree as ET

from .base import Connector, ConnectorError, SyncResult, normalize_sev

QUALYS_SEV = {"5": "critical", "4": "high", "3": "medium", "2": "low", "1": "low"}


class QualysConnector(Connector):
    id = "qualys"
    name = "Qualys VMDR"
    description = "Network and host vulnerability scan results, scan coverage, and remediation status."
    docs_url = "https://docs.qualys.com/en/vm/api/"
    fields = [
        {"key": "base_url", "label": "Platform API URL", "secret": False, "placeholder": "https://qualysapi.qualys.com"},
        {"key": "username", "label": "Username", "secret": False, "placeholder": "API user"},
        {"key": "secret", "label": "Password", "secret": True, "placeholder": "API user password"},
    ]

    def _client(self, cfg, secret):
        base = (cfg.get("base_url") or "https://qualysapi.qualys.com").rstrip("/")
        return self.client(base_url=base, auth=(cfg.get("username", ""), secret), headers={"X-Requested-With": "CyberRiskDashboard"})

    def _get(self, c, path, params):
        r = c.get(path, params=params)
        if r.status_code == 401:
            raise ConnectorError("Authentication failed (HTTP 401)")
        r.raise_for_status()
        return ET.fromstring(r.content)

    def test(self, cfg, secret):
        with self._client(cfg, secret) as c:
            root = self._get(c, "/api/2.0/fo/asset/host/", {"action": "list", "truncation_limit": 1})
        return f"Authenticated. Response: {root.tag}"

    def sync(self, cfg, secret):
        out = SyncResult()
        with self._client(cfg, secret) as c:
            root = self._get(c, "/api/2.0/fo/asset/host/vm/detection/", {
                "action": "list", "status": "New,Active,Re-Opened", "truncation_limit": 1000, "show_results": 0})
            detections = []
            for host in root.iter("HOST"):
                hostname = host.findtext("DNS") or host.findtext("NETBIOS") or host.findtext("IP")
                out.assets.append({"hostname": hostname, "ip": host.findtext("IP"), "os": host.findtext("OS"),
                                   "last_scanned": (host.findtext("LAST_VM_SCANNED_DATE") or "")[:10] or None})
                for det in host.iter("DETECTION"):
                    detections.append((hostname, det))

            qids = sorted({det.findtext("QID") for _, det in detections})
            kb = {}
            for i in range(0, len(qids), 200):
                kroot = self._get(c, "/api/2.0/fo/knowledge_base/vuln/", {"action": "list", "ids": ",".join(qids[i:i + 200]), "details": "Basic"})
                for v in kroot.iter("VULN"):
                    kb[v.findtext("QID")] = {
                        "title": v.findtext("TITLE"), "cve": v.findtext("CVE_LIST/CVE/ID"),
                        "cvss": float(v.findtext("CVSS_V3/BASE") or v.findtext("CVSS/BASE") or 0) or None,
                    }

            for hostname, det in detections:
                info = kb.get(det.findtext("QID"), {})
                out.findings.append({
                    "hostname": hostname, "external_id": f"QID-{det.findtext('QID')}", "cve": info.get("cve"),
                    "title": info.get("title") or f"QID {det.findtext('QID')}",
                    "severity": QUALYS_SEV.get(det.findtext("SEVERITY"), normalize_sev(None)), "cvss": info.get("cvss"),
                    "vendor_score": float(det.findtext("QDS") or 0) or None,
                    "status": "open", "first_seen": (det.findtext("FIRST_FOUND_DATETIME") or "")[:10], "due_date": None,
                })
        return out
