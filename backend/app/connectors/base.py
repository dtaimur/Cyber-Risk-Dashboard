"""Shared plumbing for security-tool connectors.

Each connector authenticates to the vendor API, pulls records, and maps them
into the dashboard's normalized schema (assets / findings / alerts /
cloud_issues). When a sync succeeds, that tool's simulated records are replaced
with live ones, so every page downstream works unchanged.
"""
import json
from dataclasses import dataclass, field

import httpx

from .. import catalog
from ..db import get_conn

TIMEOUT = httpx.Timeout(30.0)


class ConnectorError(Exception):
    pass


@dataclass
class SyncResult:
    assets: list = field(default_factory=list)       # dicts keyed like the assets table (hostname required)
    findings: list = field(default_factory=list)     # dicts + "hostname"
    alerts: list = field(default_factory=list)       # dicts + "hostname"
    cloud_issues: list = field(default_factory=list)

    @property
    def total(self):
        return len(self.findings) + len(self.alerts) + len(self.cloud_issues)


def sev_from_score(score):
    return catalog.severity_from_cvss(float(score or 0))


def normalize_sev(value, default="medium"):
    v = str(value or "").lower()
    if v in ("critical", "high", "medium", "low"):
        return v
    return {"informational": "low", "info": "low", "5": "critical", "4": "high", "3": "medium", "2": "low", "1": "low"}.get(v, default)


def persist(source: str, result: SyncResult):
    """Replace this tool's records with live data in one transaction."""
    with get_conn() as conn:
        host_ids = {r["hostname"]: r["id"] for r in conn.execute("SELECT id, hostname FROM assets")}

        def asset_id(hostname):
            if hostname and hostname not in host_ids:
                cur = conn.execute("INSERT INTO assets (hostname, asset_type, environment, criticality, software, edr_status) VALUES (?,?,?,?,?,?)",
                                   (hostname, "server", "on-prem", 3, "[]", "n/a"))
                host_ids[hostname] = cur.lastrowid
            return host_ids.get(hostname)

        for a in result.assets:
            aid = asset_id(a["hostname"])
            cols = [k for k in a if k != "hostname"]
            if cols:
                conn.execute(f"UPDATE assets SET {', '.join(c + '=?' for c in cols)} WHERE id=?",
                             [json.dumps(a[c]) if isinstance(a[c], list) else a[c] for c in cols] + [aid])

        if result.findings:
            conn.execute("DELETE FROM findings WHERE source=?", (source,))
            for f in result.findings:
                f = _finding_defaults(f)
                f = {**f, "asset_id": asset_id(f.pop("hostname", None)), "source": source, "is_live": 1}
                conn.execute(f"INSERT INTO findings ({','.join(f)}) VALUES ({','.join('?' * len(f))})", list(f.values()))
        if result.alerts:
            conn.execute("DELETE FROM alerts WHERE source=?", (source,))
            for al in result.alerts:
                al = {**al, "asset_id": asset_id(al.pop("hostname", None)), "source": source, "is_live": 1}
                conn.execute(f"INSERT INTO alerts ({','.join(al)}) VALUES ({','.join('?' * len(al))})", list(al.values()))
        if result.cloud_issues:
            conn.execute("DELETE FROM cloud_issues")
            for ci in result.cloud_issues:
                ci = {**ci, "is_live": 1}
                conn.execute(f"INSERT INTO cloud_issues ({','.join(ci)}) VALUES ({','.join('?' * len(ci))})", list(ci.values()))


def _finding_defaults(f):
    """Vendor APIs don't share our SLA model; derive due dates from our policy."""
    from datetime import date, timedelta
    f = dict(f)
    f["first_seen"] = f.get("first_seen") or date.today().isoformat()
    f["severity"] = f.get("severity") or "medium"
    if not f.get("due_date"):
        f["due_date"] = (date.fromisoformat(f["first_seen"]) + timedelta(days=catalog.SLA_DAYS[f["severity"]])).isoformat()
    return f


class Connector:
    id: str
    kind: str = "security_tool"
    name: str
    description: str
    docs_url: str
    fields: list  # [{key, label, secret, placeholder}]

    def client(self, headers=None, **kw):
        return httpx.Client(timeout=TIMEOUT, headers={"User-Agent": "Cyber-Risk-Dashboard/1.0", **(headers or {})}, **kw)

    def test(self, cfg: dict, secret: str) -> str:
        raise NotImplementedError

    def sync(self, cfg: dict, secret: str) -> SyncResult:
        raise NotImplementedError
