"""Integration registry and state (enabled flag, config, encrypted credential, sync status)."""
import json
from datetime import datetime, timezone

from .connectors import CONNECTORS
from .db import get_conn, jloads, one
from .secrets_store import decrypt, encrypt
from .threat_intel import NEWS_FEEDS

FEEDS = {
    "cisa_kev": ("CISA KEV Catalog", "Known Exploited Vulnerabilities: CVEs with confirmed in-the-wild exploitation.",
                 "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
    **{k: (name, f"Security news RSS feed from {name}.", url) for k, (name, url) in NEWS_FEEDS.items()},
    "epss": ("FIRST EPSS", "Exploit Prediction Scoring System: probability a CVE is exploited in the next 30 days.",
             "https://www.first.org/epss/"),
}


def definitions():
    out = []
    for cid, c in CONNECTORS.items():
        out.append({"id": cid, "name": c.name, "kind": c.kind, "description": c.description,
                    "docs_url": c.docs_url, "fields": c.fields, "requires_credentials": True})
    for fid, (name, desc, url) in FEEDS.items():
        out.append({"id": fid, "name": name, "kind": "threat_feed", "description": desc, "docs_url": url,
                    "fields": [], "requires_credentials": False})
    return out


def ensure_rows():
    with get_conn() as conn:
        for d in definitions():
            conn.execute("INSERT OR IGNORE INTO integrations (id, enabled, config) VALUES (?,?,?)",
                         (d["id"], 0 if d["requires_credentials"] else 1, "{}"))


def state(integration_id):
    with get_conn() as conn:
        return one(conn, "SELECT * FROM integrations WHERE id=?", (integration_id,))


def enabled_ids():
    with get_conn() as conn:
        return {r["id"] for r in conn.execute("SELECT id FROM integrations WHERE enabled=1")}


def public_view():
    """Integration list safe to send to the browser: secrets reduced to a boolean."""
    with get_conn() as conn:
        states = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM integrations")}
    out = []
    for d in definitions():
        s = states.get(d["id"], {})
        live = d["kind"] == "threat_feed" or bool(s.get("enabled") and s.get("last_status") == "ok")
        out.append({**d, "enabled": bool(s.get("enabled")), "config": jloads(s.get("config"), {}),
                    "has_secret": bool(s.get("secret_enc")), "last_sync": s.get("last_sync"),
                    "last_status": s.get("last_status"), "last_message": s.get("last_message"),
                    "record_count": s.get("record_count"), "data_mode": "live" if live else "mock"})
    return out


def update(integration_id, enabled=None, config=None, secret=None, actor=None):
    with get_conn() as conn:
        if enabled is not None:
            conn.execute("UPDATE integrations SET enabled=? WHERE id=?", (int(enabled), integration_id))
        if config is not None:
            conn.execute("UPDATE integrations SET config=? WHERE id=?", (json.dumps(config), integration_id))
        if secret:
            conn.execute("UPDATE integrations SET secret_enc=? WHERE id=?", (encrypt(secret), integration_id))
        conn.execute("INSERT INTO audit_log (ts, actor, action, detail) VALUES (?,?,?,?)",
                     (_now(), actor, "integration.update", json.dumps({"id": integration_id, "enabled": enabled,
                                                                        "config_keys": sorted((config or {}).keys()), "secret_changed": bool(secret)})))


def credentials(integration_id):
    s = state(integration_id) or {}
    return jloads(s.get("config"), {}), decrypt(s.get("secret_enc"))


def set_status(integration_id, status, message, count):
    with get_conn() as conn:
        conn.execute("UPDATE integrations SET last_sync=?, last_status=?, last_message=?, record_count=COALESCE(?, record_count) WHERE id=?",
                     (_now(), status, message, count, integration_id))


def tool_modes():
    return {i["id"]: i["data_mode"] for i in public_view() if i["kind"] in ("security_tool", "ticketing")}


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
