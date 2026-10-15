"""Threat news (live RSS + CISA KEV) and active-threat correlation."""
from datetime import date, timedelta

from fastapi import APIRouter, Depends, Query

from .. import threat_intel
from ..db import get_conn, jloads, rows
from ..auth import require

router = APIRouter(prefix="/api/threats")


@router.get("/news", dependencies=[Depends(require("view_threat_intel"))])
def news(source: str | None = Query(None, max_length=60), relevant: bool = False, q: str | None = Query(None, max_length=100),
         limit: int = Query(60, ge=1, le=200)):
    with get_conn() as conn:
        env = set(threat_intel.env_cves(conn))
        kev = {r["cve"] for r in conn.execute("SELECT cve FROM kev")}
        where, params = [], []
        if source:
            where.append("source = ?"); params.append(source)
        if q:
            where.append("(title LIKE ? OR summary LIKE ?)"); params += [f"%{q}%"] * 2
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        items = rows(conn, f"SELECT * FROM articles {clause} ORDER BY published DESC LIMIT 400", params)
        sources = [r["source"] for r in conn.execute("SELECT DISTINCT source FROM articles ORDER BY source")]
    out = []
    for a in items:
        cves = jloads(a["cves"], [])
        products = jloads(a["products"], [])
        a["cves"] = [{"id": c, "in_environment": c in env, "in_kev": c in kev} for c in cves]
        a["products"] = products
        a["relevant"] = bool(products) or any(c["in_environment"] for c in a["cves"])
        if relevant and not a["relevant"]:
            continue
        out.append(a)
    return {"items": out[:limit], "sources": sources}


@router.get("/kev", dependencies=[Depends(require("view_threat_intel"))])
def kev(limit: int = Query(40, ge=1, le=200)):
    with get_conn() as conn:
        env = set(threat_intel.env_cves(conn))
        items = rows(conn, "SELECT * FROM kev ORDER BY date_added DESC, cve DESC LIMIT ?", (limit,))
        total = conn.execute("SELECT COUNT(*) FROM kev").fetchone()[0]
        last_30 = conn.execute("SELECT COUNT(*) FROM kev WHERE date_added >= ?", ((date.today() - timedelta(days=30)).isoformat(),)).fetchone()[0]
    for k in items:
        k["in_environment"] = k["cve"] in env
    return {"items": items, "total": total, "added_30d": last_30}


@router.get("/active", dependencies=[Depends(require("view_details"))])
def active():
    with get_conn() as conn:
        threats = threat_intel.active_threats(conn)
        unverified = threat_intel.unverified_exposure(conn)
        # Remediation ticket per CVE (an open one wins over a closed one)
        tickets = {}
        for r in conn.execute("""SELECT DISTINCT f.cve, t.key, t.status, t.url FROM tickets t
                                 JOIN ticket_findings tf ON tf.ticket_id=t.id JOIN findings f ON f.id=tf.finding_id
                                 WHERE f.status IN ('open','in_progress')
                                 ORDER BY CASE WHEN t.status IN ('To Do','In Progress','In Review') THEN 1 ELSE 0 END"""):
            tickets[r["cve"]] = {"key": r["key"], "status": r["status"], "url": r["url"]}
        since = (date.today() - timedelta(days=21)).isoformat()
        watch = rows(conn, "SELECT id, source, title, link, published, products FROM articles WHERE products != '[]' AND published >= ? ORDER BY published DESC LIMIT 12", (since,))
    for t in threats:
        t["ticket"] = tickets.get(t["cve"])
    for w in watch:
        w["products"] = jloads(w["products"], [])
    return {
        "threats": threats, "unverified": unverified, "watchlist": watch,
        "stats": {"total": len(threats), "kev": sum(t["in_kev"] for t in threats), "ransomware": sum(t["ransomware"] for t in threats),
                  "in_news": sum(1 for t in threats if t["news_count"]), "internet_facing_assets": len({a["asset_id"] for t in threats for a in t["affected_assets"] if a["internet_facing"]}),
                  "overdue": sum(t["overdue"] for t in threats)},
        "weights": threat_intel.WEIGHTS,
    }


@router.post("/refresh", dependencies=[Depends(require("refresh_feeds"))])
def refresh():
    return threat_intel.refresh()
