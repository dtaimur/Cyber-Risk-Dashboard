"""Executive summary, vulnerability overview, per-tool pages, and asset drill-down."""
from collections import Counter
from datetime import date, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query

from .. import metrics, remediation, threat_intel
from ..db import get_conn, jloads, one, rows
from ..integrations import tool_modes
from ..metrics import SEVS, Data
from ..auth import require

router = APIRouter(prefix="/api")

TOOLS = ("qualys", "crowdstrike", "expel", "wiz")


@router.get("/status", dependencies=[Depends(require("view_summary"))])
def status():
    """Which tools are on a live API connection (drives the live indicators in navigation)."""
    return {"modes": tool_modes()}


@router.get("/summary", dependencies=[Depends(require("view_summary"))])
def summary():
    with get_conn() as conn:
        data = Data(conn)
        ctx = metrics.context(data)
        risk = metrics.risk_score(data, ctx=ctx)
        history = metrics.risk_history(data, ctx)
        threats = threat_intel.active_threats(conn)
    v, al, tp, cov = ctx["vulns"], ctx["alerts"], ctx["tprm"], ctx["coverage"]
    prior = history[-5]["score"] if len(history) >= 5 else history[0]["score"]

    # "What needs action, and who owns the next step?"
    actions = []
    # Group top threats by product so one patch campaign is one action
    by_product = {}
    for t in threats:
        key = t["product"] or t["cve"]
        by_product.setdefault(key, []).append(t)
    for product, group in list(by_product.items())[:3]:
        lead = group[0]
        hosts = {a["asset_id"] for t in group for a in t["affected_assets"]}
        cves = f"{len(group)} {product} CVEs" if len(group) > 1 else lead["cve"]
        actions.append({"priority": "critical" if lead["in_kev"] else "high", "area": "Active threat",
                        "title": f"Patch {cves} on {len(hosts)} asset{'s' if len(hosts) > 1 else ''}",
                        "detail": ", ".join(t["cve"] for t in group[:3]) + (" · in the news" if any(t["news"] for t in group) else ""),
                        "owner": lead["affected_assets"][0]["owner"] if lead["affected_assets"] else "Vulnerability Mgmt",
                        "link": f"/threats/active#{lead['cve']}"})
    if al["open_critical"]:
        actions.append({"priority": "critical", "area": "Alerts", "title": f"Triage {al['open_critical']} open critical alerts",
                        "detail": "Unresolved critical detections across connected tools", "owner": "SOC", "link": "/alerts"})
    for vend in [x for x in tp["vendors"] if x["tier"] == 1 and x["reasons"]][:2]:
        actions.append({"priority": "high", "area": "Third-party", "title": f"Review {vend['name']}", "detail": "; ".join(vend["reasons"]),
                        "owner": "Third-Party Risk", "link": "/"})
    if cov["edr"]["missing"]:
        actions.append({"priority": "medium", "area": "Coverage", "title": f"Deploy EDR to {cov['edr']['missing']} unprotected hosts",
                        "detail": "Hosts with no CrowdStrike sensor", "owner": "Endpoint Engineering", "link": "/vulnerabilities/crowdstrike"})
    for r in data.roadmap:
        if r["status"] == "at_risk":
            actions.append({"priority": "medium", "area": "Roadmap", "title": r["title"], "detail": r["notes"] or "Marked at risk",
                            "owner": r["owner"], "link": "/compliance"})

    return {
        "risk": {**risk, "history": history, "change_30d": round(risk["score"] - prior, 1)},
        "kpis": {
            "open_critical": v["by_severity"]["critical"], "open_high": v["by_severity"]["high"], "kev_open": v["kev_open"],
            "crit_high_overdue": v["crit_high_overdue"], "sla_compliance": v["sla_compliance"],
            "active_threats": len(threats), "alerts_30d": al["total"], "open_crit_high_alerts": al["open_crit_high"],
            "incidents_30d": al["incidents"], "mttr_critical_hours": al["mttr_hours"]["critical"], "mttd_minutes": al["mttd_minutes"],
            "edr_coverage": cov["edr_coverage"], "scan_coverage": cov["scan_coverage"],
            "compliance_avg": round(sum(f["pct"] for f in ctx["frameworks"]) / len(ctx["frameworks"]), 1),
        },
        "alerts_by_platform": metrics.alerts_by_platform(data),
        "vulns_by_source": metrics.by_source(data),
        "third_party": {k: tp[k] for k in ("vendor_count", "avg_bitsight", "avg_ssc", "tier1_avg_ssc", "needs_attention", "overdue_assessments", "due_soon", "trend")}
                       | {"vendors": tp["vendors"]},
        "frameworks": [{k: f[k] for k in ("framework", "pct")} for f in ctx["frameworks"]],
        "actions": actions[:7],
        "modes": tool_modes(),
    }


@router.get("/vulnerabilities/overview", dependencies=[Depends(require("view_details"))])
def vuln_overview():
    with get_conn() as conn:
        data = Data(conn)
    return {"metrics": metrics.vuln_metrics(data), "by_source": metrics.by_source(data), "trend": metrics.vuln_trend(data),
            "aging": metrics.aging(data), "top_assets": metrics.top_assets(data), "modes": tool_modes()}


@router.get("/vulnerabilities/findings", dependencies=[Depends(require("view_details"))])
def findings(source: str | None = Query(None, pattern="^(qualys|crowdstrike|wiz)$"),
             severity: str | None = Query(None, pattern="^(critical|high|medium|low)$"),
             status: str = Query("open", pattern="^(open|all|remediated|overdue)$"),
             asset_id: int | None = None, q: str | None = Query(None, max_length=100),
             limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    where, params = [], []
    if source:
        where.append("f.source = ?"); params.append(source)
    if severity:
        where.append("f.severity = ?"); params.append(severity)
    if status == "open":
        where.append("f.status IN ('open','in_progress')")
    elif status == "remediated":
        where.append("f.status = 'remediated'")
    elif status == "overdue":
        where.append("f.status IN ('open','in_progress') AND f.due_date < ?"); params.append(date.today().isoformat())
    if asset_id:
        where.append("f.asset_id = ?"); params.append(asset_id)
    if q:
        where.append("(f.cve LIKE ? OR f.title LIKE ? OR a.hostname LIKE ?)"); params += [f"%{q}%"] * 3
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    with get_conn() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM findings f JOIN assets a ON a.id=f.asset_id {clause}", params).fetchone()[0]
        items = rows(conn, f"""SELECT f.*, a.hostname, a.criticality, a.internet_facing, a.business_unit,
                                      (SELECT 1 FROM kev k WHERE k.cve = f.cve) AS in_kev
                               FROM findings f JOIN assets a ON a.id=f.asset_id {clause}
                               ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                                        f.cvss DESC, f.first_seen LIMIT ? OFFSET ?""", params + [limit, offset])
    return {"total": total, "items": items}


@router.get("/assets/{asset_id}", dependencies=[Depends(require("view_details"))])
def asset_detail(asset_id: int):
    with get_conn() as conn:
        a = one(conn, "SELECT * FROM assets WHERE id=?", (asset_id,))
        if not a:
            raise HTTPException(404, "Asset not found")
        a["software"] = jloads(a["software"], [])
        a["findings"] = rows(conn, """SELECT f.*, (SELECT 1 FROM kev k WHERE k.cve=f.cve) AS in_kev FROM findings f
                                      WHERE asset_id=? ORDER BY status, cvss DESC""", (asset_id,))
        a["alerts"] = rows(conn, "SELECT * FROM alerts WHERE asset_id=? ORDER BY detected_at DESC LIMIT 25", (asset_id,))
        idx = remediation.finding_ticket_index(conn)
        for f in a["findings"]:
            f["ticket"] = idx.get(f["id"])
    return a


@router.get("/tools/{tool}", dependencies=[Depends(require("view_details"))])
def tool_page(tool: str):
    if tool not in TOOLS:
        raise HTTPException(404, "Unknown tool")
    with get_conn() as conn:
        data = Data(conn)
        out = {"tool": tool, "mode": tool_modes().get(tool, "mock")}
        out.update({"qualys": _qualys, "crowdstrike": _crowdstrike, "expel": _expel, "wiz": _wiz}[tool](data, conn))
    return out


def _top_titles(data, source, limit=8):
    c = Counter()
    meta = {}
    for f in data.findings:
        if f["source"] == source and metrics.is_open(f, data.today):
            c[f["title"]] += 1
            meta[f["title"]] = {"severity": f["severity"], "cve": f["cve"], "cvss": f["cvss"], "in_kev": f["cve"] in data.kev}
    return [{"title": t, "count": n, **meta[t]} for t, n in c.most_common(limit)]


def _qualys(data, conn):
    v = metrics.vuln_metrics(data, source="qualys")
    open_q = [f for f in data.findings if f["source"] == "qualys" and metrics.is_open(f, data.today)]
    qds = [f["vendor_score"] for f in open_q if f["vendor_score"]]
    labels = {"critical": "5 – Urgent", "high": "4 – Critical", "medium": "3 – Serious", "low": "2 – Medium"}
    buckets = [("0–7 days", 0, 7), ("8–14 days", 8, 14), ("15–30 days", 15, 30), ("31–60 days", 31, 60), ("60+ days", 61, 10_000)]
    scan_age = [{"bucket": b, "hosts": sum(1 for a in data.assets.values() if a["last_scanned"]
                                           and lo <= (data.today - date.fromisoformat(a["last_scanned"])).days <= hi)} for b, lo, hi in buckets]
    cov = metrics.coverage(data)
    return {
        "kpis": {"open": v["open_total"], "urgent": v["by_severity"]["critical"], "hosts_scanned_30d": cov["scanned_30d"],
                 "scan_coverage": cov["scan_coverage"], "avg_qds": round(sum(qds) / len(qds), 1) if qds else None,
                 "patchable_pct": v["patchable_pct"], "sla_compliance": v["sla_compliance"], "mttr_critical": v["mttr_days"]["critical"],
                 "affected_hosts": v["affected_assets"], "kev_open": v["kev_open"]},
        "severity": [{"label": labels[s], "severity": s, "count": v["by_severity"][s]} for s in SEVS],
        "trend": metrics.vuln_trend(data, "qualys"), "aging": metrics.aging(data, "qualys"),
        "top_vulns": _top_titles(data, "qualys"), "top_assets": metrics.top_assets(data, "qualys", 8), "scan_age": scan_age,
    }


def _crowdstrike(data, conn):
    cov = metrics.coverage(data)
    managed = [a for a in data.assets.values() if a["asset_type"] != "network"]
    versions = Counter(a["sensor_version"] for a in managed if a["sensor_version"])
    am = metrics.alert_metrics(data, 30, source="crowdstrike")
    start = data.now - timedelta(days=30)
    det = [a for a in data.alerts if a["source"] == "crowdstrike" and a["_det"] and a["_det"] > start]
    tactics = Counter(a["tactic"] for a in det if a["tactic"])
    prevented = sum(1 for a in det if any(w in (a["title"] or "").lower() for w in ("blocked", "quarantined")))
    host_hits = Counter(a["asset_id"] for a in det)
    v = metrics.vuln_metrics(data, source="crowdstrike")
    env_counts = Counter(a["environment"] for a in managed if a["edr_status"] == "missing")
    return {
        "kpis": {"edr_coverage": cov["edr_coverage"], "managed_hosts": cov["managed_hosts"], "sensors_healthy": cov["edr"]["normal"],
                 "rfm": cov["edr"]["rfm"], "missing": cov["edr"]["missing"], "contained": sum(a["contained"] or 0 for a in managed),
                 "detections_30d": am["total"], "open_detections": am["open_total"], "prevented": prevented,
                 "spotlight_open": v["open_total"], "spotlight_critical": v["by_severity"]["critical"], "mttr_critical_hours": am["mttr_hours"]["critical"]},
        "sensor_status": [{"status": "Healthy", "key": "normal", "count": cov["edr"]["normal"]},
                          {"status": "Reduced functionality", "key": "rfm", "count": cov["edr"]["rfm"]},
                          {"status": "No sensor", "key": "missing", "count": cov["edr"]["missing"]}],
        "missing_by_env": [{"environment": k, "count": n} for k, n in env_counts.most_common()],
        "sensor_versions": [{"version": k, "count": n, "current": k == max(versions)} for k, n in sorted(versions.items(), reverse=True)],
        "detections_by_severity": [{"severity": s, "count": am["by_severity"][s]} for s in SEVS],
        "tactics": [{"tactic": t, "count": n} for t, n in tactics.most_common()],
        "top_hosts": [{"hostname": data.assets[h]["hostname"], "asset_id": h, "count": n} for h, n in host_hits.most_common(8)],
        "spotlight_trend": metrics.vuln_trend(data, "crowdstrike"), "top_vulns": _top_titles(data, "crowdstrike"),
    }


def _expel(data, conn):
    am = metrics.alert_metrics(data, 30, source="expel")
    start = data.now - timedelta(days=30)
    al = [a for a in data.alerts if a["source"] == "expel" and a["_det"] and a["_det"] > start]
    weekly = []
    for w in range(12, -1, -1):
        end = data.now - timedelta(days=7 * w)
        wk = [a for a in data.alerts if a["source"] == "expel" and a["_det"] and end - timedelta(days=7) < a["_det"] <= end]
        res = [(a["_res"] - a["_det"]).total_seconds() / 3600 for a in wk if a["_res"] and a["status"] != "false_positive"]
        weekly.append({"date": end.date().isoformat(), "alerts": len(wk), "incidents": sum(a["is_incident"] for a in wk),
                       "mttr_hours": round(sum(res) / len(res), 1) if res else None})
    investigated = [a for a in al if a["status"] != "false_positive"]
    incidents = rows(conn, """SELECT al.*, a.hostname FROM alerts al LEFT JOIN assets a ON a.id=al.asset_id
                              WHERE al.source='expel' AND al.is_incident=1 ORDER BY al.detected_at DESC LIMIT 10""")
    return {
        "kpis": {"alerts_30d": am["total"], "investigating": am["by_status"]["investigating"], "incidents_30d": am["incidents"],
                 "mttd_minutes": am["mttd_minutes"], "mttr_critical": am["mttr_hours"]["critical"], "mttr_high": am["mttr_hours"]["high"],
                 "false_positive_rate": am["false_positive_rate"], "open": am["open_total"]},
        "funnel": [{"stage": "Alerts triaged", "count": len(al)}, {"stage": "Escalated for investigation", "count": len(investigated)},
                   {"stage": "Confirmed incidents", "count": am["incidents"]}],
        "categories": [{"category": c.replace("_", " "), "count": n} for c, n in Counter(a["category"] for a in al).most_common()],
        "weekly": weekly, "incidents": incidents,
    }


def _wiz(data, conn):
    cloud_assets = [a for a in data.assets.values() if a["environment"] in ("aws", "azure", "gcp")]
    open_i = [c for c in data.cloud if c["status"] == "open"]
    trend = []
    for w in range(12, -1, -1):
        end = (data.today - timedelta(days=7 * w)).isoformat()
        o = [c for c in data.cloud if c["created_at"] <= end and (not c["resolved_at"] or c["resolved_at"] > end)]
        trend.append({"date": end, **{s: sum(1 for c in o if c["severity"] == s) for s in SEVS}})
    v = metrics.vuln_metrics(data, source="wiz")
    return {
        "kpis": {"cloud_resources": len(cloud_assets), "open_issues": len(open_i), "critical_issues": sum(1 for c in open_i if c["severity"] == "critical"),
                 "toxic_combinations": sum(1 for c in open_i if c["category"] == "toxic_combination"),
                 "internet_exposed": sum(1 for c in open_i if c["internet_exposed"]), "secrets": sum(1 for c in open_i if c["category"] == "secret"),
                 "workload_vulns": v["open_total"], "workload_critical": v["by_severity"]["critical"]},
        "by_cloud": [{"cloud": cl.upper(), "resources": sum(1 for a in cloud_assets if a["environment"] == cl),
                      **{s: sum(1 for c in open_i if c["cloud"] == cl and c["severity"] == s) for s in SEVS}} for cl in ("aws", "azure", "gcp")],
        "by_category": [{"category": c.replace("_", " "), "count": n} for c, n in Counter(c["category"] for c in open_i).most_common()],
        "top_rules": [{"rule": r, "count": n, "severity": next(c["severity"] for c in open_i if c["rule"] == r)}
                      for r, n in Counter(c["rule"] for c in open_i).most_common(8)],
        "toxic": [c for c in open_i if c["category"] == "toxic_combination"][:10],
        "trend": trend, "top_vulns": _top_titles(data, "wiz"),
    }
