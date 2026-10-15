"""Consolidated alert stream and forensic trend analysis."""
from collections import Counter, defaultdict
from datetime import timedelta
from statistics import median

from fastapi import APIRouter, Depends, Query

from .. import metrics
from ..db import get_conn, rows
from ..metrics import SEVS, Data
from ..auth import require

router = APIRouter(prefix="/api/alerts")


@router.get("", dependencies=[Depends(require("view_details"))])
def alert_stream(source: str | None = Query(None, pattern="^(crowdstrike|expel|wiz|qualys)$"),
                 severity: str | None = Query(None, pattern="^(critical|high|medium|low)$"),
                 status: str | None = Query(None, pattern="^(new|investigating|resolved|false_positive|open)$"),
                 tactic: str | None = Query(None, max_length=60), q: str | None = Query(None, max_length=100),
                 limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    where, params = [], []
    for col, val in (("al.source", source), ("al.severity", severity), ("al.tactic", tactic)):
        if val:
            where.append(f"{col} = ?"); params.append(val)
    if status == "open":
        where.append("al.status IN ('new','investigating')")
    elif status:
        where.append("al.status = ?"); params.append(status)
    if q:
        where.append("(al.title LIKE ? OR a.hostname LIKE ? OR al.user_name LIKE ? OR al.technique LIKE ?)"); params += [f"%{q}%"] * 4
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    with get_conn() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM alerts al LEFT JOIN assets a ON a.id=al.asset_id {clause}", params).fetchone()[0]
        items = rows(conn, f"""SELECT al.*, a.hostname, a.business_unit FROM alerts al LEFT JOIN assets a ON a.id=al.asset_id
                               {clause} ORDER BY al.detected_at DESC LIMIT ? OFFSET ?""", params + [limit, offset])
    return {"total": total, "items": items}


@router.get("/trends", dependencies=[Depends(require("view_details"))])
def trends(days: int = Query(90, ge=7, le=180)):
    with get_conn() as conn:
        data = Data(conn)
    start = data.now - timedelta(days=days)
    al = [a for a in data.alerts if a["_det"] and a["_det"] > start]

    daily = defaultdict(lambda: {"crowdstrike": 0, "expel": 0, "wiz": 0, "qualys": 0, "total": 0})
    for a in al:
        d = daily[a["_det"].date().isoformat()]
        d[a["source"]] += 1
        d["total"] += 1
    for i in range(days):
        daily[(data.now - timedelta(days=days - 1 - i)).date().isoformat()]
    daily_list = [{"date": k, **v} for k, v in sorted(daily.items())]

    weekly = []
    for w in range(days // 7 - 1, -1, -1):
        end = data.now - timedelta(days=7 * w)
        wk = [a for a in al if end - timedelta(days=7) < a["_det"] <= end]
        mttd = [(a["_det"] - a["_occ"]).total_seconds() / 60 for a in wk if a["_occ"]]
        res = [(a["_res"] - a["_det"]).total_seconds() / 3600 for a in wk if a["_res"] and a["status"] != "false_positive"
               and a["severity"] in ("critical", "high")]
        weekly.append({"date": end.date().isoformat(), "mttd_minutes": round(median(mttd), 1) if mttd else None,
                       "mttr_hours": round(median(res), 1) if res else None, "incidents": sum(a["is_incident"] for a in wk),
                       **{s: sum(1 for a in wk if a["severity"] == s) for s in SEVS}})

    heat = [[0] * 24 for _ in range(7)]
    for a in al:
        heat[a["_det"].weekday()][a["_det"].hour] += 1

    vals = [d["total"] for d in daily_list]
    base = median(vals) if vals else 0
    anomalies = [d for d in daily_list if base and d["total"] >= 1.8 * base]

    return {
        "summary": metrics.alert_metrics(data, days), "daily": daily_list, "weekly": weekly,
        "tactics": [{"tactic": t, "count": n} for t, n in Counter(a["tactic"] for a in al if a["tactic"]).most_common()],
        "techniques": [{"technique": t, "count": n} for t, n in Counter(a["technique"] for a in al if a["technique"]).most_common(10)],
        "categories": [{"category": c.replace("_", " "), "count": n} for c, n in Counter(a["category"] for a in al).most_common()],
        "top_hosts": [{"hostname": data.assets[h]["hostname"], "asset_id": h, "count": n} for h, n in Counter(a["asset_id"] for a in al if a["asset_id"]).most_common(8)],
        "top_users": [{"user": u, "count": n} for u, n in Counter(a["user_name"] for a in al if a["user_name"]).most_common(8)],
        "heatmap": heat, "baseline_daily": base, "anomalies": anomalies,
    }
