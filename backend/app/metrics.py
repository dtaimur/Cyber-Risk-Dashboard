"""Metric and scoring engine.

All metrics are computed from normalized records (findings, alerts, vendors,
controls) regardless of whether they came from a live connector or mock data.
Functions take an `as_of` date so trend lines are computed from the same logic
as today's numbers instead of being stored separately.
"""
from datetime import date, datetime, timedelta, timezone
from statistics import mean, median

from .catalog import SLA_DAYS
from .db import jloads, rows

SEVS = ["critical", "high", "medium", "low"]
SEV_WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 1}


def _dt(s):
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if "T" in s else datetime.combine(date.fromisoformat(s), datetime.min.time(), timezone.utc)


def _pct(n, d):
    return round(100 * n / d, 1) if d else 0.0


class Data:
    """Loads everything once per request; datasets are small (thousands of rows)."""

    def __init__(self, conn):
        self.assets = {a["id"]: a for a in rows(conn, "SELECT * FROM assets")}
        self.findings = rows(conn, "SELECT * FROM findings")
        self.alerts = rows(conn, "SELECT * FROM alerts")
        for a in self.alerts:
            a["_det"], a["_res"], a["_occ"] = _dt(a["detected_at"]), _dt(a["resolved_at"]), _dt(a["occurred_at"])
        self.cloud = rows(conn, "SELECT * FROM cloud_issues")
        self.vendors = rows(conn, "SELECT * FROM vendors")
        for v in self.vendors:
            v["bitsight_history"] = jloads(v["bitsight_history"], [])
            v["ssc_history"] = jloads(v["ssc_history"], [])
        self.controls = rows(conn, "SELECT * FROM controls")
        self.kev = {r["cve"]: r for r in rows(conn, "SELECT cve, date_added, due_date, ransomware FROM kev")}
        self.roadmap = rows(conn, "SELECT * FROM roadmap")
        self.now = datetime.now(timezone.utc)
        self.today = date.today()


# --------------------------------------------------------------------------- vulnerabilities
def is_open(f, as_of: date):
    d = as_of.isoformat()
    if f["first_seen"] > d:
        return False
    if f["remediated_at"]:
        return f["remediated_at"] > d
    if as_of >= date.today():
        return f["status"] in ("open", "in_progress")
    return f["status"] != "risk_accepted"


def vuln_metrics(data: Data, as_of=None, source=None):
    as_of = as_of or data.today
    fs = [f for f in data.findings if source is None or f["source"] == source]
    open_f = [f for f in fs if is_open(f, as_of)]
    d = as_of.isoformat()
    by_sev = {s: sum(1 for f in open_f if f["severity"] == s) for s in SEVS}
    crit_high = [f for f in open_f if f["severity"] in ("critical", "high")]
    overdue = [f for f in crit_high if f["due_date"] < d]
    window = (as_of - timedelta(days=90)).isoformat()
    remediated = [f for f in fs if f["remediated_at"] and window <= f["remediated_at"] <= d]
    mttr = {}
    for s in SEVS:
        days = [(date.fromisoformat(f["remediated_at"]) - date.fromisoformat(f["first_seen"])).days for f in remediated if f["severity"] == s]
        mttr[s] = round(mean(days), 1) if days else None
    on_time = sum(1 for f in remediated if f["severity"] in ("critical", "high") and f["remediated_at"] <= f["due_date"])
    closed_ch = sum(1 for f in remediated if f["severity"] in ("critical", "high"))
    affected_assets = {f["asset_id"] for f in open_f}
    return {
        "open_total": len(open_f), "by_severity": by_sev, "crit_high_open": len(crit_high), "crit_high_overdue": len(overdue),
        "sla_compliance": round(100 - _pct(len(overdue), len(crit_high)), 1),
        "remediated_on_time_pct": _pct(on_time, closed_ch), "remediated_90d": len(remediated), "mttr_days": mttr,
        "affected_assets": len(affected_assets), "patchable_pct": _pct(sum(f["patch_available"] for f in open_f), len(open_f)),
        "kev_open": len({f["cve"] for f in open_f if f["cve"] in data.kev and data.kev[f["cve"]]["date_added"] <= d}),
    }


def vuln_trend(data: Data, source=None, weeks=13):
    fs = [f for f in data.findings if source is None or f["source"] == source]
    out = []
    for w in range(weeks - 1, -1, -1):
        end = data.today - timedelta(days=7 * w)
        start = end - timedelta(days=7)
        point = {"date": end.isoformat()}
        for s in SEVS:
            point[s] = sum(1 for f in fs if f["severity"] == s and is_open(f, end))
        point["new"] = sum(1 for f in fs if start.isoformat() < f["first_seen"] <= end.isoformat())
        point["remediated"] = sum(1 for f in fs if f["remediated_at"] and start.isoformat() < f["remediated_at"] <= end.isoformat())
        out.append(point)
    return out


def aging(data: Data, source=None):
    buckets = [("0–30 days", 0, 30), ("31–60 days", 31, 60), ("61–90 days", 61, 90), ("90+ days", 91, 10_000)]
    open_f = [f for f in data.findings if (source is None or f["source"] == source) and is_open(f, data.today)]
    out = []
    for label, lo, hi in buckets:
        row = {"bucket": label}
        for s in SEVS:
            row[s] = sum(1 for f in open_f if f["severity"] == s and lo <= (data.today - date.fromisoformat(f["first_seen"])).days <= hi)
        out.append(row)
    return out


def top_assets(data: Data, source=None, limit=10):
    scores = {}
    for f in data.findings:
        if (source is None or f["source"] == source) and is_open(f, data.today):
            s = scores.setdefault(f["asset_id"], {"risk": 0, **{k: 0 for k in SEVS}})
            s["risk"] += SEV_WEIGHT[f["severity"]] * data.assets[f["asset_id"]]["criticality"]
            s[f["severity"]] += 1
    ranked = sorted(scores.items(), key=lambda kv: -kv[1]["risk"])[:limit]
    return [{**{k: data.assets[aid][k] for k in ("id", "hostname", "os", "business_unit", "criticality", "internet_facing", "owner")}, **s}
            for aid, s in ranked]


def by_source(data: Data):
    out = []
    for src in ("qualys", "crowdstrike", "wiz"):
        m = vuln_metrics(data, source=src)
        out.append({"source": src, **m["by_severity"], "total": m["open_total"], "overdue": m["crit_high_overdue"]})
    return out


# --------------------------------------------------------------------------- coverage
def coverage(data: Data):
    managed = [a for a in data.assets.values() if a["asset_type"] != "network"]
    edr = {s: sum(1 for a in managed if a["edr_status"] == s) for s in ("normal", "rfm", "missing")}
    cutoff = (data.today - timedelta(days=30)).isoformat()
    scanned = sum(1 for a in data.assets.values() if a["last_scanned"] and a["last_scanned"] >= cutoff)
    return {"edr": edr, "edr_coverage": _pct(edr["normal"], len(managed)), "managed_hosts": len(managed),
            "scan_coverage": _pct(scanned, len(data.assets)), "scanned_30d": scanned, "total_assets": len(data.assets)}


# --------------------------------------------------------------------------- alerts
def alert_metrics(data: Data, days=30, as_of=None, source=None):
    as_of = as_of or data.now
    start = as_of - timedelta(days=days)
    al = [a for a in data.alerts if (source is None or a["source"] == source) and a["_det"] and start < a["_det"] <= as_of]
    open_now = [a for a in data.alerts if (source is None or a["source"] == source) and a["_det"] and a["_det"] <= as_of
                and (a["_res"] is None or a["_res"] > as_of)]
    mttd = [(a["_det"] - a["_occ"]).total_seconds() / 60 for a in al if a["_occ"]]
    mttr = {}
    for s in SEVS:
        hrs = [(a["_res"] - a["_det"]).total_seconds() / 3600 for a in al if a["severity"] == s and a["_res"] and a["_res"] <= as_of
               and a["status"] != "false_positive"]
        mttr[s] = round(mean(hrs), 1) if hrs else None
    closed = [a for a in al if a["status"] in ("resolved", "false_positive")]
    return {
        "total": len(al), "by_severity": {s: sum(1 for a in al if a["severity"] == s) for s in SEVS},
        "by_status": {s: sum(1 for a in al if a["status"] == s) for s in ("new", "investigating", "resolved", "false_positive")},
        "open_total": len(open_now), "open_crit_high": sum(1 for a in open_now if a["severity"] in ("critical", "high")),
        "open_critical": sum(1 for a in open_now if a["severity"] == "critical"),
        "incidents": sum(a["is_incident"] for a in al), "mttd_minutes": round(median(mttd), 1) if mttd else None,
        "mttr_hours": mttr, "false_positive_rate": _pct(sum(1 for a in closed if a["status"] == "false_positive"), len(closed)),
    }


def alerts_by_platform(data: Data, days=30):
    out = []
    for src in ("crowdstrike", "expel", "wiz", "qualys"):
        m = alert_metrics(data, days, source=src)
        out.append({"source": src, **m["by_severity"], "total": m["total"], "open": m["open_total"]})
    return out


# --------------------------------------------------------------------------- third-party risk
def vendor_risk(v):
    """0-100 risk from external ratings (Bitsight 250-900, SecurityScorecard 0-100)."""
    return round(0.5 * (900 - v["bitsight_rating"]) / 6.5 + 0.5 * (100 - v["ssc_score"]), 1)


def ssc_grade(score):
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"


def bitsight_band(rating):
    return "Advanced" if rating >= 740 else "Intermediate" if rating >= 640 else "Basic"


def third_party(data: Data):
    today = data.today.isoformat()
    soon = (data.today + timedelta(days=60)).isoformat()
    vendors = []
    for v in data.vendors:
        bs_change = v["bitsight_history"][-1] - v["bitsight_history"][-4] if len(v["bitsight_history"]) >= 4 else 0
        reasons = []
        if v["bitsight_rating"] < 640:
            reasons.append("Bitsight rating in Basic range")
        if v["ssc_score"] < 70:
            reasons.append(f"SecurityScorecard grade {ssc_grade(v['ssc_score'])}")
        if bs_change <= -30:
            reasons.append(f"Bitsight down {abs(bs_change)} pts in 90 days")
        if v["next_assessment"] < today:
            reasons.append("Assessment overdue")
        vendors.append({k: v[k] for k in ("id", "name", "category", "tier", "data_access", "bitsight_rating", "ssc_score",
                                          "last_assessment", "next_assessment", "open_issues")}
                       | {"ssc_grade": ssc_grade(v["ssc_score"]), "bitsight_band": bitsight_band(v["bitsight_rating"]),
                          "bitsight_change_90d": bs_change, "risk": vendor_risk(v), "reasons": reasons,
                          "assessment_status": "overdue" if v["next_assessment"] < today else "due_soon" if v["next_assessment"] <= soon else "current"})
    vendors.sort(key=lambda v: (-len(v["reasons"]), -v["risk"]))
    months = len(data.vendors[0]["bitsight_history"]) if data.vendors else 0
    trend = [{"month": i, "bitsight": round(mean(v["bitsight_history"][i] for v in data.vendors)),
              "ssc": round(mean(v["ssc_history"][i] for v in data.vendors), 1)} for i in range(months)]
    tier1 = [v for v in data.vendors if v["tier"] == 1]
    return {
        "vendor_count": len(vendors), "avg_bitsight": round(mean(v["bitsight_rating"] for v in data.vendors)) if vendors else None,
        "avg_ssc": round(mean(v["ssc_score"] for v in data.vendors), 1) if vendors else None,
        "tier1_avg_ssc": round(mean(v["ssc_score"] for v in tier1), 1) if tier1 else None,
        "needs_attention": sum(1 for v in vendors if v["reasons"]), "overdue_assessments": sum(1 for v in vendors if v["assessment_status"] == "overdue"),
        "due_soon": sum(1 for v in vendors if v["assessment_status"] == "due_soon"), "vendors": vendors, "trend": trend,
    }


# --------------------------------------------------------------------------- compliance
def auto_rule_status(rule, ctx):
    value, good, ok, unit, higher = {
        "edr_coverage": (ctx["coverage"]["edr_coverage"], 95, 85, "% EDR coverage", True),
        "scan_coverage": (ctx["coverage"]["scan_coverage"], 95, 85, "% assets scanned in 30 days", True),
        "vuln_sla": (ctx["vulns"]["sla_compliance"], 90, 70, "% critical/high within SLA", True),
        "vendor_assessments": (100 - _pct(ctx["tprm"]["overdue_assessments"], ctx["tprm"]["vendor_count"]), 95, 80, "% vendor assessments current", True),
        "incident_response": (ctx["alerts"]["mttr_hours"]["critical"] or 0, 4, 12, "h critical alert MTTR", False),
        "cloud_config": (ctx["cloud_critical_open"], 0, 5, " open critical cloud issues", False),
    }[rule]
    if higher:
        status = "implemented" if value >= good else "partial" if value >= ok else "not_implemented"
    else:
        status = "implemented" if value <= good else "partial" if value <= ok else "not_implemented"
    return status, f"{value:g}{unit}"


def compliance(data: Data, ctx):
    controls, frameworks = [], {}
    for c in data.controls:
        c = dict(c)
        if c["auto_rule"]:
            c["status"], c["evidence"] = auto_rule_status(c["auto_rule"], ctx)
        controls.append(c)
        fw = frameworks.setdefault(c["framework"], {"framework": c["framework"], "total": 0, "implemented": 0, "partial": 0, "not_implemented": 0, "families": {}})
        fw["total"] += 1
        fw[c["status"]] += 1
        fam = fw["families"].setdefault(c["family"], {"family": c["family"], "total": 0, "score": 0})
        fam["total"] += 1
        fam["score"] += 1 if c["status"] == "implemented" else 0.5 if c["status"] == "partial" else 0
    for fw in frameworks.values():
        fw["pct"] = _pct(fw["implemented"] + 0.5 * fw["partial"], fw["total"])
        fw["families"] = [{"family": f["family"], "pct": _pct(f["score"], f["total"]), "total": f["total"]} for f in fw["families"].values()]
    return list(frameworks.values()), controls


# --------------------------------------------------------------------------- enterprise risk score
COMPONENTS = [
    ("vulnerability", "Vulnerability exposure", 0.25),
    ("threat", "Active threat exposure", 0.20),
    ("detection", "Detection & response", 0.20),
    ("third_party", "Third-party risk", 0.15),
    ("coverage", "Security tool coverage", 0.10),
    ("compliance", "Compliance gaps", 0.10),
]


def risk_score(data: Data, as_of: date = None, ctx=None):
    """Enterprise risk 0-100 (higher = more risk). Each component is scored
    0-100 with a documented formula, then combined with fixed weights."""
    as_of = as_of or data.today
    as_of_dt = datetime.combine(as_of, datetime.max.time(), timezone.utc) if as_of < data.today else data.now
    v = vuln_metrics(data, as_of)
    density = 100 * v["by_severity"]["critical"] / max(1, len(data.assets))
    vuln_r = 0.6 * (100 - v["sla_compliance"]) + 0.4 * min(100, density * 10)

    open_f = [f for f in data.findings if f["cve"] in data.kev and data.kev[f["cve"]]["date_added"] <= as_of.isoformat() and is_open(f, as_of)]
    kev_cves = {f["cve"] for f in open_f}
    kev_internet = {f["asset_id"] for f in open_f if data.assets[f["asset_id"]]["internet_facing"]}
    threat_r = min(100, 2.5 * len(kev_cves) + 4 * len(kev_internet))

    am = alert_metrics(data, 30, as_of_dt)
    crit_mttr = am["mttr_hours"]["critical"] or 0
    det_r = 0.5 * min(100, 8 * am["open_critical"] + 3 * (am["open_crit_high"] - am["open_critical"])) + 0.5 * min(100, crit_mttr / 4 * 40)

    months_back = min(11, (data.today - as_of).days // 30)
    weights = {1: 3, 2: 2, 3: 1}
    tp_total = sum(weights[x["tier"]] for x in data.vendors) or 1
    tp_r = sum(weights[x["tier"]] * vendor_risk({"bitsight_rating": x["bitsight_history"][-1 - months_back],
                                                    "ssc_score": x["ssc_history"][-1 - months_back]}) for x in data.vendors) / tp_total

    cov = ctx["coverage"] if ctx else coverage(data)
    cov_r = min(100, 3 * (100 - cov["edr_coverage"]) + 2 * (100 - cov["scan_coverage"]))
    comp_r = 100 - mean(f["pct"] for f in ctx["frameworks"]) if ctx else 30

    details = {
        "vulnerability": (vuln_r, f"{v['crit_high_overdue']} of {v['crit_high_open']} critical/high findings past SLA; {v['by_severity']['critical']} critical open"),
        "threat": (threat_r, f"{len(kev_cves)} actively exploited (KEV) CVEs open on {len(kev_internet)} internet-facing assets"),
        "detection": (det_r, f"{am['open_crit_high']} critical/high alerts open; critical MTTR {crit_mttr:g}h vs 4h target"),
        "third_party": (tp_r, "Tier-weighted Bitsight + SecurityScorecard ratings"),
        "coverage": (cov_r, f"EDR {cov['edr_coverage']}% · scan coverage {cov['scan_coverage']}%"),
        "compliance": (comp_r, "Average implementation gap across frameworks"),
    }
    comps = []
    for key, label, w in COMPONENTS:
        r, detail = details[key]
        comps.append({"key": key, "label": label, "weight": w, "risk": round(r, 1), "contribution": round(r * w, 1), "detail": detail})
    score = round(sum(c["contribution"] for c in comps), 1)
    return {"score": score, "rating": rating(score), "components": comps}


def rating(score):
    return "Critical" if score >= 75 else "High" if score >= 55 else "Elevated" if score >= 35 else "Low"


def risk_history(data: Data, ctx, weeks=13):
    return [{"date": (data.today - timedelta(days=7 * w)).isoformat(),
             "score": risk_score(data, data.today - timedelta(days=7 * w), ctx)["score"]} for w in range(weeks - 1, -1, -1)]


def context(data: Data):
    """Shared metric bundle used by summary, compliance, goals, and the report."""
    ctx = {"coverage": coverage(data), "vulns": vuln_metrics(data), "alerts": alert_metrics(data, 30), "tprm": third_party(data),
           "cloud_critical_open": sum(1 for c in data.cloud if c["status"] == "open" and c["severity"] == "critical")}
    ctx["frameworks"], ctx["controls"] = compliance(data, ctx)
    return ctx


GOAL_METRICS = {
    "crit_mttr_days": ("Critical vuln MTTR", "days", lambda ctx: ctx["vulns"]["mttr_days"]["critical"]),
    "edr_coverage": ("EDR coverage", "%", lambda ctx: ctx["coverage"]["edr_coverage"]),
    "kev_open": ("Open KEV CVEs", "CVEs", lambda ctx: ctx["vulns"]["kev_open"]),
    "alert_mttr_hours": ("Critical alert MTTR", "hours", lambda ctx: ctx["alerts"]["mttr_hours"]["critical"]),
    "vendor_ssc_tier1": ("Tier-1 vendor SSC avg", "pts", lambda ctx: ctx["tprm"]["tier1_avg_ssc"]),
    "compliance_nist": ("NIST CSF implementation", "%", lambda ctx: next((f["pct"] for f in ctx["frameworks"] if f["framework"].startswith("NIST")), None)),
}


def goal_progress(goal, ctx):
    label, unit, fn = GOAL_METRICS[goal["metric_key"]]
    current = fn(ctx)
    if current is None:
        return {**goal, "current": None, "progress": 0, "on_track": False, "unit": unit, "metric_label": label}
    span = goal["baseline"] - goal["target"] if goal["direction"] == "lower" else goal["target"] - goal["baseline"]
    moved = goal["baseline"] - current if goal["direction"] == "lower" else current - goal["baseline"]
    progress = max(0.0, min(1.0, moved / span)) if span else 1.0
    met = current <= goal["target"] if goal["direction"] == "lower" else current >= goal["target"]
    return {**goal, "current": round(current, 1), "progress": round(progress * 100), "met": met, "unit": unit, "metric_label": label}
