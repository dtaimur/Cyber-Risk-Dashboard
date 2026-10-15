"""Metric catalog: one self-describing definition per dashboard metric.

Every KPI on the dashboard can be opened to show what is affected, what the
metric means, why it matters, where the data comes from, and exactly how it is
calculated (including the live inputs to the formula). Each definition also
returns an optional weekly trend and categorical breakdowns so the frontend can
render the same metric as a number, a line chart, or a bar chart.

Values come from the same functions in metrics.py that the pages use, so a
number on a card always matches its detail view.
"""
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from functools import cached_property
from statistics import mean, median

from . import metrics, threat_intel
from .catalog import SLA_DAYS
from .integrations import tool_modes
from .metrics import SEVS, Data, is_open

TOOL = {"qualys": "Qualys", "crowdstrike": "CrowdStrike", "expel": "Expel", "wiz": "Wiz", "jira": "Jira"}
SOURCE_DETAIL = {
    "qualys": "Qualys VMDR host detection API (vulnerability scans)",
    "crowdstrike": "CrowdStrike Falcon (sensor inventory, Spotlight vulnerabilities, detections)",
    "expel": "Expel Workbench (MDR alerts, investigations, incidents)",
    "wiz": "Wiz GraphQL API (cloud issues and workload vulnerabilities)",
    "jira": "Jira Cloud REST API (remediation tickets and workflow status)",
    "cisa_kev": "CISA Known Exploited Vulnerabilities catalog (live JSON feed)",
    "epss": "FIRST EPSS API (exploit probability, live)",
    "news": "Security news RSS feeds (SecurityWeek, The Hacker News, BleepingComputer, Dark Reading)",
    "bitsight": "Bitsight security ratings (vendor risk)",
    "ssc": "SecurityScorecard ratings (vendor risk)",
    "grc": "Control attestations maintained by GRC control owners",
    "roadmap": "Third-party risk assessment schedule",
}
WEEKS = 13
ROW_LIMIT = 250


@dataclass
class Metric:
    key: str
    label: str
    unit: str
    better: str           # "lower" | "higher"
    description: str
    why: str
    calculation: str
    fn: callable
    trend: bool = True    # has a weekly/monthly history -> line chart view
    bars: bool = True     # has categorical breakdowns -> bar chart view
    pie: bool = False     # has a part-of-whole breakdown (marked "pie": True) -> pie chart view


REGISTRY: dict[str, Metric] = {}


def metric(key, label, unit="", better="lower", description="", why="", calculation="", trend=True, bars=True, pie=False):
    def deco(fn):
        REGISTRY[key] = Metric(key, label, unit, better, description, why, calculation, fn, trend, bars, pie)
        return fn
    return deco


class Env:
    """Per-request inputs shared by metric functions."""

    def __init__(self, conn, params):
        self.conn = conn
        self.data = Data(conn)
        self.source = params.get("source") or None
        self.days = int(params.get("days") or 30)
        self.filter = params.get("filter") or "all"
        self.framework = params.get("framework")
        self.modes = tool_modes()

    @cached_property
    def ctx(self):
        return metrics.context(self.data)

    @cached_property
    def threats(self):
        return threat_intel.active_threats(self.conn)

    def findings(self, open_only=True, source="__env__"):
        src = self.source if source == "__env__" else source
        return [f for f in self.data.findings if (src is None or f["source"] == src)
                and (not open_only or is_open(f, self.data.today))]

    def alerts(self, as_of=None, days=None):
        as_of = as_of or self.data.now
        start = as_of - timedelta(days=days or self.days)
        return [a for a in self.data.alerts if (self.source is None or a["source"] == self.source)
                and a["_det"] and start < a["_det"] <= as_of]

    def scope(self, noun):
        return f"{noun} reported by {TOOL[self.source]}" if self.source else f"{noun} across all connected tools"

    def tool_sources(self, tools):
        return [src(t) for t in tools if self.source is None or t == self.source]


def src(key, kind=None, modes=None):
    if key in TOOL:
        mode = (modes or tool_modes()).get(key, "mock")
        return {"name": TOOL[key], "detail": SOURCE_DETAIL[key], "mode": mode}
    live = key in ("cisa_kev", "epss", "news")
    return {"name": {"cisa_kev": "CISA KEV", "epss": "FIRST EPSS", "news": "Security news", "bitsight": "Bitsight",
                     "ssc": "SecurityScorecard", "grc": "GRC attestations", "roadmap": "Assessment schedule"}[key],
            "detail": SOURCE_DETAIL[key], "mode": "live" if live else ("manual" if key in ("grc", "roadmap") else "mock")}


# --------------------------------------------------------------------------- shaping helpers
def weekly(data, fn):
    return [{"date": (data.today - timedelta(days=7 * w)).isoformat(), "value": fn(w)} for w in range(WEEKS - 1, -1, -1)]


def week_end_dt(data, w):
    return data.now if w == 0 else datetime.combine(data.today - timedelta(days=7 * w), datetime.max.time(), timezone.utc)


def count_by(items, keyfn, order=None, limit=12):
    c = Counter(k for k in (keyfn(i) for i in items) if k is not None)
    keys = [k for k in order if c.get(k)] if order else [k for k, _ in c.most_common(limit)]
    return [{"label": str(k), "value": c[k]} for k in keys]


def avg_by(items, keyfn, valfn, digits=1):
    groups = defaultdict(list)
    for i in items:
        v = valfn(i)
        if v is not None:
            groups[keyfn(i)].append(v)
    return sorted([{"label": str(k), "value": round(mean(v), digits)} for k, v in groups.items()], key=lambda x: -x["value"])


def table(columns, rows_, total=None):
    return {"columns": [{"key": k, "label": l, "type": t} for k, l, t in columns], "rows": rows_[:ROW_LIMIT],
            "total": len(rows_) if total is None else total}


FINDING_COLS = [("severity", "Severity", "severity"), ("title", "Finding", "text"), ("cve", "CVE", "mono"),
                ("hostname", "Asset", "asset"), ("source", "Tool", "tool"), ("cvss", "CVSS", "num"),
                ("first_seen", "First seen", "date"), ("due_date", "SLA due", "due"), ("owner_team", "Owner", "text")]


def finding_rows(env, fs, extra=None):
    kev = env.data.kev
    order = {s: i for i, s in enumerate(SEVS)}
    out = []
    for f in sorted(fs, key=lambda f: (order[f["severity"]], -(f["cvss"] or 0), f["first_seen"])):
        a = env.data.assets.get(f["asset_id"], {})
        row = {**{k: f[k] for k in ("severity", "title", "cve", "source", "cvss", "first_seen", "due_date", "owner_team", "status", "remediated_at")},
               "hostname": a.get("hostname"), "asset_id": f["asset_id"], "in_kev": f["cve"] in kev,
               "internet_facing": a.get("internet_facing"), "business_unit": a.get("business_unit")}
        if extra:
            row.update(extra(f))
        out.append(row)
    return out


ASSET_COLS = [("hostname", "Asset", "asset"), ("os", "OS", "text"), ("environment", "Environment", "upper"),
              ("business_unit", "Business unit", "text"), ("criticality", "Criticality", "num"), ("owner", "Owner", "text")]


def asset_rows(assets, extra=None):
    out = []
    for a in sorted(assets, key=lambda a: (-(a["criticality"] or 0), a["hostname"])):
        row = {k: a[k] for k in ("hostname", "os", "environment", "business_unit", "criticality", "owner", "internet_facing",
                                 "edr_status", "last_scanned", "asset_type")}
        row["asset_id"] = a["id"]
        if extra:
            row.update(extra(a))
        out.append(row)
    return out


ALERT_COLS = [("severity", "Severity", "severity"), ("title", "Alert", "text"), ("source", "Source", "tool"),
              ("tactic", "Tactic", "text"), ("hostname", "Host", "asset"), ("user_name", "User", "text"),
              ("status", "Status", "status"), ("detected_at", "Detected", "datetime")]


def alert_rows(env, al, extra=None):
    out = []
    for a in sorted(al, key=lambda a: a["detected_at"] or "", reverse=True):
        asset = env.data.assets.get(a["asset_id"], {})
        row = {k: a[k] for k in ("severity", "title", "source", "tactic", "technique", "user_name", "status", "detected_at", "is_incident")}
        row.update({"hostname": asset.get("hostname"), "asset_id": a["asset_id"]})
        if extra:
            row.update(extra(a))
        out.append(row)
    return out


VENDOR_COLS = [("name", "Vendor", "text"), ("tier", "Tier", "num"), ("data_access", "Data access", "text"),
               ("bitsight_rating", "Bitsight", "num"), ("ssc_score", "SSC", "num"), ("next_assessment", "Next assessment", "date"),
               ("reasons", "Flags", "text")]


def vendor_rows(vs):
    return [{**{k: v[k] for k in ("name", "tier", "data_access", "bitsight_rating", "ssc_score", "next_assessment", "assessment_status", "risk")},
             "reasons": "; ".join(v["reasons"]) or "—"} for v in vs]


CLOUD_COLS = [("severity", "Severity", "severity"), ("rule", "Issue", "text"), ("resource", "Resource", "mono"),
              ("cloud", "Cloud", "upper"), ("category", "Category", "label"), ("created_at", "Opened", "date")]


# =========================================================================== vulnerability metrics
VULN_SOURCES = ("qualys", "crowdstrike", "wiz")
SEV_RULE = "Severity comes from the CVSS v3 base score: ≥ 9.0 critical, 7.0–8.9 high, 4.0–6.9 medium, < 4.0 low (Qualys severity 5/4/3/2 maps the same way)."


def vuln_breakdowns(env, fs):
    b = [{"by": "Severity", "kind": "severity", "pie": True, "data": count_by(fs, lambda f: f["severity"], SEVS)}]
    if not env.source:
        b.append({"by": "Tool", "kind": "tool", "pie": True, "data": count_by(fs, lambda f: TOOL[f["source"]])})
    b.append({"by": "Business unit", "kind": "category", "data": count_by(fs, lambda f: env.data.assets[f["asset_id"]]["business_unit"])})
    b.append({"by": "Owner team", "kind": "category", "data": count_by(fs, lambda f: f["owner_team"])})
    return b


@metric("open_findings", "Open vulnerabilities", pie=True,
        description="The number of vulnerability findings that are currently open or being remediated.",
        why="This is the overall size of our exposure. On its own the number matters less than its direction: if new findings arrive faster than they are fixed, the backlog — and the attack surface — keeps growing.",
        calculation="Count of findings whose status is open or in progress. A finding counts as open from the day it was first detected until the day it was remediated. Findings formally risk-accepted are excluded. " + SEV_RULE)
def _open_findings(env):
    fs = env.findings()
    return {"value": len(fs), "items": table(FINDING_COLS, finding_rows(env, fs)), "items_label": "Open findings, most severe first",
            "series": weekly(env.data, lambda w: metrics.vuln_metrics(env.data, env.data.today - timedelta(days=7 * w), env.source)["open_total"]),
            "breakdowns": vuln_breakdowns(env, fs),
            "inputs": {"Open": sum(f["status"] == "open" for f in fs), "In progress": sum(f["status"] == "in_progress" for f in fs),
                       "Affected assets": len({f["asset_id"] for f in fs})},
            "sources": env.tool_sources(VULN_SOURCES)}


@metric("open_critical", "Open critical vulnerabilities", pie=True,
        description="Open findings rated critical (CVSS 9.0 or higher).",
        why="Critical vulnerabilities usually allow an attacker to take over a system remotely, often without credentials. They are where most breaches start, so leadership tracks this number specifically.",
        calculation="Count of open or in-progress findings with severity = critical. " + SEV_RULE)
def _open_critical(env):
    fs = [f for f in env.findings() if f["severity"] == "critical"]
    b = vuln_breakdowns(env, fs)[1:]
    b.insert(0, {"by": "Product", "kind": "category", "data": count_by(fs, lambda f: f["product"] or "Configuration")})
    return {"value": len(fs), "items": table(FINDING_COLS, finding_rows(env, fs)),
            "series": weekly(env.data, lambda w: metrics.vuln_metrics(env.data, env.data.today - timedelta(days=7 * w), env.source)["by_severity"]["critical"]),
            "breakdowns": b, "inputs": {"Critical findings": len(fs), "Assets affected": len({f["asset_id"] for f in fs}),
                                        "Internet-facing assets": len({f["asset_id"] for f in fs if env.data.assets[f["asset_id"]]["internet_facing"]})},
            "sources": env.tool_sources(VULN_SOURCES)}


@metric("kev_open", "Actively exploited CVEs open",
        description="Distinct CVEs open in our environment that appear on CISA's Known Exploited Vulnerabilities (KEV) catalog.",
        why="KEV only lists vulnerabilities with confirmed real-world exploitation. These are the flaws attackers are using right now, so they should be fixed before anything else — US federal agencies are required to patch them by a set deadline.",
        calculation="Join of open scanner findings (by CVE ID) against the live CISA KEV feed. Counted once per CVE regardless of how many assets have it. KEV is refreshed from cisa.gov on startup and on demand.")
def _kev_open(env):
    fs = [f for f in env.findings() if f["cve"] in env.data.kev]
    kev = env.data.kev
    rows_ = finding_rows(env, fs, lambda f: {"kev_added": kev[f["cve"]]["date_added"], "ransomware": kev[f["cve"]]["ransomware"] == "Known"})
    cols = FINDING_COLS[:5] + [("kev_added", "Added to KEV", "date"), ("due_date", "SLA due", "due")]
    return {"value": len({f["cve"] for f in fs}), "items": table(cols, rows_),
            "series": weekly(env.data, lambda w: metrics.vuln_metrics(env.data, env.data.today - timedelta(days=7 * w), env.source)["kev_open"]),
            "breakdowns": [{"by": "Product", "kind": "category", "data": count_by({f["cve"]: f for f in fs}.values(), lambda f: f["product"] or "Other")},
                           {"by": "Affected assets per tool", "kind": "tool", "data": count_by(fs, lambda f: TOOL[f["source"]])},
                           {"by": "Severity", "kind": "severity", "data": count_by({f["cve"]: f for f in fs}.values(), lambda f: f["severity"], SEVS)}],
            "inputs": {"Distinct KEV CVEs": len({f["cve"] for f in fs}), "Findings (CVE × asset)": len(fs),
                       "Ransomware-linked CVEs": len({f["cve"] for f in fs if kev[f["cve"]]["ransomware"] == "Known"}),
                       "KEV catalog size": len(kev)},
            "sources": env.tool_sources(VULN_SOURCES) + [src("cisa_kev")]}


@metric("sla_compliance", "Critical/high within SLA", unit="%", better="higher",
        description="The share of open critical and high vulnerabilities that are still inside their remediation deadline.",
        why="Remediation SLAs are the commitment we make to auditors, customers, and the board about how fast serious risk is closed. Past-due items are the most common audit finding (ISO 27001 A.8.8, SOC 2 CC7.1) and represent exposure we agreed not to tolerate.",
        calculation=f"SLA deadlines from first detection: critical {SLA_DAYS['critical']} days, high {SLA_DAYS['high']} days, medium {SLA_DAYS['medium']} days, low {SLA_DAYS['low']} days. "
                    "Value = 100 × (1 − past-due critical/high ÷ all open critical/high). The table lists the past-due items pulling the number down.")
def _sla(env):
    open_ch = [f for f in env.findings() if f["severity"] in ("critical", "high")]
    overdue = [f for f in open_ch if f["due_date"] < env.data.today.isoformat()]
    m = metrics.vuln_metrics(env.data, source=env.source)
    rows_ = finding_rows(env, overdue, lambda f: {"days_overdue": (env.data.today - date.fromisoformat(f["due_date"])).days})
    return {"value": m["sla_compliance"], "items": table(FINDING_COLS[:6] + [("due_date", "SLA due", "due"), ("days_overdue", "Days overdue", "num"), ("owner_team", "Owner", "text")], rows_),
            "items_label": "Past-due critical/high findings",
            "series": weekly(env.data, lambda w: metrics.vuln_metrics(env.data, env.data.today - timedelta(days=7 * w), env.source)["sla_compliance"]),
            "breakdowns": [{"by": "Past-due by owner team", "kind": "category", "data": count_by(overdue, lambda f: f["owner_team"])},
                           {"by": "Past-due by severity", "kind": "severity", "data": count_by(overdue, lambda f: f["severity"], SEVS)},
                           {"by": "Past-due by business unit", "kind": "category", "data": count_by(overdue, lambda f: env.data.assets[f["asset_id"]]["business_unit"])}],
            "inputs": {"Open critical/high": len(open_ch), "Past due": len(overdue), "Within SLA": len(open_ch) - len(overdue)},
            "sources": env.tool_sources(VULN_SOURCES)}


def _remediated(env, sevs, days=90, as_of=None):
    as_of = as_of or env.data.today
    lo = (as_of - timedelta(days=days)).isoformat()
    return [f for f in env.findings(open_only=False) if f["remediated_at"] and lo <= f["remediated_at"] <= as_of.isoformat() and f["severity"] in sevs]


def _fix_days(f):
    return (date.fromisoformat(f["remediated_at"]) - date.fromisoformat(f["first_seen"])).days


@metric("crit_mttr_days", "Critical vulnerability MTTR", unit=" days",
        description="Mean time to remediate: the average number of days between first detecting a critical vulnerability and fixing it.",
        why="Speed of remediation directly controls how long an attacker has to exploit a flaw. Exploits for critical vulnerabilities often appear within days of disclosure, so our target is 15 days or less.",
        calculation="For every critical finding remediated in the last 90 days: days = remediated date − first detected date. Value = average of those days. Target ≤ 15 days.")
def _crit_mttr(env):
    fs = _remediated(env, ("critical",))
    rows_ = finding_rows(env, fs, lambda f: {"days_to_fix": _fix_days(f)})
    rows_.sort(key=lambda r: -r["days_to_fix"])
    m = metrics.vuln_metrics(env.data, source=env.source)

    def at(w):
        sub = _remediated(env, ("critical",), as_of=env.data.today - timedelta(days=7 * w))
        return round(mean(_fix_days(f) for f in sub), 1) if sub else None
    return {"value": m["mttr_days"]["critical"], "items": table([("severity", "Severity", "severity"), ("title", "Finding", "text"), ("hostname", "Asset", "asset"),
                                                                ("source", "Tool", "tool"), ("first_seen", "Detected", "date"), ("remediated_at", "Fixed", "date"),
                                                                ("days_to_fix", "Days to fix", "num"), ("owner_team", "Owner", "text")], rows_),
            "items_label": "Critical findings remediated in the last 90 days", "series": weekly(env.data, at),
            "breakdowns": [{"by": "Average days by owner team", "kind": "category", "data": avg_by(fs, lambda f: f["owner_team"], _fix_days)},
                           {"by": "Average days by tool", "kind": "tool", "data": avg_by(fs, lambda f: TOOL[f["source"]], _fix_days)}],
            "inputs": {"Criticals remediated (90d)": len(fs), "Fixed within 15 days": sum(_fix_days(f) <= 15 for f in fs),
                       "Slowest fix (days)": max((_fix_days(f) for f in fs), default=0)},
            "sources": env.tool_sources(VULN_SOURCES)}


@metric("fixed_on_time", "Fixed on time (90 days)", unit="%", better="higher",
        description="Of the critical and high vulnerabilities fixed in the last 90 days, the share fixed before their SLA deadline.",
        why="Shows whether the remediation process is actually meeting its commitments, not just closing tickets eventually. A low number means risk stayed open longer than policy allows.",
        calculation="100 × (critical/high findings remediated on or before their due date ÷ all critical/high findings remediated in the last 90 days). The table lists the late fixes.")
def _on_time(env):
    fs = _remediated(env, ("critical", "high"))
    late = [f for f in fs if f["remediated_at"] > f["due_date"]]

    def at(w):
        sub = _remediated(env, ("critical", "high"), as_of=env.data.today - timedelta(days=7 * w))
        return metrics._pct(sum(f["remediated_at"] <= f["due_date"] for f in sub), len(sub)) if sub else None
    rows_ = finding_rows(env, late, lambda f: {"days_late": (date.fromisoformat(f["remediated_at"]) - date.fromisoformat(f["due_date"])).days})
    return {"value": metrics._pct(len(fs) - len(late), len(fs)),
            "items": table([("severity", "Severity", "severity"), ("title", "Finding", "text"), ("hostname", "Asset", "asset"), ("due_date", "Due", "date"),
                            ("remediated_at", "Fixed", "date"), ("days_late", "Days late", "num"), ("owner_team", "Owner", "text")], rows_),
            "items_label": "Fixes that missed their deadline", "series": weekly(env.data, at),
            "breakdowns": [{"by": "Late fixes by owner team", "kind": "category", "data": count_by(late, lambda f: f["owner_team"])},
                           {"by": "Late fixes by severity", "kind": "severity", "data": count_by(late, lambda f: f["severity"], SEVS)}],
            "inputs": {"Remediated (90d)": len(fs), "On time": len(fs) - len(late), "Late": len(late)},
            "sources": env.tool_sources(VULN_SOURCES)}


@metric("patchable_pct", "Patch available", trend=False, unit="%", better="higher",
        description="The share of open findings for which the vendor has released a fix.",
        why="Patchable findings can be closed with routine maintenance. Findings with no patch need compensating controls (isolation, configuration changes, monitoring) and should be tracked as accepted risk.",
        calculation="100 × (open findings where the scanner reports a vendor patch ÷ all open findings). The table lists findings with no patch available.")
def _patchable(env):
    fs = env.findings()
    nopatch = [f for f in fs if not f["patch_available"]]
    return {"value": metrics._pct(len(fs) - len(nopatch), len(fs)), "items": table(FINDING_COLS, finding_rows(env, nopatch)),
            "items_label": "Open findings with no vendor patch",
            "breakdowns": [{"by": "No patch, by severity", "kind": "severity", "data": count_by(nopatch, lambda f: f["severity"], SEVS)}],
            "inputs": {"Open findings": len(fs), "Patch available": len(fs) - len(nopatch), "No patch": len(nopatch)},
            "sources": env.tool_sources(VULN_SOURCES)}


@metric("avg_qds", "Average Qualys Detection Score", better="lower",
        description="Average Qualys Detection Score (QDS, 1–100) across open Qualys detections.",
        why="QDS is Qualys's risk-based score: it adjusts CVSS with threat intelligence such as active exploitation and malware use. A rising average means the open backlog is getting more dangerous even if the count is flat.",
        calculation="Mean of the QDS value Qualys reports for each open detection. QDS bands: 90–100 critical, 70–89 high, 40–69 medium, 1–39 low.")
def _qds(env):
    env.source = "qualys"
    fs = [f for f in env.findings() if f["vendor_score"]]
    band = lambda s: "90–100" if s >= 90 else "70–89" if s >= 70 else "40–69" if s >= 40 else "1–39"

    def at(w):
        d = env.data.today - timedelta(days=7 * w)
        sub = [f["vendor_score"] for f in env.data.findings if f["source"] == "qualys" and f["vendor_score"] and is_open(f, d)]
        return round(mean(sub), 1) if sub else None
    rows_ = finding_rows(env, sorted(fs, key=lambda f: -f["vendor_score"]), lambda f: {"qds": f["vendor_score"]})
    rows_.sort(key=lambda r: -r["qds"])
    return {"value": round(mean(f["vendor_score"] for f in fs), 1) if fs else None,
            "items": table([("qds", "QDS", "num")] + FINDING_COLS[:5], rows_), "series": weekly(env.data, at),
            "breakdowns": [{"by": "QDS band", "kind": "category", "data": count_by(fs, lambda f: band(f["vendor_score"]), ["90–100", "70–89", "40–69", "1–39"])}],
            "inputs": {"Detections with QDS": len(fs), "QDS ≥ 70": sum(f["vendor_score"] >= 70 for f in fs)},
            "sources": [src("qualys")]}


# =========================================================================== coverage
@metric("scan_coverage", "Scan coverage (30 days)", trend=False, unit="%", better="higher",
        description="The share of known assets that received a vulnerability scan in the last 30 days.",
        why="Every metric about vulnerabilities assumes we are actually looking. Unscanned assets are blind spots: their vulnerabilities are not in any count, SLA, or report.",
        calculation="100 × (assets whose last Qualys scan date is within 30 days ÷ all assets in inventory). The table lists stale or never-scanned assets.")
def _scan_cov(env):
    cutoff = (env.data.today - timedelta(days=30)).isoformat()
    stale = [a for a in env.data.assets.values() if not a["last_scanned"] or a["last_scanned"] < cutoff]
    cov = metrics.coverage(env.data)
    return {"value": cov["scan_coverage"],
            "items": table(ASSET_COLS + [("last_scanned", "Last scanned", "date")], asset_rows(stale)), "items_label": "Assets not scanned in 30 days",
            "breakdowns": [{"by": "Unscanned by environment", "kind": "category", "data": count_by(stale, lambda a: a["environment"].upper())},
                           {"by": "Unscanned by asset type", "kind": "category", "data": count_by(stale, lambda a: a["asset_type"])}],
            "inputs": {"Total assets": cov["total_assets"], "Scanned in 30 days": cov["scanned_30d"], "Stale / never scanned": len(stale)},
            "sources": [src("qualys")]}


def _edr_gaps(env):
    return [a for a in env.data.assets.values() if a["asset_type"] != "network" and a["edr_status"] in ("missing", "rfm")]


EDR_COLS = ASSET_COLS + [("edr_status", "Sensor", "edr")]


@metric("edr_coverage", "EDR coverage", pie=True, trend=False, unit="%", better="higher",
        description="The share of managed hosts (servers, workstations, cloud workloads) running a healthy CrowdStrike Falcon sensor.",
        why="Endpoint detection and response is how we see and stop attacks on a machine. Ransomware operators deliberately target hosts without EDR, and incidents there take far longer to detect and investigate.",
        calculation="100 × (hosts whose Falcon sensor reports normal status ÷ all managed hosts). Network appliances are excluded because they cannot run a sensor. Hosts in reduced-functionality mode (RFM) count as not covered.")
def _edr(env):
    gaps = _edr_gaps(env)
    cov = metrics.coverage(env.data)
    return {"value": cov["edr_coverage"], "items": table(EDR_COLS, asset_rows(gaps)), "items_label": "Hosts without a healthy sensor",
            "breakdowns": [{"by": "Sensor status", "kind": "status", "pie": True, "data": [{"label": "Healthy", "value": cov["edr"]["normal"]},
                                                                                {"label": "Reduced functionality", "value": cov["edr"]["rfm"]},
                                                                                {"label": "No sensor", "value": cov["edr"]["missing"]}]},
                           {"by": "Gaps by environment", "kind": "category", "data": count_by(gaps, lambda a: a["environment"].upper())},
                           {"by": "Gaps by business unit", "kind": "category", "data": count_by(gaps, lambda a: a["business_unit"])}],
            "inputs": {"Managed hosts": cov["managed_hosts"], "Healthy sensors": cov["edr"]["normal"], "Reduced functionality": cov["edr"]["rfm"], "No sensor": cov["edr"]["missing"]},
            "sources": [src("crowdstrike")]}


@metric("edr_missing", "Hosts without EDR sensor", trend=False,
        description="Managed hosts with no CrowdStrike Falcon sensor installed.",
        why="These hosts generate no endpoint telemetry and cannot be contained remotely during an incident.",
        calculation="Count of non-network assets in inventory with no Falcon sensor (agent never reported).")
def _edr_missing(env):
    miss = [a for a in env.data.assets.values() if a["asset_type"] != "network" and a["edr_status"] == "missing"]
    return {"value": len(miss), "items": table(EDR_COLS, asset_rows(miss)),
            "breakdowns": [{"by": "Environment", "kind": "category", "data": count_by(miss, lambda a: a["environment"].upper())},
                           {"by": "Asset type", "kind": "category", "data": count_by(miss, lambda a: a["asset_type"])}],
            "inputs": {"Hosts with no sensor": len(miss)}, "sources": [src("crowdstrike")]}


@metric("contained_hosts", "Hosts in containment", bars=False, trend=False,
        description="Hosts currently network-isolated by CrowdStrike Falcon.",
        why="Containment is the emergency brake during an incident. Contained hosts are cut off from the network (except the Falcon cloud) and usually indicate an active investigation.",
        calculation="Count of hosts whose Falcon device status is 'contained'.")
def _contained(env):
    c = [a for a in env.data.assets.values() if a["contained"]]
    return {"value": len(c), "items": table(ASSET_COLS, asset_rows(c)), "breakdowns": [], "inputs": {"Contained hosts": len(c)},
            "sources": [src("crowdstrike")]}


# =========================================================================== alerts
ALERT_TOOLS = ("crowdstrike", "expel", "wiz", "qualys")


def alert_breakdowns(env, al):
    b = [{"by": "Severity", "kind": "severity", "pie": True, "data": count_by(al, lambda a: a["severity"], SEVS)}]
    if not env.source:
        b.append({"by": "Source", "kind": "tool", "pie": True, "data": count_by(al, lambda a: TOOL[a["source"]])})
    b.append({"by": "MITRE ATT&CK tactic", "kind": "category", "data": count_by(al, lambda a: a["tactic"])})
    b.append({"by": "Category", "kind": "category", "data": count_by(al, lambda a: (a["category"] or "other").replace("_", " "))})
    return b


@metric("alerts", "Security alerts", pie=True,
        description="Security detections raised by connected tools during the selected window.",
        why="Alert volume reflects both attacker activity and how noisy our tooling is. Sudden spikes often mark a campaign (for example a phishing wave); a steady rise without more incidents suggests tuning is needed.",
        calculation="Count of alerts whose detection time falls in the window, after normalizing every tool's alert format (severity, status, MITRE ATT&CK tactic) into one schema. The trend shows the same trailing-window count at each week.")
def _alerts(env):
    al = env.alerts()
    return {"value": len(al), "items": table(ALERT_COLS, alert_rows(env, al)), "items_label": f"Alerts in the last {env.days} days",
            "series": weekly(env.data, lambda w: len(env.alerts(week_end_dt(env.data, w)))),
            "breakdowns": alert_breakdowns(env, al),
            "inputs": {"Window (days)": env.days, "Alerts": len(al), "Per day (avg)": round(len(al) / env.days, 1),
                       "Confirmed incidents": sum(a["is_incident"] for a in al)},
            "sources": env.tool_sources(ALERT_TOOLS)}


@metric("open_alerts", "Open alerts", pie=True,
        description="Alerts that are new or under investigation right now.",
        why="Open alerts are unresolved potential incidents. A growing queue — especially of critical/high alerts — means the SOC is falling behind and real attacks could be missed.",
        calculation="Count of alerts detected at or before now and not yet resolved (status new or investigating).")
def _open_alerts(env):
    al = [a for a in env.data.alerts if (env.source is None or a["source"] == env.source) and a["status"] in ("new", "investigating")]
    return {"value": len(al), "items": table(ALERT_COLS, alert_rows(env, al)),
            "series": weekly(env.data, lambda w: metrics.alert_metrics(env.data, 30, week_end_dt(env.data, w), env.source)["open_total"]),
            "breakdowns": alert_breakdowns(env, al),
            "inputs": {"New": sum(a["status"] == "new" for a in al), "Investigating": sum(a["status"] == "investigating" for a in al),
                       "Critical/high": sum(a["severity"] in ("critical", "high") for a in al)},
            "sources": env.tool_sources(ALERT_TOOLS)}


@metric("alerts_investigating", "Under investigation", trend=False,
        description="Alerts the MDR team is actively investigating.",
        why="Shows the current analyst workload and how many potential incidents are unresolved.",
        calculation="Count of alerts in the window with status = investigating.")
def _investigating(env):
    al = [a for a in env.alerts() if a["status"] == "investigating"]
    return {"value": len(al), "items": table(ALERT_COLS, alert_rows(env, al)), "breakdowns": alert_breakdowns(env, al),
            "inputs": {"Investigating": len(al)}, "sources": env.tool_sources(ALERT_TOOLS)}


@metric("incidents", "Confirmed incidents", pie=True,
        description="Alerts that were investigated and confirmed as real security incidents.",
        why="Incidents are the outcome that matters: confirmed malicious activity. Their count and type tell leadership what attackers are actually achieving, not just attempting.",
        calculation="Count of alerts in the window that were escalated and marked as an incident by the analyst or MDR provider (Expel investigations flagged is_incident; CrowdStrike detections escalated to incidents).")
def _incidents(env):
    al = [a for a in env.alerts() if a["is_incident"]]
    return {"value": len(al), "items": table(ALERT_COLS, alert_rows(env, al)),
            "series": weekly(env.data, lambda w: sum(a["is_incident"] for a in env.alerts(week_end_dt(env.data, w)))),
            "breakdowns": [b for b in alert_breakdowns(env, al) if b["by"] != "MITRE ATT&CK tactic"],
            "inputs": {"Window (days)": env.days, "Incidents": len(al), "Alerts in window": len(env.alerts())},
            "sources": env.tool_sources(ALERT_TOOLS)}


def _detect_minutes(a):
    return (a["_det"] - a["_occ"]).total_seconds() / 60 if a["_occ"] else None


@metric("mttd", "Median time to detect", unit=" min",
        description="Median minutes between when malicious activity occurred and when a tool raised an alert.",
        why="The faster we detect, the less time an attacker has to move laterally or steal data. Detection time is one of the strongest predictors of breach cost.",
        calculation="For each alert in the window: detected time − event time (as reported by the tool). Value = median, which is robust to a few very late detections. The table lists the slowest detections.")
def _mttd(env):
    al = [a for a in env.alerts() if a["_occ"]]
    rows_ = alert_rows(env, al, lambda a: {"minutes": round(_detect_minutes(a))})
    rows_.sort(key=lambda r: -r["minutes"])

    def at(w):
        sub = [_detect_minutes(a) for a in env.alerts(week_end_dt(env.data, w)) if a["_occ"]]
        return round(median(sub), 1) if sub else None
    return {"value": round(median(_detect_minutes(a) for a in al), 1) if al else None,
            "items": table([("minutes", "Minutes to detect", "num")] + ALERT_COLS, rows_), "items_label": "Alerts, slowest detection first",
            "series": weekly(env.data, at),
            "breakdowns": [{"by": "Median minutes by source", "kind": "tool", "data": sorted(
                [{"label": TOOL[s], "value": round(median([_detect_minutes(a) for a in al if a["source"] == s]), 1)} for s in {a["source"] for a in al}],
                key=lambda x: -x["value"])}],
            "inputs": {"Alerts measured": len(al), "Fastest (min)": round(min((_detect_minutes(a) for a in al), default=0)),
                       "Slowest (min)": round(max((_detect_minutes(a) for a in al), default=0))},
            "sources": env.tool_sources(ALERT_TOOLS)}


def _resolve_hours(a):
    return (a["_res"] - a["_det"]).total_seconds() / 3600


@metric("mttr_critical_alerts", "Critical alert response time", unit="h",
        description="Mean hours from detection to resolution for critical-severity alerts.",
        why="Critical alerts represent possible active compromise. Every hour unresolved is an hour an attacker may be operating. Our target is under 4 hours.",
        calculation="For each critical alert detected in the window and resolved (false positives excluded): resolved time − detected time. Value = mean of those hours. Target ≤ 4 h.")
def _mttr_alerts(env):
    al = [a for a in env.alerts() if a["severity"] == "critical" and a["_res"] and a["status"] != "false_positive"]
    rows_ = alert_rows(env, al, lambda a: {"hours": round(_resolve_hours(a), 1)})
    rows_.sort(key=lambda r: -r["hours"])
    open_crit = [a for a in env.alerts() if a["severity"] == "critical" and not a["_res"]]
    return {"value": metrics.alert_metrics(env.data, env.days, source=env.source)["mttr_hours"]["critical"],
            "items": table([("hours", "Hours to resolve", "num")] + ALERT_COLS, rows_), "items_label": "Resolved critical alerts, slowest first",
            "series": weekly(env.data, lambda w: metrics.alert_metrics(env.data, env.days, week_end_dt(env.data, w), env.source)["mttr_hours"]["critical"]),
            "breakdowns": [{"by": "Average hours by source", "kind": "tool", "data": avg_by(al, lambda a: TOOL[a["source"]], _resolve_hours)},
                           {"by": "Average hours by tactic", "kind": "category", "data": avg_by(al, lambda a: a["tactic"], _resolve_hours)}],
            "inputs": {"Resolved critical alerts": len(al), "Within 4h target": sum(_resolve_hours(a) <= 4 for a in al), "Still open": len(open_crit)},
            "sources": env.tool_sources(ALERT_TOOLS)}


@metric("false_positive_rate", "False positive rate", unit="%",
        description="The share of closed alerts that turned out to be benign.",
        why="False positives consume analyst time and cause alert fatigue, which is how real attacks get missed. A high rate signals detection rules that need tuning.",
        calculation="100 × (alerts closed as false positive ÷ all closed alerts) within the window.")
def _fp(env):
    al = env.alerts()
    fp = [a for a in al if a["status"] == "false_positive"]
    closed = [a for a in al if a["status"] in ("resolved", "false_positive")]

    def at(w):
        sub = env.alerts(week_end_dt(env.data, w))
        c = [a for a in sub if a["status"] in ("resolved", "false_positive")]
        return metrics._pct(sum(a["status"] == "false_positive" for a in c), len(c)) if c else None
    return {"value": metrics._pct(len(fp), len(closed)), "items": table(ALERT_COLS, alert_rows(env, fp)), "items_label": "Alerts closed as false positive",
            "series": weekly(env.data, at),
            "breakdowns": [{"by": "False positives by rule", "kind": "category", "data": count_by(fp, lambda a: a["title"], limit=8)},
                           {"by": "False positives by source", "kind": "tool", "data": count_by(fp, lambda a: TOOL[a["source"]])}],
            "inputs": {"Closed alerts": len(closed), "False positives": len(fp)}, "sources": env.tool_sources(ALERT_TOOLS)}


# =========================================================================== cloud (Wiz)
def _cloud_metric(env, pred):
    open_i = [c for c in env.data.cloud if c["status"] == "open" and pred(c)]

    def at(w):
        d = (env.data.today - timedelta(days=7 * w)).isoformat()
        return sum(1 for c in env.data.cloud if pred(c) and c["created_at"] <= d and (not c["resolved_at"] or c["resolved_at"] > d))
    order = {s: i for i, s in enumerate(SEVS)}
    rows_ = sorted([{k: c[k] for k in ("severity", "rule", "resource", "cloud", "category", "created_at")} for c in open_i], key=lambda r: order[r["severity"]])
    return {"value": len(open_i), "items": table(CLOUD_COLS, rows_), "items_label": "Open cloud issues", "series": weekly(env.data, at),
            "breakdowns": [{"by": "Severity", "kind": "severity", "pie": True, "data": count_by(open_i, lambda c: c["severity"], SEVS)},
                           {"by": "Cloud", "kind": "category", "data": count_by(open_i, lambda c: c["cloud"].upper())},
                           {"by": "Rule", "kind": "category", "data": count_by(open_i, lambda c: c["rule"], limit=8)}],
            "inputs": {"Open issues": len(open_i), "Critical": sum(c["severity"] == "critical" for c in open_i)},
            "sources": [src("wiz")]}


@metric("cloud_open_issues", "Open cloud issues", pie=True,
        description="Open security issues Wiz has found in our AWS, Azure, and GCP environments.",
        why="Cloud misconfigurations (public storage, open security groups, excessive permissions) are among the most common causes of data breaches, and they can be introduced by any deployment.",
        calculation="Count of Wiz issues with status open, across misconfiguration, exposure, identity, secret, and toxic-combination categories.")
def _cloud_open(env):
    return _cloud_metric(env, lambda c: True)


@metric("toxic_combinations", "Toxic combinations",
        description="Cloud resources where several risks combine into a direct attack path — e.g. internet-exposed, running an exploitable vulnerability, and holding admin privileges.",
        why="Individually these issues are moderate; together they give an attacker a one-step route from the internet to privileged access. They should be fixed first, ideally within 7 days.",
        calculation="Count of open Wiz issues of type TOXIC_COMBINATION (Wiz's graph engine correlates exposure, vulnerabilities, identities, and data on the same resource).")
def _toxic(env):
    return _cloud_metric(env, lambda c: c["category"] == "toxic_combination")


@metric("internet_exposed_issues", "Internet-exposed cloud issues",
        description="Open cloud issues on resources reachable from the internet.",
        why="Internet exposure removes the first barrier an attacker faces. Issues on exposed resources are found by automated scanning within hours.",
        calculation="Count of open Wiz issues where the affected resource is publicly reachable (exposure analysis on network paths and public IPs).")
def _exposed(env):
    return _cloud_metric(env, lambda c: c["internet_exposed"])


@metric("exposed_secrets", "Exposed secrets",
        description="Credentials, keys, or tokens found in cleartext in cloud resources or container images.",
        why="A leaked secret lets an attacker skip exploitation entirely and log in as a legitimate service.",
        calculation="Count of open Wiz issues in the secret category (secret scanning of images, VMs, and code).")
def _secrets(env):
    return _cloud_metric(env, lambda c: c["category"] == "secret")


@metric("cloud_resources", "Cloud resources", trend=False, better="higher",
        description="Cloud workloads Wiz is monitoring across AWS, Azure, and GCP.",
        why="Defines the scope of cloud monitoring; resources outside it are unmonitored.",
        calculation="Count of assets in inventory whose environment is AWS, Azure, or GCP.")
def _cloud_resources(env):
    ca = [a for a in env.data.assets.values() if a["environment"] in ("aws", "azure", "gcp")]
    return {"value": len(ca), "items": table(ASSET_COLS + [("internet_facing", "Internet-facing", "bool")], asset_rows(ca)),
            "breakdowns": [{"by": "Cloud", "kind": "category", "data": count_by(ca, lambda a: a["environment"].upper())},
                           {"by": "Business unit", "kind": "category", "data": count_by(ca, lambda a: a["business_unit"])}],
            "inputs": {"Cloud resources": len(ca), "Internet-facing": sum(a["internet_facing"] for a in ca)}, "sources": [src("wiz")]}


# =========================================================================== active threats
THREAT_FILTERS = {
    "all": ("Active threats", "Vulnerabilities in our environment that are on CISA KEV, have an EPSS exploit probability ≥ 50%, or are cited in recent security news.",
            lambda t: True),
    "kev": ("Active threats on CISA KEV", "Active threats whose CVE is on CISA's Known Exploited Vulnerabilities catalog.", lambda t: t["in_kev"]),
    "ransomware": ("Ransomware-linked threats", "Active threats whose CVE CISA reports as used in ransomware campaigns.", lambda t: t["ransomware"]),
    "news": ("Threats in recent news", "Active threats whose CVE ID appears in a security news article from the last 45 days.", lambda t: t["news_count"] > 0),
    "overdue": ("Threats past remediation SLA", "Active threats with at least one affected asset past its remediation deadline.", lambda t: t["overdue"]),
    "internet": ("Internet-facing assets exposed", "Distinct internet-facing assets affected by at least one active threat.", lambda t: t["internet_facing_count"] > 0),
}
THREAT_COLS = [("priority", "Priority", "num"), ("cve", "CVE", "cve"), ("title", "Vulnerability", "text"), ("asset_count", "Assets", "num"),
               ("internet_facing_count", "Internet-facing", "num"), ("epss_pct", "EPSS %", "num"), ("flags", "Signals", "text")]


@metric("active_threats", "Active threats", pie=True, trend=False,
        description="", why="This is the shortlist of vulnerabilities attackers are actually using or talking about, matched to systems we own. It is where patching effort has the highest payoff.",
        calculation="Join of open scanner findings with the live CISA KEV catalog, FIRST EPSS scores, and CVE IDs extracted from security news. Each match is ranked with an additive priority score (0–100): "
                    + " · ".join(f"{k} up to {v}" for k, v in threat_intel.WEIGHTS.items()) + ".")
def _threats(env):
    label, desc, pred = THREAT_FILTERS.get(env.filter, THREAT_FILTERS["all"])
    ts = [t for t in env.threats if pred(t)]
    sources = env.tool_sources(VULN_SOURCES) + [src("cisa_kev"), src("epss"), src("news")]
    if env.filter == "internet":
        assets = {}
        for t in ts:
            for a in t["affected_assets"]:
                if a["internet_facing"]:
                    assets.setdefault(a["asset_id"], {**a, "cves": []})["cves"].append(t["cve"])
        rows_ = [{"hostname": a["hostname"], "asset_id": a["asset_id"], "business_unit": a["business_unit"], "owner": a["owner"],
                  "criticality": a["criticality"], "cves": ", ".join(a["cves"]), "n": len(a["cves"])} for a in assets.values()]
        rows_.sort(key=lambda r: -r["n"])
        return {"value": len(rows_), "label": label, "description": desc,
                "items": table([("hostname", "Asset", "asset"), ("business_unit", "Business unit", "text"), ("owner", "Owner", "text"),
                                ("criticality", "Criticality", "num"), ("n", "Active threats", "num"), ("cves", "CVEs", "mono")], rows_),
                "breakdowns": [{"by": "Business unit", "kind": "category", "data": count_by(assets.values(), lambda a: a["business_unit"])}],
                "inputs": {"Internet-facing assets": len(rows_), "Active threats involved": len(ts)}, "sources": sources}
    rows_ = [{"priority": t["priority"], "cve": t["cve"], "title": t["title"], "asset_count": t["asset_count"],
              "internet_facing_count": t["internet_facing_count"], "epss_pct": round(t["epss"] * 100, 1),
              "flags": " · ".join(x for x, ok in (("KEV", t["in_kev"]), ("Ransomware", t["ransomware"]), ("In news", t["news_count"] > 0),
                                                  ("New this month", t["newly_listed"]), ("Past SLA", t["overdue"])) if ok)} for t in ts]
    band = lambda p: "75–100" if p >= 75 else "60–74" if p >= 60 else "< 60"
    return {"value": len(ts), "label": label, "description": desc, "items": table(THREAT_COLS, rows_),
            "breakdowns": [{"by": "Priority band", "kind": "category", "pie": True, "data": count_by(ts, lambda t: band(t["priority"]), ["75–100", "60–74", "< 60"])},
                           {"by": "Product", "kind": "category", "data": count_by(ts, lambda t: t["product"] or "Other")}],
            "inputs": {"Matched threats": len(ts), "On KEV": sum(t["in_kev"] for t in ts), "Cited in news": sum(t["news_count"] > 0 for t in ts),
                       "EPSS ≥ 50%": sum(t["epss"] >= 0.5 for t in ts)}, "sources": sources}


# =========================================================================== third-party
def _vendor_monthly(env, field):
    hist = [v[field] for v in env.data.vendors]
    n = len(hist[0]) if hist else 0
    first = env.data.today.replace(day=1)
    out = []
    for i in range(n):
        months_back = n - 1 - i
        y, m = first.year, first.month - months_back
        while m <= 0:
            y, m = y - 1, m + 12
        out.append({"date": date(y, m, 1).isoformat(), "value": round(mean(h[i] for h in hist), 1)})
    return out


@metric("avg_bitsight", "Average Bitsight rating", better="higher",
        description="Average Bitsight security rating across our vendor portfolio (250–900).",
        why="Bitsight rates a company's security from the outside (compromised systems, patching, open ports, breaches). Low or falling ratings at vendors who hold our data are an early warning of supply-chain risk.",
        calculation="Mean of each vendor's current Bitsight rating. Bands: 740+ Advanced, 640–739 Intermediate, below 640 Basic. The trend is the monthly portfolio average.")
def _bitsight(env):
    vs = sorted(env.ctx["tprm"]["vendors"], key=lambda v: v["bitsight_rating"])
    band = metrics.bitsight_band
    return {"value": env.ctx["tprm"]["avg_bitsight"], "items": table(VENDOR_COLS, vendor_rows(vs)), "items_label": "Vendors, lowest Bitsight rating first", "series": _vendor_monthly(env, "bitsight_history"),
            "series_label": "Monthly portfolio average",
            "breakdowns": [{"by": "Rating band", "kind": "category", "data": count_by(vs, lambda v: band(v["bitsight_rating"]), ["Advanced", "Intermediate", "Basic"])},
                           {"by": "Average by tier", "kind": "category", "data": avg_by(vs, lambda v: f"Tier {v['tier']}", lambda v: v["bitsight_rating"], 0)}],
            "inputs": {"Vendors rated": len(vs), "Basic range (< 640)": sum(v["bitsight_rating"] < 640 for v in vs)}, "sources": [src("bitsight")]}


@metric("avg_ssc", "Average SecurityScorecard score", better="higher",
        description="Average SecurityScorecard score across our vendor portfolio (0–100, graded A–F).",
        why="A second, independent outside-in rating. Agreement between Bitsight and SecurityScorecard increases confidence that a vendor's posture really is weak.",
        calculation="Mean of each vendor's current SecurityScorecard score. Grades: A ≥ 90, B 80–89, C 70–79, D 60–69, F < 60.")
def _ssc(env):
    vs = sorted(env.ctx["tprm"]["vendors"], key=lambda v: v["ssc_score"])
    return {"value": env.ctx["tprm"]["avg_ssc"], "items": table(VENDOR_COLS, vendor_rows(vs)), "items_label": "Vendors, lowest SecurityScorecard first", "series": _vendor_monthly(env, "ssc_history"),
            "series_label": "Monthly portfolio average",
            "breakdowns": [{"by": "Grade", "kind": "category", "data": count_by(vs, lambda v: v["ssc_grade"], list("ABCDF"))},
                           {"by": "Average by tier", "kind": "category", "data": avg_by(vs, lambda v: f"Tier {v['tier']}", lambda v: v["ssc_score"])}],
            "inputs": {"Vendors rated": len(vs), "Grade D or F": sum(v["ssc_score"] < 70 for v in vs)}, "sources": [src("ssc")]}


@metric("vendors_attention", "Vendors needing attention", pie=True, trend=False,
        description="Vendors with at least one risk flag: Bitsight in the Basic range, SecurityScorecard grade D/F, a Bitsight drop of 30+ points in 90 days, or an overdue assessment.",
        why="Focuses third-party risk management effort on the suppliers most likely to cause an incident, especially tier-1 vendors with access to sensitive data or systems.",
        calculation="Count of vendors where any rule fires: Bitsight < 640 · SecurityScorecard < 70 · Bitsight change over 3 months ≤ −30 · next assessment date in the past.")
def _attention(env):
    vs = [v for v in env.ctx["tprm"]["vendors"] if v["reasons"]]
    reasons = Counter(r.split(" in ")[0].split(" down")[0].split(" grade")[0] for v in vs for r in v["reasons"])
    return {"value": len(vs), "items": table(VENDOR_COLS, vendor_rows(vs)), "items_label": "Flagged vendors",
            "breakdowns": [{"by": "Flag", "kind": "category", "data": [{"label": k, "value": n} for k, n in reasons.most_common()]},
                           {"by": "Tier", "kind": "category", "pie": True, "data": count_by(vs, lambda v: f"Tier {v['tier']}", ["Tier 1", "Tier 2", "Tier 3"])}],
            "inputs": {"Vendors": env.ctx["tprm"]["vendor_count"], "Flagged": len(vs), "Tier-1 flagged": sum(v["tier"] == 1 for v in vs)},
            "sources": [src("bitsight"), src("ssc"), src("roadmap")]}


@metric("overdue_assessments", "Overdue vendor assessments", trend=False,
        description="Vendors whose periodic security assessment is past due.",
        why="Assessments are how we verify a vendor's controls contractually. Overdue reviews mean we are relying on stale assurance — a common audit finding under ISO 27001 A.5.22 and SOC 2.",
        calculation="Count of vendors whose next assessment date is before today. Cycle: tier-1 every 12 months, tier-2/3 every 24 months. The table also lists vendors due within 60 days.")
def _overdue_assess(env):
    tp = env.ctx["tprm"]
    vs = [v for v in tp["vendors"] if v["assessment_status"] in ("overdue", "due_soon")]
    vs.sort(key=lambda v: v["next_assessment"])
    return {"value": tp["overdue_assessments"],
            "items": table(VENDOR_COLS[:3] + [("next_assessment", "Next assessment", "due"), ("assessment_status", "Status", "status")], vendor_rows(vs)),
            "items_label": "Overdue and due within 60 days",
            "breakdowns": [{"by": "Status", "kind": "category", "data": [{"label": "Overdue", "value": tp["overdue_assessments"]}, {"label": "Due in 60 days", "value": tp["due_soon"]}]}],
            "inputs": {"Overdue": tp["overdue_assessments"], "Due within 60 days": tp["due_soon"]}, "sources": [src("roadmap")]}


# =========================================================================== risk score
COMPONENT_TEXT = {
    "vulnerability": ("How much serious vulnerability exposure is past its fix deadline.", "60% × share of critical/high findings past SLA + 40% × critical density (10 × criticals per 100 assets), capped at 100."),
    "threat": ("Exposure to vulnerabilities attackers are actively exploiting.", "2.5 points per distinct open KEV CVE + 4 points per internet-facing asset affected by one, capped at 100."),
    "detection": ("How well we are keeping up with security alerts.", "50% × (8 per open critical alert + 3 per open high alert, capped at 100) + 50% × (critical alert MTTR ÷ 4h target × 40, capped at 100)."),
    "third_party": ("Security posture of our suppliers as rated externally.", "Tier-weighted average (tier 1 ×3, tier 2 ×2, tier 3 ×1) of vendor risk = 50% × (900 − Bitsight) ÷ 6.5 + 50% × (100 − SecurityScorecard)."),
    "coverage": ("Blind spots in our security tooling.", "3 × (100 − EDR coverage %) + 2 × (100 − scan coverage %), capped at 100."),
    "compliance": ("Gaps in required security controls.", "100 − average implementation % across NIST CSF 2.0, ISO 27001:2022, and GDPR."),
}


@metric("risk_score", "Enterprise risk score", unit="/100",
        description="A single 0–100 indicator of overall cyber risk (higher = more risk), combining six weighted components.",
        why="Gives leadership one consistent number to track over time and compare across periods, while every component behind it stays visible and explainable.",
        calculation="Weighted sum of six component scores, each 0–100: " + " · ".join(f"{label} {int(w * 100)}%" for _, label, w in metrics.COMPONENTS)
                    + ". Ratings: < 35 Low, 35–54 Elevated, 55–74 High, ≥ 75 Critical. History is recomputed as of each past week from record timestamps.")
def _risk(env):
    r = metrics.risk_score(env.data, ctx=env.ctx)
    rows_ = [{"label": c["label"], "weight": f"{int(c['weight'] * 100)}%", "risk": c["risk"], "contribution": c["contribution"], "detail": c["detail"]} for c in r["components"]]
    return {"value": r["score"], "items": table([("label", "Component", "text"), ("weight", "Weight", "text"), ("risk", "Component score", "num"),
                                                 ("contribution", "Points contributed", "num"), ("detail", "Driver", "text")], rows_),
            "items_label": "Score components",
            "series": [{"date": h["date"], "value": h["score"]} for h in metrics.risk_history(env.data, env.ctx)],
            "breakdowns": [{"by": "Points contributed", "kind": "category", "data": [{"label": c["label"], "value": c["contribution"]} for c in r["components"]]}],
            "inputs": {c["label"]: f"{c['risk']} × {c['weight']} = {c['contribution']}" for c in r["components"]},
            "sources": [src(t) for t in ("qualys", "crowdstrike", "expel", "wiz")] + [src("cisa_kev"), src("bitsight"), src("ssc"), src("grc")]}


def _component_items(env, key):
    if key == "vulnerability":
        fs = [f for f in env.findings() if f["severity"] in ("critical", "high") and f["due_date"] < env.data.today.isoformat()]
        return table(FINDING_COLS, finding_rows(env, fs)), "Past-due critical/high findings"
    if key == "threat":
        fs = [f for f in env.findings() if f["cve"] in env.data.kev]
        return table(FINDING_COLS, finding_rows(env, fs)), "Open findings on CISA KEV"
    if key == "detection":
        al = [a for a in env.data.alerts if a["status"] in ("new", "investigating") and a["severity"] in ("critical", "high")]
        return table(ALERT_COLS, alert_rows(env, al)), "Open critical/high alerts"
    if key == "third_party":
        return table(VENDOR_COLS, vendor_rows(sorted(env.ctx["tprm"]["vendors"], key=lambda v: -v["risk"]))), "Vendors, highest risk first"
    if key == "coverage":
        return table(EDR_COLS, asset_rows(_edr_gaps(env))), "Hosts without healthy EDR"
    gaps = [c for c in env.ctx["controls"] if c["status"] != "implemented"]
    return table(CONTROL_COLS, control_rows(gaps)), "Controls not fully implemented"


def _make_component(key, label, weight):
    what, formula = COMPONENT_TEXT[key]

    @metric(f"risk_{key}", f"Risk component: {label}", unit="/100", bars=False,
            description=f"{what} Contributes {int(weight * 100)}% of the enterprise risk score.",
            why="Breaking the score into components shows which area is driving risk, so investment goes where it reduces the score most.",
            calculation=formula)
    def _fn(env):
        r = metrics.risk_score(env.data, ctx=env.ctx)
        comp = next(c for c in r["components"] if c["key"] == key)
        items, items_label = _component_items(env, key)
        series = [{"date": (env.data.today - timedelta(days=7 * w)).isoformat(),
                   "value": next(c["risk"] for c in metrics.risk_score(env.data, env.data.today - timedelta(days=7 * w), env.ctx)["components"] if c["key"] == key)}
                  for w in range(WEEKS - 1, -1, -1)]
        return {"value": comp["risk"], "items": items, "items_label": items_label, "series": series, "breakdowns": [],
                "inputs": {"Component score": comp["risk"], "Weight": f"{int(weight * 100)}%", "Points contributed": comp["contribution"], "Driver": comp["detail"]},
                "sources": [src(t) for t in ("qualys", "crowdstrike", "expel", "wiz")]}


for _k, _l, _w in metrics.COMPONENTS:
    _make_component(_k, _l, _w)


# =========================================================================== compliance
CONTROL_COLS = [("control_id", "ID", "mono"), ("name", "Control", "text"), ("family", "Area", "text"), ("status", "Status", "status"),
                ("evidence", "Evidence", "text"), ("owner", "Owner", "text")]


def control_rows(cs):
    order = {"not_implemented": 0, "partial": 1, "implemented": 2}
    return [{**{k: c.get(k) for k in ("control_id", "name", "family", "status", "owner", "framework")},
             "evidence": c.get("evidence") or ("Auto-evaluated" if c.get("auto_rule") else "Owner attestation")}
            for c in sorted(cs, key=lambda c: (order[c["status"]], c["control_id"]))]


@metric("compliance", "Framework implementation", pie=True, trend=False, unit="%", better="higher",
        description="How much of a compliance framework's control set is implemented.",
        why="Framework readiness determines audit outcomes and certifications customers require during procurement. Gaps are also where real security weaknesses tend to hide.",
        calculation="100 × (implemented controls + 0.5 × partially implemented controls) ÷ all controls in the framework. Controls marked auto-evaluated are scored from live data (e.g. EDR coverage, vulnerability SLA, vendor assessments) instead of self-attestation.")
def _compliance(env):
    fws = env.ctx["frameworks"]
    fw_name = env.framework or (fws[0]["framework"] if fws else None)
    if env.framework is None:
        cs, pct = env.ctx["controls"], round(mean(f["pct"] for f in fws), 1)
        label = "Compliance (average across frameworks)"
        bd = [{"by": "Framework", "kind": "category", "data": [{"label": f["framework"], "value": f["pct"]} for f in fws]}]
    else:
        fw = next(f for f in fws if f["framework"] == fw_name)
        cs, pct, label = [c for c in env.ctx["controls"] if c["framework"] == fw_name], fw["pct"], f"{fw_name} implementation"
        bd = [{"by": "Implementation % by area", "kind": "category", "data": [{"label": f["family"], "value": f["pct"]} for f in fw["families"]]}]
    bd.insert(0, {"by": "Control status", "kind": "status", "pie": True, "data": count_by(cs, lambda c: c["status"].replace("_", " "), ["implemented", "partial", "not implemented"])})
    return {"value": pct, "label": label, "items": table(CONTROL_COLS + ([("framework", "Framework", "text")] if env.framework is None else []), control_rows(cs)),
            "items_label": "Controls, gaps first", "breakdowns": bd,
            "inputs": {"Controls": len(cs), "Implemented": sum(c["status"] == "implemented" for c in cs), "Partial": sum(c["status"] == "partial" for c in cs),
                       "Not implemented": sum(c["status"] == "not_implemented" for c in cs), "Auto-evaluated": sum(bool(c["auto_rule"]) for c in cs)},
            "sources": [src("grc")] + [src(t) for t in ("qualys", "crowdstrike")]}


# =========================================================================== remediation (Jira)
TICKET_COLS = [("key", "Ticket", "ticket"), ("summary", "Summary", "text"), ("status", "Status", "status"), ("priority", "Priority", "priority"),
               ("team", "Team", "text"), ("assignee", "Assignee", "text"), ("due_date", "Due", "due"), ("created_at", "Created", "date")]
T_OPEN = ("To Do", "In Progress", "In Review")
T_STATUSES = ["To Do", "In Progress", "In Review", "Done", "Won't Fix"]
T_PRIORITIES = ["Highest", "High", "Medium", "Low"]


def _tickets(env):
    if "_tickets" not in env.__dict__:
        ts = [dict(r) for r in env.conn.execute("""
            SELECT t.*, (SELECT COUNT(*) FROM ticket_findings tf JOIN findings f ON f.id=tf.finding_id
                         WHERE tf.ticket_id=t.id AND f.status IN ('open','in_progress')) AS still_open
            FROM tickets t""")]
        for t in ts:
            t["_c"] = metrics._dt(t["created_at"])
            t["_r"] = metrics._dt(t["resolved_at"])
        env.__dict__["_tickets"] = ts
    return env.__dict__["_tickets"]


def _ticket_rows(ts, extra=None):
    order = {s: i for i, s in enumerate(T_STATUSES)}
    porder = {p: i for i, p in enumerate(T_PRIORITIES)}
    out = []
    for t in sorted(ts, key=lambda t: (order[t["status"]], porder.get(t["priority"], 9), t["due_date"] or "")):
        row = {k: t[k] for k in ("key", "summary", "status", "priority", "team", "assignee", "due_date", "created_at", "resolved_at", "url")}
        if extra:
            row.update(extra(t))
        out.append(row)
    return out


def _open_at(t, dt):
    return t["_c"] <= dt and (t["_r"] is None or t["_r"] > dt)


def _ticket_index(env):
    from .remediation import finding_ticket_index
    return finding_ticket_index(env.conn)


@metric("remediation_vulns", "Open vs closed vulnerabilities", pie=True,
        description="Vulnerabilities detected in the last 90 days, split into still open versus closed (remediated and verified by a rescan, or formally risk-accepted).",
        why="The ratio shows whether remediation is keeping up with discovery. Breaking the open ones down by Jira status shows how much exposure is actually being worked versus waiting for someone to pick it up.",
        calculation="Findings with first-seen date in the last 90 days. Open = status open or in progress. Closed = remediated (scanner no longer detects it) or risk accepted via a Won't Fix ticket. "
                    "Jira status comes from the ticket linked to each finding; 'Not ticketed' means no ticket exists yet.")
def _rem_vulns(env):
    cutoff = (env.data.today - timedelta(days=90)).isoformat()
    fs = [f for f in env.data.findings if f["first_seen"] >= cutoff]
    idx = _ticket_index(env)
    open_f = [f for f in fs if f["status"] in ("open", "in_progress")]
    remediated = sum(f["status"] == "remediated" for f in fs)
    accepted = sum(f["status"] == "risk_accepted" for f in fs)
    def jira_state(f):
        t = idx.get(f["id"])
        if not t:
            return "Not ticketed"
        return "Done (awaiting rescan)" if t["status"] == "Done" else t["status"]
    rows_ = finding_rows(env, open_f, lambda f: {"ticket": (idx.get(f["id"]) or {}).get("key"), "jira_status": jira_state(f)})
    def at(w):
        d = env.data.today - timedelta(days=7 * w)
        lo = (d - timedelta(days=90)).isoformat()
        return sum(1 for f in env.data.findings if lo <= f["first_seen"] <= d.isoformat() and is_open(f, d))
    return {"value": len(open_f),
            "items": table([("severity", "Severity", "severity"), ("title", "Finding", "text"), ("hostname", "Asset", "asset"), ("ticket", "Ticket", "ticket"),
                            ("jira_status", "Jira status", "status"), ("due_date", "SLA due", "due"), ("owner_team", "Owner", "text")], rows_),
            "items_label": "Open vulnerabilities and their remediation tickets", "series": weekly(env.data, at),
            "breakdowns": [{"by": "Open vs closed", "kind": "status", "pie": True,
                            "data": [{"label": "Open", "value": len(open_f)}, {"label": "Remediated", "value": remediated}, {"label": "Risk accepted", "value": accepted}]},
                           {"by": "Open, by Jira status", "kind": "status", "pie": True,
                            "data": count_by(open_f, jira_state, ["Not ticketed", "To Do", "In Progress", "In Review", "Done (awaiting rescan)"])},
                           {"by": "Open, by severity", "kind": "severity", "pie": True, "data": count_by(open_f, lambda f: f["severity"], SEVS)}],
            "inputs": {"Detected (90d)": len(fs), "Open": len(open_f), "Remediated": remediated, "Risk accepted": accepted,
                       "Closure rate": f"{metrics._pct(remediated + accepted, len(fs))}%"},
            "sources": env.tool_sources(VULN_SOURCES) + [src("jira")]}


@metric("tickets_open", "Open remediation tickets", pie=True,
        description="Jira remediation tickets that are not yet resolved (To Do, In Progress, or In Review).",
        why="This is the remediation backlog. Its size and trend show whether engineering teams have capacity to keep up with security work.",
        calculation="Count of tickets in status To Do, In Progress, or In Review. The trend counts tickets open at the end of each week (created on or before that day and not yet resolved).")
def _tickets_open(env):
    ts = _tickets(env)
    open_t = [t for t in ts if t["status"] in T_OPEN]
    return {"value": len(open_t), "items": table(TICKET_COLS, _ticket_rows(open_t)), "items_label": "Open tickets",
            "series": weekly(env.data, lambda w: sum(_open_at(t, week_end_dt(env.data, w)) for t in ts)),
            "breakdowns": [{"by": "Open vs closed", "kind": "status", "pie": True,
                            "data": [{"label": "Open", "value": len(open_t)}, {"label": "Closed", "value": len(ts) - len(open_t)}]},
                           {"by": "Status", "kind": "status", "pie": True, "data": count_by(ts, lambda t: t["status"], T_STATUSES)},
                           {"by": "Open, by priority", "kind": "priority", "pie": True, "data": count_by(open_t, lambda t: t["priority"], T_PRIORITIES)},
                           {"by": "Open, by team", "kind": "category", "data": count_by(open_t, lambda t: t["team"])}],
            "inputs": {"All tickets": len(ts), **{s: sum(t["status"] == s for t in ts) for s in T_STATUSES}},
            "sources": [src("jira")]}


@metric("tickets_overdue", "Overdue tickets", pie=True,
        description="Open remediation tickets past their due date. The due date is the remediation SLA of the most urgent finding on the ticket.",
        why="Overdue tickets are exposure we committed to close and haven't. Grouping them by team and assignee shows where to escalate.",
        calculation="Count of tickets in To Do / In Progress / In Review whose due date is before today. Due dates default to the finding SLA (critical 15 days, high 30 days from detection).")
def _tickets_overdue(env):
    ts = _tickets(env)
    today = env.data.today.isoformat()
    open_t = [t for t in ts if t["status"] in T_OPEN]
    over = [t for t in open_t if t["due_date"] and t["due_date"] < today]
    def at(w):
        dt = week_end_dt(env.data, w)
        d = dt.date().isoformat()
        return sum(1 for t in ts if _open_at(t, dt) and t["due_date"] and t["due_date"] < d)
    rows_ = _ticket_rows(over, lambda t: {"days_overdue": (env.data.today - date.fromisoformat(t["due_date"])).days})
    return {"value": len(over), "items": table(TICKET_COLS[:6] + [("due_date", "Due", "due"), ("days_overdue", "Days overdue", "num")], rows_),
            "items_label": "Overdue tickets", "series": weekly(env.data, at),
            "breakdowns": [{"by": "On track vs overdue", "kind": "status", "pie": True,
                            "data": [{"label": "On track", "value": len(open_t) - len(over)}, {"label": "Overdue", "value": len(over)}]},
                           {"by": "Overdue by team", "kind": "category", "data": count_by(over, lambda t: t["team"])},
                           {"by": "Overdue by assignee", "kind": "category", "data": count_by(over, lambda t: t["assignee"])}],
            "inputs": {"Open tickets": len(open_t), "Overdue": len(over), "On track": len(open_t) - len(over)},
            "sources": [src("jira")]}


@metric("ticket_mttr", "Ticket resolution time", unit=" days",
        description="Mean days from a remediation ticket being created to being marked Done, for tickets resolved in the last 90 days.",
        why="Measures how quickly engineering acts once security asks. Comparing it with vulnerability MTTR separates triage delay (before a ticket exists) from fix delay (after).",
        calculation="For each ticket resolved as Done in the last 90 days: resolved date − created date, in days. Value = mean.")
def _ticket_mttr(env):
    ts = _tickets(env)
    def resolved(as_of):
        lo = as_of - timedelta(days=90)
        return [t for t in ts if t["status"] == "Done" and t["_r"] and lo < t["_r"] <= as_of]
    days = lambda t: round((t["_r"] - t["_c"]).total_seconds() / 86400, 1)
    done = resolved(env.data.now)
    def at(w):
        sub = resolved(week_end_dt(env.data, w))
        return round(mean(days(t) for t in sub), 1) if sub else None
    rows_ = _ticket_rows(done, lambda t: {"days": days(t)})
    rows_.sort(key=lambda r: -r["days"])
    return {"value": round(mean(days(t) for t in done), 1) if done else None,
            "items": table([("key", "Ticket", "ticket"), ("summary", "Summary", "text"), ("priority", "Priority", "priority"), ("team", "Team", "text"),
                            ("created_at", "Created", "date"), ("resolved_at", "Resolved", "date"), ("days", "Days to resolve", "num")], rows_),
            "items_label": "Tickets resolved in the last 90 days, slowest first", "series": weekly(env.data, at),
            "breakdowns": [{"by": "Average days by team", "kind": "category", "data": avg_by(done, lambda t: t["team"], days)},
                           {"by": "Average days by priority", "kind": "priority", "data": avg_by(done, lambda t: t["priority"], days)}],
            "inputs": {"Resolved (90d)": len(done), "Fastest (days)": min((days(t) for t in done), default=0), "Slowest (days)": max((days(t) for t in done), default=0)},
            "sources": [src("jira")]}


@metric("tracking_coverage", "Remediation tracking coverage", unit="%", better="higher", pie=True, trend=False,
        description="The share of open critical and high vulnerabilities that have an active remediation ticket.",
        why="A vulnerability nobody has been asked to fix will not get fixed. Untracked critical/high findings are the gap between knowing about risk and acting on it.",
        calculation="100 × (open critical/high findings linked to a ticket in To Do, In Progress, In Review, or Done ÷ all open critical/high findings). The table lists untracked findings — create tickets for them from the asset or Active Threats views.")
def _coverage(env):
    idx = _ticket_index(env)
    open_ch = [f for f in env.findings() if f["severity"] in ("critical", "high")]
    tracked = [f for f in open_ch if f["id"] in idx and idx[f["id"]]["status"] != "Won't Fix"]
    untracked = [f for f in open_ch if f not in tracked]
    return {"value": metrics._pct(len(tracked), len(open_ch)), "items": table(FINDING_COLS, finding_rows(env, untracked)),
            "items_label": "Open critical/high findings with no ticket",
            "breakdowns": [{"by": "Tracked vs untracked", "kind": "status", "pie": True,
                            "data": [{"label": "Tracked", "value": len(tracked)}, {"label": "Not ticketed", "value": len(untracked)}]},
                           {"by": "Untracked by severity", "kind": "severity", "data": count_by(untracked, lambda f: f["severity"], SEVS)},
                           {"by": "Untracked by owner team", "kind": "category", "data": count_by(untracked, lambda f: f["owner_team"])}],
            "inputs": {"Open critical/high": len(open_ch), "With a ticket": len(tracked), "No ticket": len(untracked),
                       "Untracked on CISA KEV": sum(f["cve"] in env.data.kev for f in untracked)},
            "sources": env.tool_sources(VULN_SOURCES) + [src("jira")]}


@metric("awaiting_verification", "Awaiting verification", trend=False,
        description="Tickets marked Done in Jira where the scanner still detects at least one of the linked vulnerabilities.",
        why="Closing a ticket is not the same as removing the risk. These are fixes that were claimed but not confirmed — a patch that failed, a missed host, or a ticket closed too early.",
        calculation="Count of tickets in status Done that have one or more linked findings still open or in progress in the latest scan data.")
def _awaiting(env):
    ts = [t for t in _tickets(env) if t["status"] == "Done" and t["still_open"]]
    rows_ = _ticket_rows(ts, lambda t: {"still_open": t["still_open"]})
    return {"value": len(ts), "items": table(TICKET_COLS[:2] + [("team", "Team", "text"), ("assignee", "Assignee", "text"),
                                                                ("resolved_at", "Marked done", "date"), ("still_open", "Findings still detected", "num")], rows_),
            "items_label": "Done tickets the scanner disagrees with",
            "breakdowns": [{"by": "By team", "kind": "category", "data": count_by(ts, lambda t: t["team"])}],
            "inputs": {"Done tickets": sum(t["status"] == "Done" for t in _tickets(env)), "Awaiting verification": len(ts)},
            "sources": [src("jira")] + env.tool_sources(VULN_SOURCES)}


@metric("tickets_resolved", "Tickets resolved (30 days)", better="higher",
        description="Remediation tickets closed as Done in the last 30 days.",
        why="Remediation throughput. Compared with tickets created, it shows whether the backlog will shrink or grow.",
        calculation="Count of tickets whose resolution date falls in the last 30 days and whose status is Done.")
def _resolved(env):
    ts = _tickets(env)
    def done_in(as_of):
        return [t for t in ts if t["status"] == "Done" and t["_r"] and as_of - timedelta(days=30) < t["_r"] <= as_of]
    done = done_in(env.data.now)
    return {"value": len(done), "items": table(TICKET_COLS[:6] + [("resolved_at", "Resolved", "date")], _ticket_rows(done)),
            "series": weekly(env.data, lambda w: len(done_in(week_end_dt(env.data, w)))),
            "breakdowns": [{"by": "By team", "kind": "category", "data": count_by(done, lambda t: t["team"])},
                           {"by": "By priority", "kind": "priority", "pie": True, "data": count_by(done, lambda t: t["priority"], T_PRIORITIES)}],
            "inputs": {"Resolved (30d)": len(done), "Created (30d)": sum(1 for t in ts if t["_c"] > env.data.now - timedelta(days=30))},
            "sources": [src("jira")]}


# =========================================================================== entry point
def build(conn, key, params):
    m = REGISTRY[key]
    env = Env(conn, params)
    res = m.fn(env)
    series = res.get("series")
    if series and all(p["value"] is None for p in series):
        series = None
    return {
        "key": key, "params": {k: v for k, v in params.items() if v}, "label": res.get("label") or m.label, "unit": m.unit, "better": m.better,
        "value": res["value"], "description": res.get("description") or m.description, "why": m.why, "calculation": m.calculation,
        "inputs": res.get("inputs", {}), "sources": res.get("sources", []),
        "items": res.get("items"), "items_label": res.get("items_label") or "Affected records",
        "series": series, "series_label": res.get("series_label") or ("Weekly, last 13 weeks" if series else None),
        "breakdowns": [b for b in res.get("breakdowns", []) if b["data"]],
        "scope": TOOL.get(env.source) if env.source else None, "window_days": env.days,
    }
