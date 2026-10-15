"""Generates the simulated enterprise environment used when a security tool's
API is not connected. Data is deterministic (fixed random seed) and expressed
relative to today, so the demo always looks current.

Run directly to rebuild the database:  python -m app.seed
"""
import json
import math
import random
from datetime import date, datetime, timedelta, timezone

from . import catalog
from .db import get_conn, init_db

R = random.Random(42)
TODAY = date.today()
NOW = datetime.now(timezone.utc).replace(microsecond=0)


def d(days_ago: float) -> str:
    return (TODAY - timedelta(days=int(days_ago))).isoformat()


def ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _ip(prefix):
    return f"{prefix}.{R.randint(1, 254)}.{R.randint(1, 254)}"


# --------------------------------------------------------------------------- assets
def build_assets():
    assets = []

    def add(hostname, os_name, asset_type, env, software, crit, internet=False, edr_missing_p=0.06):
        roll = R.random()
        edr = "missing" if roll < edr_missing_p else ("rfm" if roll < edr_missing_p + 0.03 else "normal")
        scanned_ago = R.choice([R.randint(0, 14)] * 9 + [R.randint(31, 90)])  # ~10% stale scans
        assets.append({
            "hostname": hostname, "ip": _ip("10" if env == "on-prem" else "172"), "os": os_name,
            "asset_type": asset_type, "environment": env,
            "business_unit": "Corporate IT" if asset_type == "network" or os_name.startswith("VMware") else R.choice(catalog.BUSINESS_UNITS),
            "criticality": crit, "internet_facing": int(internet), "owner": R.choice(catalog.PEOPLE),
            "software": software, "edr_status": edr if asset_type != "network" else "n/a",
            "sensor_version": R.choice(["7.18.18702", "7.17.18607", "7.16.18405", "7.14.18110"]) if edr != "missing" and asset_type != "network" else None,
            "last_scanned": d(scanned_ago),
        })

    for i in range(230):
        if R.random() < 0.85:
            add(f"WS-{i:04d}", "Windows 11 23H2", "workstation", "on-prem",
                ["Windows 11", "Chrome", "Microsoft Office", "Outlook"], R.choice([1, 1, 2]))
        else:
            add(f"MAC-{i:04d}", "macOS 15", "workstation", "on-prem", ["macOS", "Chrome"], 1)

    roles = (["Active Directory"] * 4 + ["Exchange Server"] * 2 + ["SharePoint"] * 2 + ["Print Spooler"] * 6)
    for i in range(50):
        role = roles[i] if i < len(roles) else None
        sw = ["Windows Server"] + ([role] if role else [])
        crit = 5 if role in ("Active Directory", "Exchange Server") else R.choice([2, 3, 3, 4])
        name = {"Active Directory": "DC", "Exchange Server": "EXCH", "SharePoint": "SP"}.get(role, "WINSRV")
        add(f"{name}-{i:02d}", "Windows Server 2022", "server", "on-prem", sw, crit,
            internet=role == "Exchange Server" and i % 2 == 0)

    linux_roles = (["Log4j"] * 8 + ["Jenkins"] * 2 + ["Confluence"] * 2 + ["TeamCity", "MOVEit Transfer", "ScreenConnect"]
                   + ["PHP"] * 5 + ["Spring Framework"] * 4)
    for i in range(60):
        role = linux_roles[i] if i < len(linux_roles) else None
        sw = ["Linux kernel", "OpenSSH", "OpenSSL", "glibc"] + ([role] if role else [])
        internet = role in ("MOVEit Transfer", "ScreenConnect") or (role in ("Confluence", "PHP") and i % 2 == 0)
        crit = 5 if role in ("MOVEit Transfer", "Confluence") else R.choice([2, 3, 3, 4])
        add(f"LNX-{(role or 'app').split()[0].lower()}-{i:02d}", R.choice(["Ubuntu 22.04", "RHEL 9", "RHEL 8"]),
            "server", "on-prem", sw, crit, internet=internet, edr_missing_p=0.08)

    for i in range(6):
        add(f"ESX-{i:02d}", "VMware ESXi 8.0", "server", "on-prem", ["ESXi"], 5, edr_missing_p=1.0)

    for product, count, internet in [("FortiOS", 4, 2), ("PAN-OS", 3, 3), ("IOS XE", 6, 0), ("NetScaler", 2, 2),
                                      ("Ivanti Connect Secure", 2, 2), ("BIG-IP", 1, 1)]:
        for i in range(count):
            add(f"NET-{product.split()[0].lower()}-{i:02d}", product, "network", "on-prem", [product], 5,
                internet=i < internet)

    for env, count in [("aws", 40), ("azure", 20), ("gcp", 10)]:
        for i in range(count):
            role = R.choice(["Kubernetes", "nginx", "Node.js", None])
            sw = ["Linux kernel", "OpenSSH", "OpenSSL"] + ([role] if role else [])
            add(f"{env}-{R.choice(['web', 'api', 'worker', 'data'])}-{i:02d}", "Amazon Linux 2023" if env == "aws" else "Ubuntu 22.04",
                "cloud", env, sw, R.choice([2, 3, 4, 5]), internet=R.random() < 0.3, edr_missing_p=0.15)
    return assets


# --------------------------------------------------------------------------- findings
APP_ROLES = {"Log4j", "Jenkins", "Confluence", "TeamCity", "MOVEit Transfer", "ScreenConnect", "PHP", "Spring Framework"}


def owner_team(asset):
    """Who fixes it depends on what it is."""
    software = asset["software"] if isinstance(asset["software"], list) else json.loads(asset["software"] or "[]")
    if asset["asset_type"] == "network":
        return "Network Engineering"
    if asset["asset_type"] == "workstation":
        return "Endpoint Engineering"
    if asset["environment"] in ("aws", "azure", "gcp"):
        return R.choice(["Cloud Platform", "Cloud Platform", "DevOps"])
    if APP_ROLES & set(software):
        return R.choice(["App Security", "DevOps"])
    return "Infrastructure"


TAU = {"critical": 18, "high": 35, "medium": 90, "low": 160}


def _status_for(sev, age):
    """Older findings are more likely to have been remediated."""
    if R.random() < 1 - math.exp(-age / TAU[sev]):
        return "remediated", R.randint(1, max(1, age))
    roll = R.random()
    if sev in ("medium", "low") and roll < 0.05:
        return "risk_accepted", None
    return ("in_progress" if roll < 0.25 else "open"), None


def build_findings(assets):
    by_product = {}
    for cve in catalog.CVES:
        by_product.setdefault(cve[2], []).append(cve)
    findings = []
    for idx, a in enumerate(assets, start=1):
        if a["environment"] in ("aws", "azure", "gcp"):
            source = "wiz"
        elif a["asset_type"] == "workstation":
            source = "crowdstrike" if R.random() < 0.7 else "qualys"
        else:
            source = "qualys" if R.random() < 0.8 or a["edr_status"] == "missing" else "crowdstrike"
        for product in a["software"]:
            for cve, title, prod, cvss in by_product.get(product, []):
                sev = catalog.severity_from_cvss(cvss)
                p = {"critical": 0.22, "high": 0.3, "medium": 0.45, "low": 0.4}[sev]
                if a["asset_type"] == "workstation":
                    p *= 0.35
                if R.random() > p:
                    continue
                findings.append(_finding(idx, source, cve, title, catalog.TECH_STACK[prod][0], prod, cvss, sev, team=owner_team(a)))
        if a["asset_type"] != "workstation" and R.random() < 0.5:
            title, sev, cvss = R.choice(catalog.NON_CVE_FINDINGS)
            findings.append(_finding(idx, "qualys" if source != "wiz" else "wiz", None, title, None, None, cvss, sev, team=owner_team(a)))
    return findings


def _finding(asset_id, source, cve, title, vendor, product, cvss, sev, age=None, team=None):
    age = age if age is not None else R.randint(0, 150)
    status, fixed_after = _status_for(sev, age)
    first = TODAY - timedelta(days=age)
    prefix = {"qualys": "QID-", "crowdstrike": "SPT-", "wiz": "WIZ-"}[source]
    return {
        "source": source, "external_id": f"{prefix}{R.randint(10000, 99999)}", "asset_id": asset_id, "cve": cve,
        "title": title, "vendor": vendor, "product": product, "severity": sev, "cvss": cvss,
        "vendor_score": round(min(100, cvss * 10 + R.uniform(-8, 6)), 1), "status": status,
        "patch_available": int(R.random() < 0.9), "first_seen": first.isoformat(),
        "due_date": (first + timedelta(days=catalog.SLA_DAYS[sev])).isoformat(),
        "remediated_at": (first + timedelta(days=fixed_after)).isoformat() if fixed_after else None,
        "owner_team": team or R.choice(catalog.OWNER_TEAMS),
    }


# --------------------------------------------------------------------------- alerts
def build_alerts(assets):
    alerts = []
    users = [f"{f}{l}" for f in "ajmslrkdtn" for l in ["chen", "patel", "rivera", "okafor", "brooks", "nguyen"]]
    rates = {"crowdstrike": 5.0, "expel": 3.0, "wiz": 2.0, "qualys": 0.6}
    for day in range(90, -1, -1):
        dt_day = NOW - timedelta(days=day)
        weekend = dt_day.weekday() >= 5
        campaign = 19 <= day <= 24  # simulated phishing / BEC campaign
        progress = 1 - day / 90      # response gets faster over the quarter
        for source, rate in rates.items():
            lam = rate * (0.6 if weekend else 1.0)
            if campaign and source in ("expel", "crowdstrike"):
                lam += 6
            n = max(0, int(R.gauss(lam, math.sqrt(lam))))
            for _ in range(n):
                templates = catalog.ALERT_TEMPLATES[source]
                if campaign and source in ("expel", "crowdstrike") and R.random() < 0.6:
                    templates = [t for t in templates if t[3] in ("phishing", "bec", "identity")] or templates
                title, tactic, technique, category, sev = R.choice(templates)
                if R.random() < 0.15:
                    sev = {"critical": "high", "high": "medium", "medium": "low", "low": "low"}[sev]
                # Users trigger identity/phishing alerts in business hours; intrusions often run off-hours
                if category in ("ransomware", "c2", "cryptomining", "lateral_movement", "credential_theft") and R.random() < 0.5:
                    hour = R.randint(0, 5)
                else:
                    hour = R.choices(range(24), weights=[1] * 7 + [4] + [6] * 10 + [3, 2] + [1] * 4)[0]
                occurred = dt_day.replace(hour=hour, minute=R.randint(0, 59), second=0)
                if occurred > NOW:
                    occurred = NOW - timedelta(minutes=R.randint(30, 600))
                mttd = R.lognormvariate(math.log(35 - 15 * progress), 0.6)
                detected = occurred + timedelta(minutes=mttd)
                base_mttr = {"critical": 9 - 5 * progress, "high": 20 - 6 * progress, "medium": 48, "low": 90}[sev]
                age_h = (NOW - detected).total_seconds() / 3600
                resolve_h = R.lognormvariate(math.log(base_mttr), 0.5)
                if resolve_h < age_h:
                    status = "false_positive" if R.random() < 0.22 else "resolved"
                    resolved = ts(detected + timedelta(hours=resolve_h))
                else:
                    status = "investigating" if R.random() < 0.5 else "new"
                    resolved = None
                asset_pool = [i for i, a in enumerate(assets, 1)
                              if (source == "wiz") == (a["environment"] in ("aws", "azure", "gcp"))]
                alerts.append({
                    "source": source, "external_id": f"{source[:2].upper()}-{R.randint(100000, 999999)}", "title": title,
                    "severity": sev, "status": status, "category": category, "tactic": tactic, "technique": technique,
                    "asset_id": R.choice(asset_pool), "user_name": R.choice(users) if category in ("identity", "bec", "phishing") else None,
                    "occurred_at": ts(occurred), "detected_at": ts(detected), "resolved_at": resolved,
                    "is_incident": int(status != "false_positive" and sev in ("critical", "high") and R.random() < (0.3 if source == "expel" else 0.12)),
                })
    return alerts


def build_cloud_issues(assets):
    cloud_assets = [a for a in assets if a["environment"] in ("aws", "azure", "gcp")]
    issues = []
    for _ in range(230):
        a = R.choice(cloud_assets)
        rule, category, sev, rtype = R.choice(catalog.CLOUD_RULES)
        age = R.randint(0, 120)
        resolved = R.random() < 1 - math.exp(-age / (25 if sev == "critical" else 60))
        issues.append({
            "external_id": f"WIZ-ISS-{R.randint(10000, 99999)}", "resource": f"{a['hostname']}/{rtype.lower()}-{R.randint(1, 99)}",
            "resource_type": rtype, "cloud": a["environment"], "rule": rule, "category": category, "severity": sev,
            "status": "resolved" if resolved else "open", "internet_exposed": int(category in ("exposure", "toxic_combination") or a["internet_facing"]),
            "created_at": d(age), "resolved_at": d(age - R.randint(0, age)) if resolved else None,
        })
    return issues


def build_vendors():
    vendors = []
    troubled = {"Apex Backup Services", "Vector Marketing Cloud", "Tidewater Print & Mail", "Sierra Logistics"}
    for name, cat, tier, data in catalog.VENDORS:
        bad = name in troubled
        start_bs = R.randint(620, 700) if bad else R.randint(690, 800)
        start_ssc = R.randint(68, 80) if bad else R.randint(78, 94)
        drift = -R.randint(6, 12) if bad else R.randint(-2, 4)
        bs_hist, ssc_hist = [], []
        for m in range(12):
            bs_hist.append(max(250, min(900, start_bs + drift * m + R.randint(-10, 10))))
            ssc_hist.append(max(0, min(100, start_ssc + round(drift / 4 * m) + R.randint(-2, 2))))
        last = R.randint(30, 420)
        cycle = 365 if tier == 1 else 730
        vendors.append({
            "name": name, "category": cat, "tier": tier, "data_access": data,
            "bitsight_rating": bs_hist[-1], "bitsight_history": json.dumps(bs_hist),
            "ssc_score": ssc_hist[-1], "ssc_history": json.dumps(ssc_hist),
            "last_assessment": d(last), "next_assessment": (TODAY - timedelta(days=last) + timedelta(days=cycle)).isoformat(),
            "open_issues": R.randint(4, 14) if bad else R.randint(0, 4),
        })
    return vendors


def build_controls():
    out = []
    for fw, items, weights in [("NIST CSF 2.0", catalog.NIST_CSF, (0.6, 0.28, 0.12)),
                               ("ISO 27001:2022", catalog.ISO_27001, (0.65, 0.25, 0.10)),
                               ("GDPR", catalog.GDPR, (0.7, 0.2, 0.10))]:
        for cid, family, name in items:
            status = R.choices(["implemented", "partial", "not_implemented"], weights=weights)[0]
            out.append({"framework": fw, "control_id": cid, "family": family, "name": name, "status": status,
                        "owner": R.choice(catalog.PEOPLE), "auto_rule": catalog.AUTO_RULES.get((fw, cid)),
                        "last_reviewed": d(R.randint(10, 300))})
    return out


def build_roadmap():
    t = lambda days: (TODAY + timedelta(days=days)).isoformat()
    return [
        ("SOC 2 Type II audit fieldwork", "audit", "SOC 2", t(38), t(52), "S. Patel", "planned", "External auditor on-site; evidence requests due 2 weeks prior."),
        ("ISO 27001 surveillance audit", "audit", "ISO 27001:2022", t(74), t(76), "J. Chen", "planned", "Focus areas: A.8.8 vulnerability mgmt, A.5.22 supplier monitoring."),
        ("NIST CSF 2.0 self-assessment", "assessment", "NIST CSF 2.0", t(-20), t(18), "M. Okafor", "in_progress", "Quarterly maturity scoring with control owners."),
        ("GDPR DPIA refresh – customer analytics", "assessment", "GDPR", t(5), t(30), "L. Nguyen", "in_progress", None),
        ("Annual external penetration test", "pen_test", None, t(60), t(74), "R. Haddad", "planned", "Scope: internet-facing apps, VPN, cloud perimeter."),
        ("Ransomware tabletop exercise", "milestone", "NIST CSF 2.0", t(25), t(25), "A. Rivera", "planned", "Executive participation required."),
        ("Tier-1 vendor reassessments (Q4)", "assessment", "ISO 27001:2022", t(-10), t(45), "K. Johansson", "at_risk", "3 of 6 questionnaires outstanding."),
        ("Information security policy annual review", "policy_review", "ISO 27001:2022", t(90), t(110), "D. Brooks", "planned", None),
        ("EDR rollout to remaining cloud workloads", "milestone", None, t(-30), t(20), "J. Chen", "at_risk", "Blocked on change window for production clusters."),
        ("PCI DSS readiness review", "assessment", "PCI DSS 4.0", t(120), t(135), "S. Patel", "planned", None),
        ("Q3 access recertification", "milestone", "SOC 2", t(-45), t(-5), "M. Okafor", "complete", None),
    ]


GOALS = [
    ("Reduce critical vulnerability MTTR to 15 days", "crit_mttr_days", 34, 15, "lower", 120, "Infrastructure"),
    ("EDR coverage on all managed hosts ≥ 98%", "edr_coverage", 88, 98, "higher", 60, "Endpoint Engineering"),
    ("Zero actively exploited (KEV) vulnerabilities open", "kev_open", 12, 0, "lower", 45, "Vulnerability Mgmt"),
    ("Critical alert response under 4 hours", "alert_mttr_hours", 9, 4, "lower", 90, "SOC"),
    ("Tier-1 vendor average SecurityScorecard ≥ 85", "vendor_ssc_tier1", 80, 85, "higher", 180, "Third-Party Risk"),
    ("NIST CSF 2.0 implementation ≥ 85%", "compliance_nist", 52, 85, "higher", 150, "GRC"),
]


def _insert(conn, table, records):
    if not records:
        return
    cols = list(records[0].keys())
    sql = f"INSERT INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})"
    conn.executemany(sql, [[json.dumps(r[c]) if isinstance(r[c], list) else r[c] for c in cols] for r in records])


def seed(force=False):
    init_db()
    with get_conn() as conn:
        if not force and conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]:
            return False
        for t in ("findings", "alerts", "cloud_issues", "assets", "vendors", "controls", "roadmap", "goals"):
            conn.execute(f"DELETE FROM {t}")
        assets = build_assets()
        _insert(conn, "assets", assets)
        _insert(conn, "findings", build_findings(assets))
        _insert(conn, "alerts", build_alerts(assets))
        _insert(conn, "cloud_issues", build_cloud_issues(assets))
        _insert(conn, "vendors", build_vendors())
        _insert(conn, "controls", build_controls())
        conn.executemany("INSERT INTO roadmap (title,item_type,framework,start_date,due_date,owner,status,notes) VALUES (?,?,?,?,?,?,?,?)", build_roadmap())
        conn.executemany("INSERT INTO goals (title,metric_key,baseline,target,direction,due_date,owner) VALUES (?,?,?,?,?,?,?)",
                         [(g[0], g[1], g[2], g[3], g[4], (TODAY + timedelta(days=g[5])).isoformat(), g[6]) for g in GOALS])
    return True


def inject_recent_kev(n=6):
    """Simulates exposure to the newest CISA KEV additions.

    The fixed catalog only contains well-known CVEs, so recent news would never
    match. This places the n most recently added KEV CVEs on plausible hosts in
    the simulated environment so the correlation engine has current matches.
    Only used for mock data; live connectors report real findings.
    """
    with get_conn() as conn:
        candidates = [dict(r) for r in conn.execute(
            """SELECT * FROM kev WHERE cve NOT IN (SELECT cve FROM findings WHERE cve IS NOT NULL)
               AND product NOT LIKE 'Multiple%' AND date_added >= ? ORDER BY date_added DESC""",
            ((TODAY - timedelta(days=90)).isoformat(),))]
        assets = [dict(r) for r in conn.execute("SELECT id, software, asset_type, environment FROM assets WHERE asset_type IN ('server','network','cloud')")]

        def matches_for(k):
            text = f"{k['vendor']} {k['product']}".lower()
            return [a for a in assets if any(s.lower() in text or text in s.lower() for s in json.loads(a["software"]))]

        # Prefer CVEs in products we actually run (realistic exposure), then the newest others
        in_stack = [k for k in candidates if matches_for(k)][: n - 2]
        recent = in_stack + [k for k in candidates if k not in in_stack][: n - len(in_stack)]
        added = []
        for k in recent:
            matches = matches_for(k)
            targets = R.sample(matches, min(len(matches), 3)) if matches else R.sample([a for a in assets if a["asset_type"] == "server"], R.randint(1, 3))
            for a in targets:
                sw = json.loads(a["software"])
                if k["product"] not in sw:
                    sw.append(k["product"])
                    conn.execute("UPDATE assets SET software=? WHERE id=?", (json.dumps(sw), a["id"]))
                source = "wiz" if a["environment"] in ("aws", "azure", "gcp") else "qualys"
                f = _finding(a["id"], source, k["cve"], k["name"], k["vendor"], k["product"], 8.8, "high",
                             age=max(0, (TODAY - date.fromisoformat(k["date_added"])).days - 1), team=owner_team(a))
                f["status"], f["remediated_at"] = "open", None
                _insert(conn, "findings", [f])
            added.append(k["cve"])
        return added


if __name__ == "__main__":
    seed(force=True)
    print("Database seeded.")
