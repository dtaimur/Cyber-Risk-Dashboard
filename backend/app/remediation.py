"""Remediation workflow: vulnerabilities -> Jira tickets -> verified closure.

Tickets are created from an active threat (one CVE across all affected
assets) or from a single finding. When Jira is connected, the issue is created
in Jira and status changes flow both ways; otherwise tickets are kept in the
dashboard's own tracker with the same fields and workflow, so the process and
metrics are identical.

Closing a ticket does not close the vulnerability: the scanner has to stop
detecting it. Tickets marked Done whose findings are still open are reported
as "awaiting verification".
"""
import random
from datetime import date, datetime, timedelta, timezone

from fastapi import HTTPException

from . import catalog, integrations, threat_intel
from .auth import audit
from .connectors import CONNECTORS
from .connectors.base import ConnectorError
from .db import get_conn, one, rows

STATUSES = ["To Do", "In Progress", "In Review", "Done", "Won't Fix"]
OPEN = ("To Do", "In Progress", "In Review")
CLOSED = ("Done", "Won't Fix")
PRIORITIES = ["Highest", "High", "Medium", "Low"]
DEFAULT_PROJECT = "SEC"


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def jira_live():
    """(cfg, secret) when a Jira site is connected and enabled, else None."""
    st = integrations.state("jira") or {}
    if not st.get("enabled"):
        return None
    cfg, secret = integrations.credentials("jira")
    return (cfg, secret) if secret and cfg.get("base_url") else None


def priority_for(severity, in_kev=False, internet=False, score=None):
    if score is not None:
        return "Highest" if score >= 75 else "High" if score >= 60 else "Medium"
    base = {"critical": 0, "high": 1, "medium": 2, "low": 3}[severity]
    if in_kev or internet:
        base = max(0, base - 1)
    return PRIORITIES[base]


# ----------------------------------------------------------------------------- drafts
def draft_from_threat(conn, cve: str):
    threat = next((t for t in threat_intel.active_threats(conn) if t["cve"] == cve), None)
    fs = rows(conn, """SELECT f.*, a.hostname, a.internet_facing, a.owner, a.business_unit FROM findings f JOIN assets a ON a.id=f.asset_id
                       WHERE f.cve=? AND f.status IN ('open','in_progress') ORDER BY a.internet_facing DESC, f.due_date""", (cve,))
    if not fs:
        raise HTTPException(404, "No open findings for this CVE")
    f0 = fs[0]
    teams = {}
    for f in fs:
        teams[f["owner_team"]] = teams.get(f["owner_team"], 0) + 1
    hosts = "\n".join(f"- {f['hostname']} ({f['business_unit']}{', internet-facing' if f['internet_facing'] else ''}) via {f['source'].title()}" for f in fs[:25])
    intel = []
    if threat:
        if threat["in_kev"]:
            intel.append(f"Listed on CISA Known Exploited Vulnerabilities (added {threat['kev_date_added']})"
                         + (" and linked to ransomware campaigns" if threat["ransomware"] else ""))
        intel.append(f"EPSS exploit probability: {threat['epss'] * 100:.1f}%")
        intel += [f"News: {n['title']} ({n['source']}) {n['link']}" for n in threat["news"][:3]]
    description = "\n\n".join(filter(None, [
        f"{cve} — {threat['title'] if threat else f0['title']}",
        threat["description"] if threat and threat.get("description") else None,
        f"Priority score {threat['priority']}/100 (CVSS {f0['cvss']}). " if threat else f"CVSS {f0['cvss']}.",
        "Why this is prioritized:\n" + "\n".join(f"- {i}" for i in intel) if intel else None,
        f"Affected assets ({len(fs)}):\n{hosts}",
        f"Required action: {threat['required_action'] if threat else 'Apply the vendor security update or mitigation.'}",
        "Closure criteria: the next scan no longer detects this CVE on any listed asset.",
        "Created from the Cyber Risk Dashboard.",
    ]))
    return {
        "summary": f"[{cve}] Remediate {(threat or {}).get('product') or f0['product'] or f0['title']} on {len(fs)} asset{'s' if len(fs) > 1 else ''}",
        "description": description, "priority": priority_for(f0["severity"], score=threat["priority"] if threat else None),
        "team": max(teams, key=teams.get), "assignee": f0["owner"], "due_date": min(f["due_date"] for f in fs),
        "cve": cve, "source_type": "threat", "finding_ids": [f["id"] for f in fs],
    }


def draft_from_finding(conn, finding_id: int):
    f = one(conn, """SELECT f.*, a.hostname, a.internet_facing, a.owner, a.business_unit FROM findings f JOIN assets a ON a.id=f.asset_id
                     WHERE f.id=?""", (finding_id,))
    if not f:
        raise HTTPException(404, "Finding not found")
    in_kev = bool(f["cve"] and one(conn, "SELECT 1 AS x FROM kev WHERE cve=?", (f["cve"],)))
    label = f["cve"] or f["external_id"]
    return {
        "summary": f"[{label}] {f['title']} on {f['hostname']}"[:250],
        "description": "\n\n".join(filter(None, [
            f"{f['title']} ({f['cve']})" if f["cve"] else f["title"],
            f"Asset: {f['hostname']} ({f['business_unit']}{', internet-facing' if f['internet_facing'] else ''})",
            f"Severity: {f['severity']} · CVSS {f['cvss']} · detected by {f['source'].title()} on {f['first_seen']}",
            "Actively exploited: listed on CISA KEV." if in_kev else None,
            f"Remediation SLA due: {f['due_date']}",
            "Closure criteria: the next scan no longer detects this finding.",
            "Created from the Cyber Risk Dashboard.",
        ])),
        "priority": priority_for(f["severity"], in_kev, bool(f["internet_facing"])), "team": f["owner_team"],
        "assignee": f["owner"], "due_date": f["due_date"], "cve": f["cve"], "source_type": "finding", "finding_ids": [f["id"]],
    }


# ----------------------------------------------------------------------------- create / update
def create(draft: dict, actor: str):
    live = jira_live()
    url, is_live = None, 0
    with get_conn() as conn:
        dup = one(conn, f"""SELECT t.key FROM tickets t JOIN ticket_findings tf ON tf.ticket_id=t.id
                            WHERE tf.finding_id IN ({','.join('?' * len(draft['finding_ids']))}) AND t.status IN ('To Do','In Progress','In Review')""",
                  draft["finding_ids"]) if draft["finding_ids"] else None
    if dup:
        raise HTTPException(409, f"These findings are already tracked in {dup['key']}")
    if live:
        cfg, secret = live
        try:
            key, url = CONNECTORS["jira"].create_issue(cfg, secret, draft)
            is_live = 1
        except ConnectorError as exc:
            raise HTTPException(502, f"Jira rejected the issue: {exc}")
        except Exception as exc:
            raise HTTPException(502, f"Could not reach Jira: {type(exc).__name__}")
    with get_conn() as conn:
        if not is_live:
            n = conn.execute("SELECT COUNT(*) FROM tickets").fetchone()[0]
            key = f"{DEFAULT_PROJECT}-{101 + n}"
            while one(conn, "SELECT 1 AS x FROM tickets WHERE key=?", (key,)):
                n += 1
                key = f"{DEFAULT_PROJECT}-{101 + n}"
        cur = conn.execute("""INSERT INTO tickets (key, summary, description, status, priority, team, assignee, reporter, source_type, cve,
                                                   created_at, updated_at, due_date, url, is_live) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                           (key, draft["summary"], draft["description"], "To Do", draft["priority"], draft["team"], draft.get("assignee"),
                            actor, draft["source_type"], draft.get("cve"), _now(), _now(), draft.get("due_date"), url, is_live))
        conn.executemany("INSERT OR IGNORE INTO ticket_findings (ticket_id, finding_id) VALUES (?,?)",
                         [(cur.lastrowid, fid) for fid in draft["finding_ids"]])
        audit(conn, actor, "ticket.create", {"key": key, "findings": len(draft["finding_ids"]), "jira": bool(is_live)})
    return get(key)


def update(key: str, changes: dict, actor: str):
    with get_conn() as conn:
        t = one(conn, "SELECT * FROM tickets WHERE key=?", (key,))
    if not t:
        raise HTTPException(404, "Ticket not found")
    if "status" in changes and changes["status"] != t["status"] and t["is_live"]:
        live = jira_live()
        if not live:
            raise HTTPException(409, "This issue lives in Jira, which is not connected")
        try:
            CONNECTORS["jira"].transition(*live, key, changes["status"])
        except ConnectorError as exc:
            raise HTTPException(502, str(exc))
    sets = {k: v for k, v in changes.items() if v is not None}
    if "status" in sets:
        sets["resolved_at"] = _now() if sets["status"] in CLOSED else None
    sets["updated_at"] = _now()
    with get_conn() as conn:
        conn.execute(f"UPDATE tickets SET {', '.join(k + '=?' for k in sets)} WHERE key=?", [*sets.values(), key])
        # Accepting risk is a decision about the findings too; record it so they leave the SLA backlog
        if sets.get("status") == "Won't Fix":
            conn.execute("""UPDATE findings SET status='risk_accepted' WHERE status IN ('open','in_progress')
                            AND id IN (SELECT finding_id FROM ticket_findings WHERE ticket_id=?)""", (t["id"],))
        elif sets.get("status") in ("In Progress", "In Review"):
            conn.execute("""UPDATE findings SET status='in_progress' WHERE status='open'
                            AND id IN (SELECT finding_id FROM ticket_findings WHERE ticket_id=?)""", (t["id"],))
        audit(conn, actor, "ticket.update", {"key": key, **{k: v for k, v in changes.items() if v is not None}})
    return get(key)


def sync_from_jira():
    live = jira_live()
    if not live:
        raise ConnectorError("Jira is not connected")
    issues = CONNECTORS["jira"].fetch_issues(*live)
    with get_conn() as conn:
        known = {r["key"] for r in conn.execute("SELECT key FROM tickets WHERE is_live=1")}
        for i in issues:
            if i["key"] not in known:
                continue
            status = i["status"] if i["status"] in STATUSES else i["category"]
            conn.execute("UPDATE tickets SET status=?, assignee=COALESCE(?, assignee), resolved_at=?, due_date=COALESCE(?, due_date), updated_at=? WHERE key=?",
                         (status, i["assignee"], _now() if status in CLOSED else None, i["due_date"], _now(), i["key"]))
    return len(issues)


# ----------------------------------------------------------------------------- reads
def _verify_state(conn, ticket_id, status):
    fs = rows(conn, "SELECT f.status FROM findings f JOIN ticket_findings tf ON tf.finding_id=f.id WHERE tf.ticket_id=?", (ticket_id,))
    still_open = sum(f["status"] in ("open", "in_progress") for f in fs)
    if status == "Done":
        return "awaiting_verification" if still_open else "verified"
    return None


def get(key):
    with get_conn() as conn:
        t = one(conn, "SELECT * FROM tickets WHERE key=?", (key,))
        if not t:
            raise HTTPException(404, "Ticket not found")
        t["findings"] = rows(conn, """SELECT f.id, f.severity, f.title, f.cve, f.status, f.source, f.due_date, a.hostname, a.id AS asset_id,
                                             a.internet_facing FROM findings f JOIN ticket_findings tf ON tf.finding_id=f.id
                                      JOIN assets a ON a.id=f.asset_id WHERE tf.ticket_id=? ORDER BY a.hostname""", (t["id"],))
        t["verification"] = _verify_state(conn, t["id"], t["status"])
        t["history"] = rows(conn, "SELECT ts, actor, action, detail FROM audit_log WHERE action LIKE 'ticket.%' AND detail LIKE ? ORDER BY id DESC LIMIT 20",
                            (f'%"key": "{key}"%',))
    return t


def finding_ticket_index(conn):
    """finding_id -> most relevant ticket (open ones win over closed)."""
    idx = {}
    for r in conn.execute("""SELECT tf.finding_id, t.key, t.status FROM ticket_findings tf JOIN tickets t ON t.id=tf.ticket_id
                             ORDER BY CASE WHEN t.status IN ('To Do','In Progress','In Review') THEN 1 ELSE 0 END, t.id"""):
        idx[r["finding_id"]] = {"key": r["key"], "status": r["status"]}
    return idx


# ----------------------------------------------------------------------------- seed history
def seed_tickets(force=False):
    """Simulated Jira history for the mock environment: critical/high findings
    grouped per CVE and owning team, with statuses consistent with the scanner."""
    R = random.Random(7)
    with get_conn() as conn:
        if not force and conn.execute("SELECT COUNT(*) FROM tickets").fetchone()[0]:
            return
        conn.execute("DELETE FROM tickets")
        fs = rows(conn, """SELECT f.*, a.owner FROM findings f JOIN assets a ON a.id=f.asset_id
                           WHERE f.severity IN ('critical','high') AND f.is_live=0 ORDER BY f.first_seen""")
        kev = {r["cve"] for r in conn.execute("SELECT cve FROM kev")}
        recent_cut = (date.today() - timedelta(days=21)).isoformat()
        groups = {}
        for f in fs:
            if f["status"] == "open" and (f["first_seen"] >= recent_cut or R.random() < 0.35):
                continue  # not yet triaged: shows up as "untracked"
            groups.setdefault((f["cve"] or f["title"], f["owner_team"]), []).append(f)
        n = 0
        for (ident, team), group in sorted(groups.items(), key=lambda kv: min(f["first_seen"] for f in kv[1])):
            first = min(date.fromisoformat(f["first_seen"]) for f in group)
            statuses = {f["status"] for f in group}
            fixed = max((date.fromisoformat(f["remediated_at"]) for f in group if f["remediated_at"]), default=None)
            # Triage delay: tickets are raised some days after detection (and before the fix)
            window = ((fixed - first).days - 1) if fixed and statuses == {"remediated"} else 21
            triage = R.randint(1, max(1, min(window, 21)))
            created = datetime.combine(first + timedelta(days=triage), datetime.min.time(), timezone.utc) + timedelta(hours=R.randint(8, 17))
            created = min(created, datetime.now(timezone.utc) - timedelta(hours=2))
            resolved = None
            due = min(f["due_date"] for f in group)
            if statuses == {"remediated"}:
                status = "Done"
                resolved = datetime.combine(max(fixed - timedelta(days=R.randint(0, 2)), created.date()), datetime.min.time(), timezone.utc) + timedelta(hours=R.randint(9, 18))
            elif "in_progress" in statuses:
                status = R.choice(["In Progress", "In Progress", "In Review"])
            else:
                status = "To Do"
            if status != "Done" and R.random() < 0.55:  # approved SLA extension / negotiated date
                due = (date.today() + timedelta(days=R.randint(3, 30))).isoformat()
            if status == "To Do" and R.random() < 0.08:  # engineer closed it, scanner disagrees
                status, resolved = "Done", datetime.now(timezone.utc) - timedelta(days=R.randint(1, 6))
            sev = "critical" if any(f["severity"] == "critical" for f in group) else "high"
            cve = group[0]["cve"]
            key = f"{DEFAULT_PROJECT}-{101 + n}"
            n += 1
            product = group[0]["product"] or group[0]["title"]
            ts = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ") if d else None
            cur = conn.execute("""INSERT INTO tickets (key, summary, description, status, priority, team, assignee, reporter, source_type, cve,
                                                       created_at, updated_at, due_date, resolved_at, is_live) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)""",
                               (key, f"[{cve or 'Config'}] Remediate {product} on {len(group)} asset{'s' if len(group) > 1 else ''}",
                                f"{ident}\n\nAffected assets: {len(group)}\n\nCreated from the Cyber Risk Dashboard.", status,
                                priority_for(sev, cve in kev), team, R.choice(catalog.PEOPLE), "analyst", "threat" if cve else "finding", cve,
                                ts(created), ts(resolved or created), due, ts(resolved)))
            conn.executemany("INSERT INTO ticket_findings (ticket_id, finding_id) VALUES (?,?)", [(cur.lastrowid, f["id"]) for f in group])
