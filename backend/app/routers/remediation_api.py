"""Remediation workflow API: Jira tickets for vulnerabilities, and tracking metrics."""
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from statistics import mean
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, model_validator

from .. import remediation
from ..auth import require
from ..db import get_conn, rows
from ..integrations import tool_modes

router = APIRouter(prefix="/api/remediation")

Status = Literal["To Do", "In Progress", "In Review", "Done", "Won't Fix"]
Priority = Literal["Highest", "High", "Medium", "Low"]


class DraftRequest(BaseModel):
    source_type: Literal["threat", "finding"]
    cve: str | None = Field(None, pattern=r"^CVE-\d{4}-\d{4,7}$")
    finding_id: int | None = None

    @model_validator(mode="after")
    def has_source(self):
        if (self.source_type == "threat") != bool(self.cve) or (self.source_type == "finding") != bool(self.finding_id):
            raise ValueError("threat requires cve; finding requires finding_id")
        return self


class TicketCreate(DraftRequest):
    summary: str = Field(min_length=5, max_length=250)
    description: str = Field(max_length=8000)
    priority: Priority
    team: str = Field(min_length=1, max_length=60)
    assignee: str | None = Field(None, max_length=60)
    due_date: date | None = None


class TicketUpdate(BaseModel):
    status: Status | None = None
    priority: Priority | None = None
    assignee: str | None = Field(None, max_length=60)
    team: str | None = Field(None, max_length=60)
    due_date: date | None = None


def _draft(conn, req: DraftRequest):
    return remediation.draft_from_threat(conn, req.cve) if req.source_type == "threat" else remediation.draft_from_finding(conn, req.finding_id)


@router.post("/draft", dependencies=[Depends(require("manage_remediation"))])
def draft(req: DraftRequest):
    """Pre-filled ticket built from the threat/finding, for the user to review before creating."""
    with get_conn() as conn:
        d = _draft(conn, req)
    return {**d, "destination": "jira" if remediation.jira_live() else "local"}


@router.post("/tickets", status_code=201)
def create_ticket(body: TicketCreate, user=Depends(require("manage_remediation"))):
    with get_conn() as conn:
        d = _draft(conn, body)  # findings come from the server-side lookup, never from the client
    d.update({k: getattr(body, k) for k in ("summary", "description", "priority", "team", "assignee")})
    d["due_date"] = body.due_date.isoformat() if body.due_date else d["due_date"]
    return remediation.create(d, user["username"])


@router.patch("/tickets/{key}")
def update_ticket(key: str, body: TicketUpdate, user=Depends(require("manage_remediation"))):
    changes = body.model_dump(exclude_none=True)
    if "due_date" in changes:
        changes["due_date"] = changes["due_date"].isoformat()
    if not changes:
        raise HTTPException(422, "Nothing to update")
    return remediation.update(key, changes, user["username"])


@router.get("/tickets/{key}", dependencies=[Depends(require("view_details"))])
def ticket(key: str):
    return remediation.get(key)


@router.get("/tickets", dependencies=[Depends(require("view_details"))])
def tickets(status: str | None = Query(None, pattern="^(open|closed|overdue|To Do|In Progress|In Review|Done|Won't Fix)$"),
            team: str | None = Query(None, max_length=60), priority: Priority | None = None, q: str | None = Query(None, max_length=100),
            limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    where, params = [], []
    if status == "open":
        where.append("t.status IN ('To Do','In Progress','In Review')")
    elif status == "closed":
        where.append("t.status IN ('Done','Won''t Fix')")
    elif status == "overdue":
        where.append("t.status IN ('To Do','In Progress','In Review') AND t.due_date < ?"); params.append(date.today().isoformat())
    elif status:
        where.append("t.status = ?"); params.append(status)
    if team:
        where.append("t.team = ?"); params.append(team)
    if priority:
        where.append("t.priority = ?"); params.append(priority)
    if q:
        where.append("(t.key LIKE ? OR t.summary LIKE ? OR t.cve LIKE ? OR t.assignee LIKE ?)"); params += [f"%{q}%"] * 4
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    with get_conn() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM tickets t {clause}", params).fetchone()[0]
        items = rows(conn, f"""SELECT t.*, (SELECT COUNT(*) FROM ticket_findings tf WHERE tf.ticket_id=t.id) AS finding_count,
                                      (SELECT COUNT(*) FROM ticket_findings tf JOIN findings f ON f.id=tf.finding_id
                                       WHERE tf.ticket_id=t.id AND f.status IN ('open','in_progress')) AS still_open
                               FROM tickets t {clause}
                               ORDER BY CASE t.status WHEN 'To Do' THEN 0 WHEN 'In Progress' THEN 1 WHEN 'In Review' THEN 2 ELSE 3 END,
                                        CASE t.priority WHEN 'Highest' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, t.due_date
                               LIMIT ? OFFSET ?""", params + [limit, offset])
    for t in items:
        t["verification"] = ("awaiting_verification" if t["still_open"] else "verified") if t["status"] == "Done" else None
    return {"total": total, "items": items}


def _ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


@router.get("/overview", dependencies=[Depends(require("view_details"))])
def overview():
    """Page data for the Jira remediation view (KPIs come from the metric catalog)."""
    today = date.today()
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        ts = rows(conn, "SELECT * FROM tickets")
        open_ch = rows(conn, "SELECT id FROM findings WHERE severity IN ('critical','high') AND status IN ('open','in_progress')")
        tracked = {r["finding_id"] for r in conn.execute("""SELECT tf.finding_id FROM ticket_findings tf JOIN tickets t ON t.id=tf.ticket_id
                                                             WHERE t.status IN ('To Do','In Progress','In Review','Done')""")}
    for t in ts:
        t["_c"], t["_r"] = _ts(t["created_at"]), _ts(t["resolved_at"])
    weekly = []
    for w in range(12, -1, -1):
        end = now - timedelta(days=7 * w)
        start = end - timedelta(days=7)
        weekly.append({"date": end.date().isoformat(),
                       "created": sum(1 for t in ts if start < t["_c"] <= end),
                       "resolved": sum(1 for t in ts if t["_r"] and start < t["_r"] <= end),
                       "open": sum(1 for t in ts if t["_c"] <= end and (not t["_r"] or t["_r"] > end))})
    open_t = [t for t in ts if t["status"] in remediation.OPEN]
    buckets = [("0–7 days", 0, 7), ("8–30 days", 8, 30), ("31–60 days", 31, 60), ("60+ days", 61, 10_000)]
    aging = [{"bucket": b, **{p: sum(1 for t in open_t if t["priority"] == p and lo <= (now - t["_c"]).days <= hi) for p in remediation.PRIORITIES}}
             for b, lo, hi in buckets]
    teams = sorted({t["team"] for t in ts})
    by_team = []
    for team in teams:
        tt = [t for t in ts if t["team"] == team]
        closed = [t for t in tt if t["status"] == "Done" and t["_r"]]
        by_team.append({"team": team, **{s: sum(1 for t in tt if t["status"] == s) for s in remediation.STATUSES},
                        "overdue": sum(1 for t in tt if t["status"] in remediation.OPEN and t["due_date"] and t["due_date"] < today.isoformat()),
                        "mttr_days": round(mean((t["_r"] - t["_c"]).days for t in closed), 1) if closed else None})
    assignees = Counter(t["assignee"] for t in open_t if t["assignee"])
    return {
        "status_counts": [{"status": s, "count": sum(1 for t in ts if t["status"] == s)} for s in remediation.STATUSES],
        "weekly": weekly, "aging": aging, "by_team": by_team,
        "workload": [{"assignee": a, "open": n, "overdue": sum(1 for t in open_t if t["assignee"] == a and t["due_date"] and t["due_date"] < today.isoformat())}
                     for a, n in assignees.most_common()],
        "untracked_critical_high": len([f for f in open_ch if f["id"] not in tracked]),
        "teams": teams, "destination": "jira" if remediation.jira_live() else "local", "mode": tool_modes().get("jira", "mock"),
    }
