"""Compliance frameworks, security goals, and the editable audit/assessment roadmap."""
from datetime import date
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, model_validator

from .. import metrics
from ..db import get_conn, one, rows
from ..metrics import Data
from ..auth import audit, require

router = APIRouter(prefix="/api/compliance")

ItemType = Literal["audit", "assessment", "pen_test", "certification", "policy_review", "milestone"]
ItemStatus = Literal["planned", "in_progress", "at_risk", "complete"]


class RoadmapItem(BaseModel):
    title: str = Field(min_length=3, max_length=120)
    item_type: ItemType
    framework: str | None = Field(None, max_length=40)
    start_date: date
    due_date: date
    owner: str = Field(min_length=1, max_length=60)
    status: ItemStatus = "planned"
    notes: str | None = Field(None, max_length=500)

    @model_validator(mode="after")
    def dates_in_order(self):
        if self.due_date < self.start_date:
            raise ValueError("due_date must be on or after start_date")
        return self


class Goal(BaseModel):
    title: str = Field(min_length=3, max_length=120)
    metric_key: Literal[tuple(metrics.GOAL_METRICS)]  # type: ignore[valid-type]
    baseline: float
    target: float
    direction: Literal["lower", "higher"]
    due_date: date
    owner: str = Field(min_length=1, max_length=60)


class ControlUpdate(BaseModel):
    status: Literal["implemented", "partial", "not_implemented"]


@router.get("", dependencies=[Depends(require("view_compliance"))])
def overview():
    with get_conn() as conn:
        data = Data(conn)
        ctx = metrics.context(data)
        goals = [metrics.goal_progress(g, ctx) for g in rows(conn, "SELECT * FROM goals ORDER BY due_date")]
        roadmap = rows(conn, "SELECT * FROM roadmap ORDER BY start_date")
    return {"frameworks": ctx["frameworks"], "controls": ctx["controls"], "goals": goals, "roadmap": roadmap,
            "goal_metrics": {k: {"label": v[0], "unit": v[1]} for k, v in metrics.GOAL_METRICS.items()}}


@router.patch("/controls/{control_id}")
def update_control(control_id: int, body: ControlUpdate, user=Depends(require("edit_compliance"))):
    with get_conn() as conn:
        c = one(conn, "SELECT * FROM controls WHERE id=?", (control_id,))
        if not c:
            raise HTTPException(404, "Control not found")
        if c["auto_rule"]:
            raise HTTPException(409, "This control is evaluated automatically from live security data")
        conn.execute("UPDATE controls SET status=?, last_reviewed=? WHERE id=?", (body.status, date.today().isoformat(), control_id))
        audit(conn, user["username"], "control.update", f"{c['framework']} {c['control_id']} -> {body.status}")
    return {"ok": True}


@router.post("/roadmap", status_code=201)
def create_item(item: RoadmapItem, user=Depends(require("edit_compliance"))):
    with get_conn() as conn:
        cur = conn.execute("INSERT INTO roadmap (title,item_type,framework,start_date,due_date,owner,status,notes) VALUES (?,?,?,?,?,?,?,?)",
                           _vals(item))
        audit(conn, user["username"], "roadmap.create", item.title)
        return one(conn, "SELECT * FROM roadmap WHERE id=?", (cur.lastrowid,))


@router.put("/roadmap/{item_id}")
def update_item(item_id: int, item: RoadmapItem, user=Depends(require("edit_compliance"))):
    with get_conn() as conn:
        if not one(conn, "SELECT id FROM roadmap WHERE id=?", (item_id,)):
            raise HTTPException(404, "Roadmap item not found")
        conn.execute("UPDATE roadmap SET title=?,item_type=?,framework=?,start_date=?,due_date=?,owner=?,status=?,notes=? WHERE id=?",
                     _vals(item) + (item_id,))
        audit(conn, user["username"], "roadmap.update", item.title)
        return one(conn, "SELECT * FROM roadmap WHERE id=?", (item_id,))


@router.delete("/roadmap/{item_id}", status_code=204)
def delete_item(item_id: int, user=Depends(require("edit_compliance"))):
    with get_conn() as conn:
        row = one(conn, "SELECT title FROM roadmap WHERE id=?", (item_id,))
        if not row:
            raise HTTPException(404, "Roadmap item not found")
        conn.execute("DELETE FROM roadmap WHERE id=?", (item_id,))
        audit(conn, user["username"], "roadmap.delete", row["title"])


@router.post("/goals", status_code=201)
def create_goal(g: Goal, user=Depends(require("edit_compliance"))):
    with get_conn() as conn:
        cur = conn.execute("INSERT INTO goals (title,metric_key,baseline,target,direction,due_date,owner) VALUES (?,?,?,?,?,?,?)",
                           (g.title, g.metric_key, g.baseline, g.target, g.direction, g.due_date.isoformat(), g.owner))
        audit(conn, user["username"], "goal.create", g.title)
        return {"id": cur.lastrowid}


@router.put("/goals/{goal_id}")
def update_goal(goal_id: int, g: Goal, user=Depends(require("edit_compliance"))):
    with get_conn() as conn:
        if not one(conn, "SELECT id FROM goals WHERE id=?", (goal_id,)):
            raise HTTPException(404, "Goal not found")
        conn.execute("UPDATE goals SET title=?,metric_key=?,baseline=?,target=?,direction=?,due_date=?,owner=? WHERE id=?",
                     (g.title, g.metric_key, g.baseline, g.target, g.direction, g.due_date.isoformat(), g.owner, goal_id))
        audit(conn, user["username"], "goal.update", g.title)
    return {"ok": True}


@router.delete("/goals/{goal_id}", status_code=204)
def delete_goal(goal_id: int, user=Depends(require("edit_compliance"))):
    with get_conn() as conn:
        conn.execute("DELETE FROM goals WHERE id=?", (goal_id,))
        audit(conn, user["username"], "goal.delete", str(goal_id))


def _vals(item: RoadmapItem):
    return (item.title, item.item_type, item.framework, item.start_date.isoformat(), item.due_date.isoformat(), item.owner, item.status, item.notes)
