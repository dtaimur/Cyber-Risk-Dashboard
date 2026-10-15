"""Metric detail endpoint: value, affected records, explanation, sources, formula, trend, breakdowns."""
from fastapi import APIRouter, Depends, HTTPException, Query

from .. import metric_catalog
from ..db import get_conn
from ..auth import can, require

router = APIRouter(prefix="/api/metrics")


@router.get("", dependencies=[Depends(require("view_summary"))])
def catalog():
    return {m.key: {"label": m.label, "unit": m.unit, "better": m.better, "trend": m.trend, "bars": m.bars, "pie": m.pie}
            for m in metric_catalog.REGISTRY.values()}


@router.get("/{key}")
def metric_detail(key: str,
                  source: str | None = Query(None, pattern="^(qualys|crowdstrike|expel|wiz)$"),
                  days: int = Query(30, ge=7, le=180),
                  filter: str = Query("all", pattern="^(all|kev|ransomware|news|overdue|internet)$"),
                  framework: str | None = Query(None, max_length=40),
                  user=Depends(require("view_summary"))):
    if key not in metric_catalog.REGISTRY:
        raise HTTPException(404, "Unknown metric")
    with get_conn() as conn:
        try:
            detail = metric_catalog.build(conn, key, {"source": source, "days": days, "filter": filter, "framework": framework})
        except StopIteration:
            raise HTTPException(404, "Unknown framework")
    # Data minimization: roles without asset-level access get the explanation and
    # aggregates, but not the underlying hosts, users, and findings.
    if not can(user, "view_details") and detail["items"]:
        detail["items"] = {**detail["items"], "rows": []}
        detail["items_redacted"] = True
    return detail
