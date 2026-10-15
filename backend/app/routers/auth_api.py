"""Sign-in, sign-out, current user, and access-control administration."""
from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, Field

from .. import auth
from ..db import get_conn, rows

router = APIRouter(prefix="/api")


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


def _client_ip(request: Request):
    return request.client.host if request.client else None


@router.post("/auth/login")
def login(body: LoginRequest, request: Request, response: Response):
    token, user = auth.login(body.username.strip().lower(), body.password, _client_ip(request))
    response.set_cookie(auth.SESSION_COOKIE, token, max_age=auth.SESSION_HOURS * 3600, httponly=True,
                        samesite="strict", secure=auth.cookie_secure(), path="/")
    return auth.public_user(user)


@router.post("/auth/logout")
def logout(request: Request, response: Response):
    auth.logout(request.cookies.get(auth.SESSION_COOKIE))
    response.delete_cookie(auth.SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/auth/me")
def me(request: Request):
    return auth.public_user(auth.current_user(request))


@router.get("/access/roles")
def roles(_=Depends(auth.require("view_audit"))):
    return {"permissions": auth.PERMISSIONS,
            "roles": {k: {**{x: v[x] for x in ("label", "description")}, "permissions": sorted(v["permissions"])} for k, v in auth.ROLES.items()}}


@router.get("/access/users")
def users(_=Depends(auth.require("view_audit"))):
    with get_conn() as conn:
        us = rows(conn, "SELECT username, display_name, role, last_login, created_at, locked_until FROM users ORDER BY id")
        active = {r["username"]: r["n"] for r in conn.execute(
            "SELECT u.username, COUNT(*) n FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.expires_at > strftime('%Y-%m-%dT%H:%M:%SZ','now') GROUP BY u.username")}
    for u in us:
        u["role_label"] = auth.ROLES[u["role"]]["label"]
        u["active_sessions"] = active.get(u["username"], 0)
    return us


@router.get("/access/audit")
def audit_log(limit: int = Query(100, ge=1, le=500), action: str | None = Query(None, max_length=40),
              _=Depends(auth.require("view_audit"))):
    with get_conn() as conn:
        if action:
            return rows(conn, "SELECT * FROM audit_log WHERE action LIKE ? ORDER BY id DESC LIMIT ?", (f"{action}%", limit))
        return rows(conn, "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
