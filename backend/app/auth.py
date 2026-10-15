"""Authentication, sessions, and role-based access control.

Design:
  * Passwords hashed with scrypt (memory-hard) and a per-user random salt.
  * Opaque random session tokens in an HttpOnly, SameSite=Strict cookie. Only a
    SHA-256 hash of the token is stored, so a database leak does not expose
    live sessions. Sessions expire after SESSION_HOURS.
  * Account lockout after repeated failed logins; one generic error message so
    usernames cannot be enumerated.
  * Permissions are enforced on the server for every API route (FastAPI
    dependencies). The UI hides what a role cannot use, but never relies on that.
  * Every login, logout, denied request, and configuration change is written to
    the audit log with the acting user.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request

from .db import DATA_DIR, get_conn, one

SESSION_COOKIE = "crd_session"
SESSION_HOURS = 8
MAX_FAILED = 5
LOCKOUT_MINUTES = 5
CREDENTIALS_FILE = DATA_DIR / ".demo-credentials"

# ----------------------------------------------------------------------------- roles
PERMISSIONS = {
    "view_summary": "View executive summary and metric definitions",
    "view_threat_intel": "View threat news and CISA KEV feed",
    "generate_report": "Generate executive reports",
    "use_assistant": "Ask the AI analyst (answers limited to the user's own permissions)",
    "view_compliance": "View compliance posture, goals, and roadmap",
    "view_details": "View asset-level detail (vulnerabilities, alerts, active threats)",
    "refresh_feeds": "Trigger threat intelligence refresh",
    "manage_remediation": "Create and update remediation tickets (Jira)",
    "edit_compliance": "Edit roadmap, goals, and control attestations",
    "manage_integrations": "Configure integrations and API credentials",
    "view_audit": "View users and the audit log",
}
_EXEC = {"view_summary", "view_threat_intel", "generate_report", "view_compliance", "use_assistant"}
_ANALYST = _EXEC | {"view_details", "refresh_feeds", "manage_remediation"}
_ADMIN = _ANALYST | {"edit_compliance", "manage_integrations", "view_audit"}
ROLES = {
    "executive": {"label": "Executive", "description": "Leadership view: posture, trends, reports. No asset-level data.", "permissions": _EXEC},
    "analyst": {"label": "Security Analyst", "description": "Full operational detail for investigation and remediation.", "permissions": _ANALYST},
    "admin": {"label": "Administrator", "description": "Everything, plus integrations, credentials, and audit.", "permissions": _ADMIN},
}

DEMO_USERS = [
    ("exec", "Morgan Lee", "executive"),
    ("analyst", "Sam Rivera", "analyst"),
    ("admin", "Alex Kim", "admin"),
]


# ----------------------------------------------------------------------------- passwords
_N, _R, _P = 2 ** 14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, digest = stored.split("$")
        calc = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(calc, base64.b64decode(digest))
    except (ValueError, TypeError):
        return False


_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))  # equalizes timing for unknown usernames


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def audit(conn, actor, action, detail=""):
    conn.execute("INSERT INTO audit_log (ts, actor, action, detail) VALUES (?,?,?,?)",
                 (_iso(_now()), actor, action, detail if isinstance(detail, str) else json.dumps(detail)))


# ----------------------------------------------------------------------------- users
def ensure_users():
    """Create demo users. Passwords come from DASHBOARD_PASSWORD_<ROLE> env vars
    (used in cloud deployments); otherwise strong random passwords are generated
    once and written to an owner-only file for local use."""
    generated, from_env = {}, set()
    with get_conn() as conn:
        for username, name, role in DEMO_USERS:
            env_pw = os.environ.get(f"DASHBOARD_PASSWORD_{role.upper()}")
            if env_pw:
                from_env.add(username)
            row = one(conn, "SELECT * FROM users WHERE username=?", (username,))
            if row is None:
                pw = env_pw or secrets.token_urlsafe(12)
                conn.execute("INSERT INTO users (username, display_name, role, password_hash, created_at) VALUES (?,?,?,?,?)",
                             (username, name, role, hash_password(pw), _iso(_now())))
                if not env_pw:
                    generated[username] = pw
            elif env_pw and not verify_password(env_pw, row["password_hash"]):
                conn.execute("UPDATE users SET password_hash=?, failed_attempts=0, locked_until=NULL WHERE id=?",
                             (hash_password(env_pw), row["id"]))
    # Keep the local credentials file truthful: generated passwords, or a pointer to .env
    previous = {}
    if CREDENTIALS_FILE.exists():
        for line in CREDENTIALS_FILE.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and not line.startswith("#"):
                previous[parts[0]] = parts[1]
    if generated or from_env or previous:
        lines = ["# Demo sign-in credentials. Keep private.", ""]
        for u, _, r in DEMO_USERS:
            label = f"({ROLES[r]['label']})"
            if u in from_env:
                lines.append(f"{u:<8} {'(set in .env)':<20} {label}")
            elif generated.get(u) or (previous.get(u) and previous[u] != "(set"):
                lines.append(f"{u:<8} {generated.get(u) or previous[u]:<20} {label}")
        CREDENTIALS_FILE.write_text("\n".join(lines) + "\n")
        CREDENTIALS_FILE.chmod(0o600)


def public_user(u):
    role = ROLES[u["role"]]
    return {"username": u["username"], "display_name": u["display_name"], "role": u["role"], "role_label": role["label"],
            "permissions": sorted(role["permissions"])}


# ----------------------------------------------------------------------------- sessions
def _token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def login(username: str, password: str, ip: str | None):
    """Returns (session_token, user) or raises 401 with a generic message.

    Failure bookkeeping (counter, lockout, audit) is committed before the error is
    raised; raising inside the transaction would roll it back.
    """
    error = None
    with get_conn() as conn:
        u = one(conn, "SELECT * FROM users WHERE username=?", (username,))
        if not u:
            verify_password(password, _DUMMY_HASH)
            audit(conn, username[:40], "auth.login_failed", {"reason": "unknown user", "ip": ip})
            error = HTTPException(401, "Invalid username or password")
        elif u["locked_until"] and u["locked_until"] > _iso(_now()):
            audit(conn, username, "auth.login_blocked", {"reason": "account locked", "ip": ip})
            error = HTTPException(429, f"Too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes.")
        elif not verify_password(password, u["password_hash"]):
            fails = (u["failed_attempts"] or 0) + 1
            locked = _iso(_now() + timedelta(minutes=LOCKOUT_MINUTES)) if fails >= MAX_FAILED else None
            conn.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?", (0 if locked else fails, locked, u["id"]))
            audit(conn, username, "auth.login_failed", {"reason": "bad password", "ip": ip, "locked": bool(locked)})
            error = HTTPException(401, "Invalid username or password")
        else:
            token = secrets.token_urlsafe(32)
            conn.execute("UPDATE users SET failed_attempts=0, locked_until=NULL, last_login=? WHERE id=?", (_iso(_now()), u["id"]))
            conn.execute("INSERT INTO sessions (token_hash, user_id, created_at, expires_at, ip) VALUES (?,?,?,?,?)",
                         (_token_hash(token), u["id"], _iso(_now()), _iso(_now() + timedelta(hours=SESSION_HOURS)), ip))
            conn.execute("DELETE FROM sessions WHERE expires_at < ?", (_iso(_now()),))
            audit(conn, username, "auth.login", {"ip": ip})
    if error:
        raise error
    return token, u


def logout(token: str | None):
    if not token:
        return
    with get_conn() as conn:
        s = one(conn, "SELECT s.id, u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE token_hash=?", (_token_hash(token),))
        if s:
            conn.execute("DELETE FROM sessions WHERE id=?", (s["id"],))
            audit(conn, s["username"], "auth.logout")


def current_user(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(401, "Not signed in")
    with get_conn() as conn:
        u = one(conn, """SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
                         WHERE s.token_hash=? AND s.expires_at > ?""", (_token_hash(token), _iso(_now())))
    if not u:
        raise HTTPException(401, "Session expired")
    return u


def require(permission: str):
    """FastAPI dependency: the signed-in user must hold `permission`."""
    assert permission in PERMISSIONS, permission

    def dep(request: Request):
        u = current_user(request)
        if permission not in ROLES[u["role"]]["permissions"]:
            with get_conn() as conn:
                audit(conn, u["username"], "access.denied", {"permission": permission, "path": request.url.path, "method": request.method})
            raise HTTPException(403, f"Your role ({ROLES[u['role']]['label']}) does not have access to this")
        request.state.user = u
        return u
    return dep


def can(user, permission):
    return permission in ROLES[user["role"]]["permissions"]


def cookie_secure() -> bool:
    return os.environ.get("DASHBOARD_SECURE_COOKIES", "0") == "1"


def credentials_hint() -> str | None:
    return str(CREDENTIALS_FILE) if CREDENTIALS_FILE.exists() else None

