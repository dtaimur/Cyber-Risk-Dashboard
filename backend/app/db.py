"""SQLite persistence layer.

A single file database keeps the demo portable. Every query uses parameter
binding (never string formatting) so user-supplied values cannot inject SQL.
"""
import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

# All runtime state (database, encryption key, generated credentials) lives in one
# directory so a container can mount it as a persistent volume.
DATA_DIR = Path(os.environ.get("DASHBOARD_DATA_DIR", Path(__file__).resolve().parent.parent))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.environ.get("DASHBOARD_DB", DATA_DIR / "dashboard.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY,
    hostname TEXT NOT NULL,
    ip TEXT,
    os TEXT,
    asset_type TEXT,            -- server | workstation | cloud | network
    environment TEXT,           -- on-prem | aws | azure | gcp
    business_unit TEXT,
    criticality INTEGER,        -- 1 (low) .. 5 (crown jewel)
    internet_facing INTEGER DEFAULT 0,
    owner TEXT,
    software TEXT,              -- JSON list of product names installed
    edr_status TEXT,            -- CrowdStrike sensor: normal | rfm | missing
    sensor_version TEXT,
    last_scanned TEXT,          -- Qualys last scan date
    contained INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,       -- qualys | crowdstrike | wiz
    external_id TEXT,           -- QID / Spotlight id / Wiz id
    asset_id INTEGER REFERENCES assets(id),
    cve TEXT,
    title TEXT,
    vendor TEXT,
    product TEXT,
    severity TEXT,              -- critical | high | medium | low
    cvss REAL,
    vendor_score REAL,          -- Qualys QDS / CrowdStrike ExPRT / Wiz score
    status TEXT,                -- open | in_progress | remediated | risk_accepted
    patch_available INTEGER DEFAULT 1,
    first_seen TEXT,
    due_date TEXT,
    remediated_at TEXT,
    owner_team TEXT,
    is_live INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve);
CREATE INDEX IF NOT EXISTS idx_findings_source ON findings(source);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,       -- crowdstrike | expel | wiz | qualys
    external_id TEXT,
    title TEXT,
    severity TEXT,
    status TEXT,                -- new | investigating | resolved | false_positive
    category TEXT,
    tactic TEXT,                -- MITRE ATT&CK tactic
    technique TEXT,             -- MITRE ATT&CK technique id + name
    asset_id INTEGER REFERENCES assets(id),
    user_name TEXT,
    occurred_at TEXT,
    detected_at TEXT,
    resolved_at TEXT,
    is_incident INTEGER DEFAULT 0,
    is_live INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_detected ON alerts(detected_at);

CREATE TABLE IF NOT EXISTS cloud_issues (
    id INTEGER PRIMARY KEY,
    external_id TEXT,
    resource TEXT,
    resource_type TEXT,
    cloud TEXT,                 -- aws | azure | gcp
    rule TEXT,
    category TEXT,              -- misconfiguration | exposure | identity | secret | toxic_combination
    severity TEXT,
    status TEXT,                -- open | resolved
    internet_exposed INTEGER DEFAULT 0,
    created_at TEXT,
    resolved_at TEXT,
    is_live INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS vendors (
    id INTEGER PRIMARY KEY,
    name TEXT,
    category TEXT,
    tier INTEGER,               -- 1 = critical vendor
    data_access TEXT,
    bitsight_rating INTEGER,    -- 250..900
    bitsight_history TEXT,      -- JSON list of monthly ratings (oldest first)
    ssc_score INTEGER,          -- SecurityScorecard 0..100
    ssc_history TEXT,
    last_assessment TEXT,
    next_assessment TEXT,
    open_issues INTEGER
);

CREATE TABLE IF NOT EXISTS controls (
    id INTEGER PRIMARY KEY,
    framework TEXT,
    control_id TEXT,
    family TEXT,
    name TEXT,
    status TEXT,                -- implemented | partial | not_implemented
    owner TEXT,
    auto_rule TEXT,             -- if set, status is evaluated from live dashboard data
    last_reviewed TEXT
);

CREATE TABLE IF NOT EXISTS roadmap (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    item_type TEXT,             -- audit | assessment | pen_test | certification | policy_review | milestone
    framework TEXT,
    start_date TEXT,
    due_date TEXT,
    owner TEXT,
    status TEXT,                -- planned | in_progress | at_risk | complete
    notes TEXT
);

CREATE TABLE IF NOT EXISTS goals (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    metric_key TEXT NOT NULL,
    baseline REAL,
    target REAL,
    direction TEXT,             -- lower | higher (which way is better)
    due_date TEXT,
    owner TEXT
);

CREATE TABLE IF NOT EXISTS integrations (
    id TEXT PRIMARY KEY,
    enabled INTEGER DEFAULT 0,
    config TEXT,                -- JSON, non-secret settings only
    secret_enc TEXT,            -- Fernet-encrypted credential, never returned by the API
    last_sync TEXT,
    last_status TEXT,
    last_message TEXT,
    record_count INTEGER
);

CREATE TABLE IF NOT EXISTS articles (
    id TEXT PRIMARY KEY,        -- sha1 of link
    source TEXT,
    title TEXT,
    link TEXT,
    published TEXT,
    summary TEXT,
    cves TEXT,                  -- JSON list
    products TEXT               -- JSON list of tech-stack keywords mentioned
);

CREATE TABLE IF NOT EXISTS kev (
    cve TEXT PRIMARY KEY,
    vendor TEXT,
    product TEXT,
    name TEXT,
    date_added TEXT,
    due_date TEXT,
    ransomware TEXT,
    description TEXT,
    action TEXT
);

CREATE TABLE IF NOT EXISTS epss (
    cve TEXT PRIMARY KEY,
    score REAL,
    percentile REAL,
    fetched_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    ts TEXT,
    actor TEXT,
    action TEXT,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY,
    key TEXT UNIQUE NOT NULL,      -- Jira issue key, e.g. SEC-142
    summary TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL,          -- To Do | In Progress | In Review | Done | Won't Fix
    priority TEXT,                 -- Highest | High | Medium | Low
    team TEXT,
    assignee TEXT,
    reporter TEXT,
    source_type TEXT,              -- threat | finding | manual
    cve TEXT,
    created_at TEXT,
    updated_at TEXT,
    due_date TEXT,
    resolved_at TEXT,
    url TEXT,                      -- Jira browse URL when created in a live Jira site
    is_live INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ticket_findings (
    ticket_id INTEGER REFERENCES tickets(id) ON DELETE CASCADE,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    PRIMARY KEY (ticket_id, finding_id)
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT,
    role TEXT NOT NULL,            -- executive | analyst | admin
    password_hash TEXT NOT NULL,   -- scrypt$N$r$p$salt$hash
    created_at TEXT,
    last_login TEXT,
    failed_attempts INTEGER DEFAULT 0,
    locked_until TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY,
    token_hash TEXT UNIQUE NOT NULL,  -- SHA-256 of the cookie token; raw token is never stored
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT,
    expires_at TEXT,
    ip TEXT
);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def get_conn():
    conn = connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        # Migration for databases created before audit entries recorded the actor
        if "actor" not in {r["name"] for r in conn.execute("PRAGMA table_info(audit_log)")}:
            conn.execute("ALTER TABLE audit_log ADD COLUMN actor TEXT")


def rows(conn, sql, params=()):
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def one(conn, sql, params=()):
    r = conn.execute(sql, params).fetchone()
    return dict(r) if r else None


def jloads(value, default=None):
    if value is None:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default
