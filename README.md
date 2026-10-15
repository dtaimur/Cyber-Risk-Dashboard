# Cyber Risk Dashboard

A full-stack cybersecurity executive dashboard that centralizes vulnerability, threat,
alert, third-party, and compliance data and turns it into decisions for leadership.

> **Note:** This is an independent rebuild of a project I worked on during an internship.
> It contains no proprietary code or data. Security-tool data (Qualys, CrowdStrike,
> Expel, Wiz) is **simulated** unless an API is connected; threat intelligence
> (CISA KEV, security news, EPSS) is **live**.

**Stack:** React + TypeScript (Vite, Recharts) · FastAPI (Python) · SQLite

---

## Run it

```bash
./run.sh            # starts API on :8000 and web app on :5173
./run.sh --reset    # rebuilds the demo database and pulls fresh threat intel
```

Open http://localhost:5173 and sign in. On first run, strong random passwords for the three demo
accounts (`exec`, `analyst`, `admin`) are generated into `backend/.demo-credentials` (owner-only file):

```bash
cat backend/.demo-credentials
```

To choose your own, set `DASHBOARD_PASSWORD_EXECUTIVE`, `DASHBOARD_PASSWORD_ANALYST`, `DASHBOARD_PASSWORD_ADMIN` before starting.
Tests: `cd backend && .venv/bin/python -m pytest -q`

### Run as a container

```bash
cp .env.example .env        # set passwords and DASHBOARD_SECRET_KEY
docker compose up --build   # http://localhost:8000
```

One image serves both the API and the built frontend. It runs as a non-root user on a read-only filesystem with all
Linux capabilities dropped; only the `/data` volume (database, encryption key) is writable. A health check is built in.

**Before a demo:** run `./run.sh --reset` the same day so news and KEV correlations are current.

---

## Architecture

```
 Live public feeds                     Security tool APIs (optional)
 ┌──────────────────────────┐          ┌──────────────────────────────────┐
 │ CISA KEV (JSON)          │          │ Qualys VMDR      (XML, basic auth)│
 │ SecurityWeek / THN /     │          │ CrowdStrike      (OAuth2 REST)    │
 │ BleepingComputer /       │          │ Expel Workbench  (JSON:API)       │
 │ Dark Reading (RSS)       │          │ Wiz              (OAuth2 GraphQL) │
 │ FIRST EPSS · NVD         │          └───────────────┬──────────────────┘
 └────────────┬─────────────┘                          │ connectors normalize
              │ threat_intel.py                        │ into one schema
              ▼                                        ▼
        ┌──────────────────────────── SQLite ─────────────────────────────┐
        │ assets · findings · alerts · cloud_issues · vendors · controls  │
        │ kev · articles · epss · roadmap · goals · integrations(enc.)    │
        └───────────────────────────────┬─────────────────────────────────┘
                                        │
             metrics.py (scores, trends) · threat_intel.active_threats (correlation)
             report.py (insight engine)
                                        │  FastAPI REST  /api/*
                                        ▼
                         React SPA (Vite proxy → API)
```

Key design choice: **every source is normalized into one schema**, so pages, scoring,
and reporting work the same whether data is mock or live. Connecting a tool's API
replaces that tool's simulated records with real ones; nothing downstream changes.

---

## Sections

| Section | What it shows |
|---|---|
| **Executive Summary** | Enterprise risk score (6 weighted components, 13-week trend), "what needs action" with owners, KPIs, alerts by platform, third-party risk (Bitsight + SecurityScorecard), compliance posture |
| **Vulnerabilities** | Cross-tool overview + a page per tool with tool-specific metrics: Qualys (QDS, scan coverage/freshness), CrowdStrike (sensor health, ATT&CK tactics, Spotlight), Expel (triage funnel, MTTD/MTTR, incidents), Wiz (toxic combinations, cloud issues). Drill down to any asset. |
| **Threat News** | Live articles; CVEs and products extracted automatically and flagged when they match our environment. Latest CISA KEV additions. |
| **Active Threats** | Correlates CVEs in our scans with KEV, EPSS, and news; ranks them with a transparent priority score; flags KEV CVEs in our tech stack that scanners haven't reported ("verify exposure") |
| **Alerts & Forensics** | Consolidated, filterable alert stream; volume by source with anomaly detection; MTTD/MTTR trends; MITRE ATT&CK tactics/techniques; hour-of-day heatmap; most-targeted hosts/users |
| **Executive Report** | Generated briefing by audience (Board / Executive / Security). Each takeaway = evidence → why it matters → recommendation → decision needed. Print-to-PDF and Markdown export. |
| **Compliance & Goals** | NIST CSF 2.0, ISO 27001:2022, GDPR readiness; some controls auto-evaluated from live data; security goals measured from real metrics; **editable** audit/assessment roadmap (timeline + CRUD) |
| **Vulnerabilities → Jira Remediation** | Remediation workflow: open vs closed vulnerabilities, open/overdue tickets, resolution time, tracking coverage (critical/high findings with a ticket), fixes awaiting scanner verification, created vs resolved, backlog trend, team and assignee workload, ticket aging. Tickets are created from Active Threats or any finding with a pre-filled summary, priority, owner, SLA due date, and description; status changes flow to the linked findings, and "Won't Fix" records a risk acceptance. |
| **Settings → API Integrations** | Configure, test, and sync each tool; enable/disable threat feeds |

### Every metric is explainable

Click any KPI card, the risk score, a risk component, a vendor rating, or a framework score to open its detail view:
the **affected assets / vulnerabilities / vendors / controls** (rows open the asset), **what it measures**, **why it matters**,
**where the data comes from** (each source marked live, mock, or manual), and **how it's calculated** — the formula plus the
live inputs behind today's number. Each card can switch between a **number**, a **trend line**, a **breakdown bar chart**, and a **pie chart** (for part-of-whole metrics such as open vs closed)
where the data supports it (choice is remembered per card). Definitions live in one place: `backend/app/metric_catalog.py`
(`GET /api/metrics/{key}`), and tests assert the drill-down values match the page values.

---

## AI Analyst (Claude API)

Ask questions in plain English ("What should I patch first today?", "How is the risk score calculated?",
"Brief me for the board"). Claude (`claude-opus-5-5`) answers by calling the dashboard's own data functions as
tools and cites the CVEs, hosts, tickets, and metrics behind each claim. Any metric's detail view has an
"Ask the AI analyst" button.

Put your key in `.env` at the project root (created on first `./run.sh`, owner-only permissions, git-ignored):

```
ANTHROPIC_API_KEY=sk-ant-...
```

then restart `./run.sh`. The same `.env` is used by `docker compose`.

How it's built (`backend/app/assistant.py`):

- **Grounded tool use**: 11 read-only tools (overview, metric definitions, findings, active threats, assets, alerts,
  threat news, vendors, compliance, tickets, ticket drafts) with strict JSON schemas, executed in a streaming agent loop.
- **Least privilege**: the tool list is filtered by the user's role and every tool re-checks permission on execution,
  so an Executive's assistant sees aggregates only — it cannot reach hosts or findings.
- **Human in the loop**: the assistant can *draft* a Jira ticket; the user reviews it and clicks Create.
- **Prompt-injection defense**: news and CISA text are labeled untrusted data, and the system prompt forbids following
  instructions found in tool output. No tool can change state, which bounds the impact of any injection.
- **Server-side history**: the browser sends only the new message, so conversations can't be tampered with client-side.
- **Cost and abuse controls**: per-user rate limit, max tool rounds per question, max turns per conversation,
  conversation expiry, prompt caching, and every question is written to the audit log with token usage.
- **Reliability**: adaptive thinking at `medium` effort; server-side refusal fallback (`fallbacks: "default"`), since
  security questions can trip cyber safety classifiers; typed API error handling streamed to the UI.

## Jira integration

Connect under Settings → API Integrations → Jira Cloud (site URL, account email, project key, API token).
When connected, tickets are created as real Jira issues (REST API v3, labeled `cyber-risk-dashboard`),
status changes are applied as Jira workflow transitions, and "Sync now" pulls status changes made in Jira
back into the dashboard. Without a connection, tickets live in the dashboard's own tracker with the same
fields and workflow. A ticket is only considered verified when the scanner stops detecting its findings.

## How the scores work

**Enterprise risk score (0–100, higher = more risk)** — weighted sum of components, each 0–100:

| Component | Weight | Formula |
|---|---|---|
| Vulnerability exposure | 25% | 60% × share of critical/high past SLA + 40% × critical density |
| Active threat exposure | 20% | 2.5 per open KEV CVE + 4 per internet-facing asset affected |
| Detection & response | 20% | Open critical/high alerts + critical MTTR vs 4h target |
| Third-party risk | 15% | Tier-weighted Bitsight + SecurityScorecard ratings |
| Tool coverage | 10% | EDR coverage gap ×3 + scan coverage gap ×2 |
| Compliance gaps | 10% | 100 − average framework implementation |

The trend is recomputed "as of" each past week from timestamps (first seen, remediated,
detected, resolved), not stored separately, so the history uses the same logic as today.

**Active threat priority (0–100)** — additive and shown per threat:
CVSS (20) · on CISA KEV (15) · ransomware use (10) · EPSS (10) · emerging/in the news (20) ·
exposure (15) · asset criticality (10).

---

## Security design

**Access control**

| Role | Can see / do |
|---|---|
| Executive | Summary, metric definitions, threat news, reports, compliance (read-only). No asset-level data: metric drill-downs show aggregates only. |
| Security Analyst | Everything operational: vulnerabilities, tools, alerts, active threats, asset detail; can refresh feeds and create/update remediation tickets. |
| Administrator | All of the above plus integrations/credentials, compliance editing, users and audit log. |

- Permissions are enforced **server-side on every API route** (FastAPI dependencies); the UI hides what a role can't use, but never relies on that.
- Passwords hashed with **scrypt** + per-user salt. Sessions are random tokens in an **HttpOnly, SameSite=Strict** cookie (Secure over HTTPS); only a SHA-256 of the token is stored. 8-hour expiry; sign-out revokes server-side.
- **Account lockout** after 5 failed attempts; one generic error so usernames can't be enumerated (with timing equalized for unknown users).
- **CSRF**: SameSite=Strict plus a required custom header on all state-changing requests.
- **Audit log** (Settings → Access & Audit): sign-ins, failures, lockouts, denied requests (user, permission, path), and every configuration change with the acting user.
- **Content-Security-Policy**, HSTS (over HTTPS), frame denial, no-referrer, permissions policy.

**Data protection**

- **Credentials encrypted at rest** (Fernet: AES-128-CBC + HMAC). Key from `DASHBOARD_SECRET_KEY` or an owner-only key file. Secrets never return to the browser; the API exposes only `has_secret`.
- **Input validation** with Pydantic: enum-constrained filters, length limits, date ordering, allow-listed config keys, HTTPS-only vendor endpoints.
- **Parameterized SQL** everywhere; tests probe injection.
- **Security headers** (`nosniff`, `X-Frame-Options: DENY`, `no-referrer`, `no-store`) and a restricted CORS allow-list.
- **Audit log** of configuration and roadmap changes.
- **Resilience:** feeds are cached in the DB; network failures are reported per integration without breaking the dashboard.
- **Auto-evaluated controls** (e.g. ISO A.8.8) cannot be manually overridden.

## Limitations (honest notes)

- Security-tool connectors use each vendor's documented API but have only been verified up to authentication (e.g. CrowdStrike correctly returns 401 for invalid credentials), not against a live tenant.
- Mock environment: on first run, the newest CISA KEV CVEs in products we "run" are placed on simulated hosts so correlation with this week's news can be demonstrated.
- Demo users are fixed (three roles); a production version would use SSO (SAML/OIDC) instead of local passwords.
- SQLite suits a single-instance demo; a production deployment would use a managed database (e.g. PostgreSQL).

## Next steps

- SSO (Entra ID / Okta) mapped to the existing roles
- CI pipeline with tests, SAST, and dependency scanning
- Scheduled background sync and alerting on new KEV matches
- Evaluation set for the AI analyst (graded question/answer pairs) to measure accuracy before prompt or model changes
