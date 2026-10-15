"""Backend tests: scoring, threat correlation, report logic, and security controls.

Runs fully offline against a throwaway database.
"""
import json
import os
import tempfile
from datetime import date, timedelta

os.environ["DASHBOARD_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")
os.environ["DASHBOARD_OFFLINE"] = "1"
os.environ.setdefault("DASHBOARD_SECRET_KEY", "Hj0m2yYzJ7c1yQkX6w4lq4m6S9j3N3r3fYQqkz0hJ7w=")
os.environ["DASHBOARD_DATA_DIR"] = os.path.dirname(os.environ["DASHBOARD_DB"])
PASSWORDS = {"exec": "exec-test-pass-1", "analyst": "analyst-test-pass-1", "admin": "admin-test-pass-1"}
os.environ["DASHBOARD_PASSWORD_EXECUTIVE"] = PASSWORDS["exec"]
os.environ["DASHBOARD_PASSWORD_ANALYST"] = PASSWORDS["analyst"]
os.environ["DASHBOARD_PASSWORD_ADMIN"] = PASSWORDS["admin"]
CSRF = {"X-Requested-With": "XMLHttpRequest"}

import pytest
from fastapi.testclient import TestClient

from app import metrics, threat_intel
from app.db import get_conn
from app.main import app


def signed_in(username):
    c = TestClient(app, headers=CSRF)
    c.__enter__()
    r = c.post("/api/auth/login", json={"username": username, "password": PASSWORDS[username]})
    assert r.status_code == 200, r.text
    return c


@pytest.fixture(scope="module")
def client():
    """Admin session: used by the functional tests."""
    c = signed_in("admin")
    yield c
    c.__exit__(None, None, None)


def _add_kev(cve, days_ago=3, ransomware="Unknown"):
    with get_conn() as conn:
        conn.execute("INSERT OR REPLACE INTO kev (cve,vendor,product,name,date_added,due_date,ransomware,description,action) VALUES (?,?,?,?,?,?,?,?,?)",
                     (cve, "Citrix", "NetScaler", "Test vuln", (date.today() - timedelta(days=days_ago)).isoformat(),
                      date.today().isoformat(), ransomware, "desc", "Patch it"))


# --------------------------------------------------------------------------- scoring
def test_risk_score_is_bounded_and_components_add_up(client):
    with get_conn() as conn:
        data = metrics.Data(conn)
        ctx = metrics.context(data)
        risk = metrics.risk_score(data, ctx=ctx)
    assert 0 <= risk["score"] <= 100
    assert abs(sum(c["contribution"] for c in risk["components"]) - risk["score"]) < 0.5
    assert abs(sum(w for _, _, w in metrics.COMPONENTS) - 1.0) < 1e-9


def test_risk_history_has_one_point_per_week(client):
    body = client.get("/api/summary").json()
    assert len(body["risk"]["history"]) == 13
    assert body["risk"]["history"][-1]["score"] == body["risk"]["score"]


def test_goal_progress_handles_both_directions():
    ctx = {"vulns": {"mttr_days": {"critical": 25}}, "coverage": {"edr_coverage": 93}}
    lower = metrics.goal_progress({"metric_key": "crit_mttr_days", "baseline": 35, "target": 15, "direction": "lower"}, ctx)
    higher = metrics.goal_progress({"metric_key": "edr_coverage", "baseline": 88, "target": 98, "direction": "higher"}, ctx)
    assert lower["progress"] == 50 and not lower["met"]
    assert higher["progress"] == 50 and not higher["met"]


# --------------------------------------------------------------------------- correlation
def test_kev_listed_cve_in_environment_becomes_active_threat(client):
    with get_conn() as conn:
        f = dict(conn.execute("SELECT * FROM findings WHERE cve IS NOT NULL AND status='open' LIMIT 1").fetchone())
    _add_kev(f["cve"], ransomware="Known")
    with get_conn() as conn:
        threats = {t["cve"]: t for t in threat_intel.active_threats(conn)}
    t = threats[f["cve"]]
    assert t["in_kev"] and t["ransomware"] and t["newly_listed"]
    assert t["breakdown"]["kev"] == threat_intel.WEIGHTS["kev"]
    assert t["priority"] == round(min(100, sum(t["breakdown"].values())))


def test_cve_mentioned_in_news_is_linked(client):
    with get_conn() as conn:
        f = dict(conn.execute("SELECT * FROM findings WHERE cve IS NOT NULL AND status='open' ORDER BY id DESC LIMIT 1").fetchone())
        conn.execute("INSERT OR REPLACE INTO articles (id,source,title,link,published,summary,cves,products) VALUES (?,?,?,?,?,?,?,?)",
                     ("t1", "Test News", f"Attackers exploit {f['cve']}", "https://example.com/a", threat_intel._now(), "", json.dumps([f["cve"]]), "[]"))
        threats = {t["cve"]: t for t in threat_intel.active_threats(conn)}
    assert threats[f["cve"]]["news_count"] == 1
    assert threats[f["cve"]]["breakdown"]["emerging"] >= 6


def test_cves_not_in_environment_are_not_active_threats(client):
    _add_kev("CVE-1999-0001")
    with get_conn() as conn:
        assert "CVE-1999-0001" not in {t["cve"] for t in threat_intel.active_threats(conn)}


def test_cve_extraction_from_text():
    assert sorted(set(threat_intel.CVE_RE.findall("Fixes cve-2024-3400 and CVE-2023-4966."))) == ["CVE-2023-4966", "cve-2024-3400"]


# --------------------------------------------------------------------------- report
def test_report_contains_reasoning_not_just_metrics(client):
    r = client.post("/api/report", json={"period_days": 30, "audience": "board"}).json()
    assert r["bluf"]
    assert 1 <= len(r["insights"]) <= 3
    for i in r["insights"]:
        assert i["why"] and i["recommendation"] and i["evidence"]
    assert any(d["decision"] for d in r["decisions"])


def test_report_rejects_unknown_audience(client):
    assert client.post("/api/report", json={"period_days": 30, "audience": "everyone"}).status_code == 422


# --------------------------------------------------------------------------- security
def test_secrets_are_encrypted_and_never_returned(client):
    resp = client.put("/api/integrations/wiz", json={"config": {"api_url": "https://api.us1.app.wiz.io/graphql", "client_id": "abc"},
                                                     "secret": "super-secret-value"})
    assert resp.status_code == 200
    assert "super-secret-value" not in resp.text
    assert "super-secret-value" not in client.get("/api/integrations").text
    with get_conn() as conn:
        stored = conn.execute("SELECT secret_enc FROM integrations WHERE id='wiz'").fetchone()[0]
    assert stored and "super-secret-value" not in stored


def test_plaintext_http_endpoints_are_rejected(client):
    resp = client.put("/api/integrations/qualys", json={"config": {"base_url": "http://qualys.example.com"}})
    assert resp.status_code == 422


def test_unknown_config_keys_are_rejected(client):
    assert client.put("/api/integrations/qualys", json={"config": {"evil": "x"}}).status_code == 422


def test_search_is_parameterized(client):
    body = client.get("/api/vulnerabilities/findings", params={"q": "' OR 1=1 --"}).json()
    assert body["total"] == 0


def test_filters_only_accept_known_values(client):
    assert client.get("/api/vulnerabilities/findings", params={"source": "x; DROP TABLE"}).status_code == 422


def test_security_headers_present(client):
    h = client.get("/api/health").headers
    assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"


# --------------------------------------------------------------------------- roadmap
def test_roadmap_crud_and_validation(client):
    item = {"title": "Pen test", "item_type": "pen_test", "start_date": "2026-12-01", "due_date": "2026-12-10", "owner": "R. Haddad"}
    created = client.post("/api/compliance/roadmap", json=item).json()
    assert client.put(f"/api/compliance/roadmap/{created['id']}", json={**item, "status": "in_progress"}).json()["status"] == "in_progress"
    assert client.post("/api/compliance/roadmap", json={**item, "due_date": "2026-11-01"}).status_code == 422
    assert client.delete(f"/api/compliance/roadmap/{created['id']}").status_code == 204


def test_auto_evaluated_controls_cannot_be_overridden(client):
    with get_conn() as conn:
        cid = conn.execute("SELECT id FROM controls WHERE auto_rule IS NOT NULL LIMIT 1").fetchone()[0]
    assert client.patch(f"/api/compliance/controls/{cid}", json={"status": "implemented"}).status_code == 409


# --------------------------------------------------------------------------- metric catalog
from app import metric_catalog  # noqa: E402


def test_every_metric_explains_itself(client):
    for key, meta in client.get("/api/metrics").json().items():
        params = {"framework": "GDPR"} if key == "compliance" else {}
        d = client.get(f"/api/metrics/{key}", params=params).json()
        assert d["description"] and d["why"] and d["calculation"], key
        assert d["sources"], key
        assert d["items"] is not None and "columns" in d["items"], key
        if meta["trend"]:
            assert d["series"], key


def test_metric_values_match_the_pages(client):
    k = client.get("/api/summary").json()["kpis"]
    get = lambda key, **p: client.get(f"/api/metrics/{key}", params=p).json()["value"]
    assert get("open_critical") == k["open_critical"]
    assert get("kev_open") == k["kev_open"]
    assert get("sla_compliance") == k["sla_compliance"]
    assert get("alerts", days=30) == k["alerts_30d"]
    assert get("edr_coverage") == k["edr_coverage"]
    assert get("mttr_critical_alerts", days=30) == k["mttr_critical_hours"]


def test_metric_params_are_validated(client):
    assert client.get("/api/metrics/open_findings", params={"source": "evil"}).status_code == 422
    assert client.get("/api/metrics/nope").status_code == 404
    assert client.get("/api/metrics/compliance", params={"framework": "Made up"}).status_code == 404



# --------------------------------------------------------------------------- authentication & RBAC
def test_api_requires_sign_in(client):
    anon = TestClient(app, headers=CSRF)
    for path in ("/api/summary", "/api/vulnerabilities/overview", "/api/integrations", "/api/metrics/kev_open", "/api/access/audit"):
        assert anon.get(path).status_code == 401, path
    assert anon.get("/api/health").status_code == 200


def test_executive_sees_aggregates_but_not_asset_detail(client):
    ex = signed_in("exec")
    assert ex.get("/api/summary").status_code == 200
    assert ex.post("/api/report", json={"period_days": 30, "audience": "board"}).status_code == 200
    for path in ("/api/vulnerabilities/findings", "/api/assets/1", "/api/alerts", "/api/threats/active", "/api/integrations"):
        assert ex.get(path).status_code == 403, path
    m = ex.get("/api/metrics/kev_open").json()
    assert m["value"] > 0 and m["items_redacted"] and m["items"]["rows"] == []


def test_analyst_can_investigate_but_not_administer(client):
    an = signed_in("analyst")
    assert an.get("/api/vulnerabilities/findings").status_code == 200
    assert an.get("/api/metrics/kev_open").json()["items"]["rows"]
    assert an.put("/api/integrations/qualys", json={"enabled": True}).status_code == 403
    item = {"title": "Should fail", "item_type": "audit", "start_date": "2026-12-01", "due_date": "2026-12-02", "owner": "x"}
    assert an.post("/api/compliance/roadmap", json=item).status_code == 403
    assert an.get("/api/access/audit").status_code == 403


def test_denied_requests_are_audited(client):
    signed_in("analyst").get("/api/integrations")
    log = client.get("/api/access/audit", params={"action": "access.denied"}).json()
    assert any(e["actor"] == "analyst" and "manage_integrations" in e["detail"] for e in log)


def test_login_failure_is_generic_and_locks_out(client):
    anon = TestClient(app, headers=CSRF)
    unknown = anon.post("/api/auth/login", json={"username": "nobody", "password": "x"})
    wrong = anon.post("/api/auth/login", json={"username": "exec", "password": "wrong"})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json()["detail"] == wrong.json()["detail"]
    for _ in range(5):
        anon.post("/api/auth/login", json={"username": "exec", "password": "wrong"})
    assert anon.post("/api/auth/login", json={"username": "exec", "password": PASSWORDS["exec"]}).status_code == 429
    with get_conn() as conn:  # unlock so other tests can use the account
        conn.execute("UPDATE users SET locked_until=NULL, failed_attempts=0 WHERE username='exec'")


def test_session_cookie_flags_and_logout(client):
    anon = TestClient(app, headers=CSRF)
    r = anon.post("/api/auth/login", json={"username": "analyst", "password": PASSWORDS["analyst"]})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert anon.get("/api/auth/me").json()["role"] == "analyst"
    anon.post("/api/auth/logout")
    assert anon.get("/api/auth/me").status_code == 401


def test_passwords_and_session_tokens_are_not_stored_in_plaintext(client):
    with get_conn() as conn:
        hashes = [r[0] for r in conn.execute("SELECT password_hash FROM users")]
        tokens = [r[0] for r in conn.execute("SELECT token_hash FROM sessions")]
    assert all(h.startswith("scrypt$") for h in hashes)
    assert not any(pw in h for h in hashes for pw in PASSWORDS.values())
    assert all(len(t) == 64 for t in tokens)  # SHA-256 hex digests


def test_state_changes_require_anti_csrf_header(client):
    bare = TestClient(app)
    bare.cookies = client.cookies
    item = {"title": "CSRF", "item_type": "audit", "start_date": "2026-12-01", "due_date": "2026-12-02", "owner": "x"}
    assert bare.post("/api/compliance/roadmap", json=item).status_code == 403


# --------------------------------------------------------------------------- remediation (Jira)
def _untracked_finding():
    with get_conn() as conn:
        return conn.execute("""SELECT f.id, f.cve FROM findings f WHERE f.status='open' AND f.severity IN ('critical','high')
                               AND f.id NOT IN (SELECT finding_id FROM ticket_findings) LIMIT 1""").fetchone()


def test_ticket_lifecycle_from_finding(client):
    an = signed_in("analyst")
    fid = _untracked_finding()["id"]
    draft = an.post("/api/remediation/draft", json={"source_type": "finding", "finding_id": fid}).json()
    assert draft["finding_ids"] == [fid] and draft["priority"] in ("Highest", "High") and draft["due_date"]
    body = {"source_type": "finding", "finding_id": fid, **{k: draft[k] for k in ("summary", "description", "priority", "team", "assignee", "due_date")}}
    t = an.post("/api/remediation/tickets", json=body)
    assert t.status_code == 201
    key = t.json()["key"]
    assert t.json()["status"] == "To Do" and [f["id"] for f in t.json()["findings"]] == [fid]
    # one active ticket per finding
    assert an.post("/api/remediation/tickets", json=body).status_code == 409
    # working the ticket marks the finding in progress; history is recorded
    u = an.patch(f"/api/remediation/tickets/{key}", json={"status": "In Progress"}).json()
    assert u["findings"][0]["status"] == "in_progress" and len(u["history"]) == 2
    # Done but still detected by the scanner -> awaiting verification
    assert an.patch(f"/api/remediation/tickets/{key}", json={"status": "Done"}).json()["verification"] == "awaiting_verification"


def test_wont_fix_records_risk_acceptance(client):
    an = signed_in("analyst")
    fid = _untracked_finding()["id"]
    d = an.post("/api/remediation/draft", json={"source_type": "finding", "finding_id": fid}).json()
    key = an.post("/api/remediation/tickets", json={"source_type": "finding", "finding_id": fid,
                                                    **{k: d[k] for k in ("summary", "description", "priority", "team", "assignee", "due_date")}}).json()["key"]
    t = an.patch(f"/api/remediation/tickets/{key}", json={"status": "Won't Fix"}).json()
    assert t["findings"][0]["status"] == "risk_accepted" and t["resolved_at"]


def test_executives_cannot_change_tickets(client):
    ex = signed_in("exec")
    assert ex.post("/api/remediation/draft", json={"source_type": "finding", "finding_id": 1}).status_code == 403
    assert ex.get("/api/remediation/overview").status_code == 403


def test_ticket_input_validation(client):
    an = signed_in("analyst")
    assert an.post("/api/remediation/draft", json={"source_type": "threat"}).status_code == 422          # no CVE
    assert an.post("/api/remediation/draft", json={"source_type": "threat", "cve": "CVE-1; DROP"}).status_code == 422
    assert an.patch("/api/remediation/tickets/SEC-101", json={"status": "Deleted"}).status_code == 422


def test_remediation_metrics_have_pie_breakdowns(client):
    cat = client.get("/api/metrics").json()
    for key in ("remediation_vulns", "tickets_open", "tickets_overdue", "tracking_coverage"):
        assert cat[key]["pie"], key
        d = client.get(f"/api/metrics/{key}").json()
        pie = next(b for b in d["breakdowns"] if b.get("pie"))
        assert sum(x["value"] for x in pie["data"]) > 0
    ov = client.get("/api/remediation/overview").json()
    open_count = sum(s["count"] for s in ov["status_counts"] if s["status"] in ("To Do", "In Progress", "In Review"))
    assert client.get("/api/metrics/tickets_open").json()["value"] == open_count


# --------------------------------------------------------------------------- AI analyst (Claude API, simulated client)
from types import SimpleNamespace as NS  # noqa: E402

from app import assistant  # noqa: E402


class FakeStream:
    def __init__(self, final, texts):
        self.final, self.texts = final, texts

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def __iter__(self):
        for b in self.final.content:
            if b.type == "tool_use":
                yield NS(type="content_block_start", content_block=b)
        for t in self.texts:
            yield NS(type="text", text=t)

    def get_final_message(self):
        return self.final


class FakeClient:
    """Plays back scripted model turns and records every request."""
    def __init__(self, turns):
        self.turns, self.requests = list(turns), []
        self.beta = NS(messages=NS(stream=self._stream))

    def _stream(self, **params):
        self.requests.append({**params, "messages": list(params["messages"])})  # snapshot: history keeps growing
        content, stop = self.turns.pop(0)
        texts = [b.text for b in content if b.type == "text"]
        return FakeStream(NS(content=content, stop_reason=stop, usage=NS(input_tokens=100, output_tokens=20, cache_read_input_tokens=0)), texts)


def _events(gen):
    return [json.loads(chunk[len("data: "):]) for chunk in gen]


def _user(username):
    with get_conn() as conn:
        return dict(conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone())


def test_assistant_runs_tools_and_streams_answer(client):
    fake = FakeClient([
        ([NS(type="tool_use", id="t1", name="search_findings", input={
            "severity": "critical", "status": "open", "tool": "any", "cve": "", "text": "", "actively_exploited_only": False,
            "internet_facing_only": False, "business_unit": "", "owner_team": "", "limit": 5})], "tool_use"),
        ([NS(type="text", text="You have critical findings on ")], "end_turn"),
    ])
    ev = _events(assistant.chat(_user("analyst"), "What critical vulns are open?", None, client=fake))
    kinds = [e["type"] for e in ev]
    assert kinds[0] == "conversation" and "tool_start" in kinds and "tool_done" in kinds and kinds[-1] == "done"
    assert any(e["type"] == "text" for e in ev)
    # request shape: Opus 5.5, adaptive thinking, explicit effort, server-side fallback, role-filtered strict tools
    req = fake.requests[0]
    assert req["model"] == "claude-opus-5-5" and req["thinking"] == {"type": "adaptive"} and req["output_config"]["effort"] == "medium"
    assert req["fallbacks"] == "default" and "server-side-fallback-2026-07-01" in req["betas"]
    assert all(t["strict"] and t["input_schema"]["additionalProperties"] is False for t in req["tools"])
    # second request carries the tool result back
    tool_result = fake.requests[1]["messages"][2]["content"][0]  # [user, assistant tool_use, user tool_result]
    assert tool_result["type"] == "tool_result" and tool_result["tool_use_id"] == "t1" and not tool_result["is_error"]
    assert "findings" in json.loads(tool_result["content"])


def test_assistant_tools_follow_role_permissions(client):
    exec_tools = {t.name for t in assistant.tools_for(_user("exec"))}
    analyst_tools = {t.name for t in assistant.tools_for(_user("analyst"))}
    assert "search_findings" not in exec_tools and "get_asset" not in exec_tools and "draft_remediation_ticket" not in exec_tools
    assert {"search_findings", "get_asset", "draft_remediation_ticket"} <= analyst_tools
    # even if the model asks for a tool it wasn't offered, execution is refused
    out, err = assistant.run_tool(_user("exec"), "get_asset", {"hostname": "DC-00"})
    assert err and "role" in out["error"]
    # executive metric lookups get aggregates without record-level rows
    out, err = assistant.run_tool(_user("exec"), "get_metric_detail", {"metric_key": "kev_open", "source": "any", "days": 30, "threat_filter": "all", "framework": "any"})
    assert not err and "first_rows" not in out["affected_records"]


def test_assistant_rejects_malformed_tool_input(client):
    out, err = assistant.run_tool(_user("analyst"), "get_asset", {"hostname": "x", "extra": "y"})
    assert err and out["error"] == "Invalid arguments"


def test_assistant_ticket_drafts_are_never_created(client):
    with get_conn() as conn:
        before = conn.execute("SELECT COUNT(*) FROM tickets").fetchone()[0]
    fid = _untracked_finding()["id"]
    fake = FakeClient([
        ([NS(type="tool_use", id="t1", name="draft_remediation_ticket", input={"cve": "", "finding_id": fid})], "tool_use"),
        ([NS(type="text", text="I prepared a draft for you to review.")], "end_turn"),
    ])
    ev = _events(assistant.chat(_user("analyst"), "Draft a ticket", None, client=fake))
    draft = next(e for e in ev if e["type"] == "ticket_draft")
    assert draft["source"] == {"source_type": "finding", "finding_id": fid}
    with get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) FROM tickets").fetchone()[0] == before


def test_assistant_conversations_are_private_and_audited(client):
    fake = FakeClient([([NS(type="text", text="Hi")], "end_turn")])
    ev = _events(assistant.chat(_user("analyst"), "hello", None, client=fake))
    conv_id = ev[0]["id"]
    fake2 = FakeClient([([NS(type="text", text="Hi")], "end_turn")])
    ev2 = _events(assistant.chat(_user("exec"), "hello", conv_id, client=fake2))  # another user's id is not resumed
    assert ev2[0]["id"] != conv_id and len(fake2.requests[0]["messages"]) == 1
    log = client.get("/api/access/audit", params={"action": "assistant.query"}).json()
    assert any(e["actor"] == "analyst" for e in log)


def test_assistant_endpoint_requires_configuration_and_validates(client):
    an = signed_in("analyst")
    assert an.post("/api/assistant/chat", json={"message": ""}).status_code == 422
    os.environ.pop("ANTHROPIC_API_KEY", None)
    if not assistant.configured():
        assert an.post("/api/assistant/chat", json={"message": "hi"}).status_code == 503
    st = an.get("/api/assistant/status").json()
    assert st["model"] == "claude-opus-5-5" and "search_findings" in st["tools"]
    assert "search_findings" not in signed_in("exec").get("/api/assistant/status").json()["tools"]
