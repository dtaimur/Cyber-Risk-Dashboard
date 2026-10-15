"""Jira Cloud connector (REST API v3, basic auth with an API token).

Unlike the security tools, Jira is two-way: the dashboard creates issues and
moves them through workflow transitions, and a sync pulls status changes made
by engineers in Jira back into the dashboard.
"""
from .base import Connector, ConnectorError

LABEL = "cyber-risk-dashboard"
# Jira status categories map onto our normalized ticket states
CATEGORY_STATUS = {"new": "To Do", "indeterminate": "In Progress", "done": "Done"}


def adf(text: str):
    """Plain text -> Atlassian Document Format (required by the v3 API)."""
    paragraphs = [p for p in text.split("\n\n") if p.strip()]
    return {"type": "doc", "version": 1, "content": [
        {"type": "paragraph", "content": [{"type": "text", "text": line}] if line else []}
        for p in paragraphs for line in [p.strip()]]}


class JiraConnector(Connector):
    id = "jira"
    kind = "ticketing"
    name = "Jira Cloud"
    description = "Remediation workflow: create issues for vulnerabilities and track them to closure."
    docs_url = "https://developer.atlassian.com/cloud/jira/platform/rest/v3/"
    fields = [
        {"key": "base_url", "label": "Site URL", "secret": False, "placeholder": "https://your-company.atlassian.net"},
        {"key": "email", "label": "Account email", "secret": False, "placeholder": "you@company.com"},
        {"key": "project_key", "label": "Project key", "secret": False, "placeholder": "SEC"},
        {"key": "issue_type", "label": "Issue type", "secret": False, "placeholder": "Task"},
        {"key": "secret", "label": "API token", "secret": True, "placeholder": "Atlassian API token"},
    ]

    def _client(self, cfg, secret):
        if not cfg.get("base_url"):
            raise ConnectorError("Site URL is required")
        return self.client(base_url=cfg["base_url"].rstrip("/"), auth=(cfg.get("email", ""), secret),
                           headers={"Accept": "application/json"})

    @staticmethod
    def _check(r):
        if r.status_code in (401, 403):
            raise ConnectorError(f"Authentication failed (HTTP {r.status_code})")
        if r.status_code >= 400:
            try:
                errs = r.json()
                msg = "; ".join(errs.get("errorMessages", []) + [f"{k}: {v}" for k, v in errs.get("errors", {}).items()])
            except ValueError:
                msg = r.text[:200]
            if r.status_code == 404 and not msg.strip():
                msg = "not found (check the site URL and project key)"
            raise ConnectorError(f"Jira error {r.status_code}: {msg}")
        return r

    def test(self, cfg, secret):
        with self._client(cfg, secret) as c:
            me = self._check(c.get("/rest/api/3/myself")).json()
            key = cfg.get("project_key") or "SEC"
            proj = self._check(c.get(f"/rest/api/3/project/{key}")).json()
        return f"Authenticated as {me.get('displayName')}. Project {proj.get('key')}: {proj.get('name')}."

    def create_issue(self, cfg, secret, ticket):
        fields = {
            "project": {"key": cfg.get("project_key") or "SEC"},
            "issuetype": {"name": cfg.get("issue_type") or "Task"},
            "summary": ticket["summary"][:250],
            "description": adf(ticket["description"]),
            "labels": [LABEL] + ([ticket["cve"].lower()] if ticket.get("cve") else []),
        }
        if ticket.get("due_date"):
            fields["duedate"] = ticket["due_date"]
        with self._client(cfg, secret) as c:
            created = self._check(c.post("/rest/api/3/issue", json={"fields": fields})).json()
        return created["key"], f"{cfg['base_url'].rstrip('/')}/browse/{created['key']}"

    def transition(self, cfg, secret, key, target_status):
        """Moves an issue to the workflow transition whose target matches our status."""
        with self._client(cfg, secret) as c:
            options = self._check(c.get(f"/rest/api/3/issue/{key}/transitions")).json()["transitions"]
            want = target_status.lower()
            match = next((t for t in options if t["to"]["name"].lower() == want), None) \
                or next((t for t in options if CATEGORY_STATUS.get(t["to"]["statusCategory"]["key"], "").lower() == want), None)
            if not match:
                raise ConnectorError(f"No Jira transition to '{target_status}' from the issue's current status")
            self._check(c.post(f"/rest/api/3/issue/{key}/transitions", json={"transition": {"id": match["id"]}}))

    def fetch_issues(self, cfg, secret):
        """Issues this dashboard created (by label), with current status."""
        jql = f'project = "{cfg.get("project_key") or "SEC"}" AND labels = "{LABEL}" ORDER BY created DESC'
        out, token = [], None
        with self._client(cfg, secret) as c:
            while True:
                body = {"jql": jql, "maxResults": 100, "fields": ["status", "assignee", "updated", "resolutiondate", "duedate", "summary"]}
                if token:
                    body["nextPageToken"] = token
                page = self._check(c.post("/rest/api/3/search/jql", json=body)).json()
                for i in page.get("issues", []):
                    f = i["fields"]
                    out.append({"key": i["key"], "status": f["status"]["name"],
                                "category": CATEGORY_STATUS.get(f["status"]["statusCategory"]["key"], "To Do"),
                                "assignee": (f.get("assignee") or {}).get("displayName"),
                                "resolved_at": (f.get("resolutiondate") or "")[:19].replace("T", " ") or None,
                                "due_date": f.get("duedate")})
                token = page.get("nextPageToken")
                if not token or len(out) >= 1000:
                    return out

    def sync(self, cfg, secret):
        raise NotImplementedError("Jira sync is handled by app.remediation.sync_from_jira")
