"""Executive report generator.

Rather than restating dashboard numbers, the generator evaluates a set of
analytic rules over the same metrics. Each rule that fires produces an
*insight*: what we found, why it matters to the business, what we recommend,
and (where needed) the decision required from leadership. Insights are ranked
by impact and trimmed to the audience.
"""
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from statistics import median

from . import metrics
from .metrics import SEVS, Data

AUDIENCES = {
    "board": {"label": "Board of Directors", "max_insights": 3, "technical": False},
    "executive": {"label": "Executive Leadership Team", "max_insights": 4, "technical": False},
    "security": {"label": "Security & IT Leadership", "max_insights": 6, "technical": True},
}

TEAM_FOR = {"vulnerability": "Infrastructure & IT Operations", "threat": "Vulnerability Management", "detection": "Security Operations",
            "third_party": "Third-Party Risk Management", "coverage": "Endpoint Engineering", "cloud": "Cloud Platform", "compliance": "GRC"}


def _delta(now, before, unit="", better="lower"):
    if now is None or before is None:
        return None
    diff = round(now - before, 1)
    improved = diff < 0 if better == "lower" else diff > 0
    return {"value": now, "previous": before, "change": diff, "unit": unit, "improved": improved if diff else None}


def generate(conn, threats, period_days=30, audience="executive"):
    data = Data(conn)
    ctx = metrics.context(data)
    cfg = AUDIENCES[audience]
    tech = cfg["technical"]
    start = data.today - timedelta(days=period_days)
    start_dt = data.now - timedelta(days=period_days)

    risk_now = metrics.risk_score(data, ctx=ctx)
    risk_then = metrics.risk_score(data, start, ctx)
    v_now, v_then = ctx["vulns"], metrics.vuln_metrics(data, start)
    a_now = metrics.alert_metrics(data, period_days)
    a_then = metrics.alert_metrics(data, period_days, start_dt)
    tprm, cov = ctx["tprm"], ctx["coverage"]
    comp_avg = round(sum(f["pct"] for f in ctx["frameworks"]) / len(ctx["frameworks"]), 1)

    insights = []

    # 1. Actively exploited vulnerabilities in our environment
    kev = [t for t in threats if t["in_kev"]]
    if kev:
        internet = sorted({a["hostname"] for t in kev for a in t["affected_assets"] if a["internet_facing"]})
        ransom = [t for t in kev if t["ransomware"]]
        top = kev[0]
        evidence = [f"{len(kev)} vulnerabilities on CISA's Known Exploited list are open across {len({a['asset_id'] for t in kev for a in t['affected_assets']})} systems",
                    f"{len(internet)} of those systems are reachable from the internet"]
        newly = [t for t in kev if t["newly_listed"]]
        if newly:
            products = Counter(t["product"] for t in newly if t["product"])
            top_product = products.most_common(1)[0][0] if products else None
            coverage = len({n["link"] for t in newly if t["product"] == top_product for n in t["news"]})
            evidence.append(f"{len(newly)} were newly confirmed as exploited in the last 30 days"
                            + (f", including {top_product} flaws covered in {coverage} recent news reports" if top_product and coverage else ""))
        if ransom:
            evidence.append(f"{len(ransom)} are confirmed to be used in ransomware campaigns")
        if tech:
            evidence.append(f"Highest priority: {top['cve']} ({top['title']}) — priority {top['priority']}/100 on {top['asset_count']} assets")
        insights.append({
            "key": "kev", "area": "Active threats", "impact": 95 + min(5, len(internet)),
            "title": "Attackers are actively exploiting weaknesses we have not yet fixed" if not tech else f"{len(kev)} actively exploited CVEs remain open in the environment",
            "evidence": evidence,
            "why": "These are not theoretical risks: government and industry sources have confirmed real attacks using these exact flaws. "
                   "Internet-facing systems can be targeted without any prior access, and exploitation typically follows disclosure within days.",
            "recommendation": "Patch or mitigate internet-facing systems within 72 hours and all remaining affected systems within 14 days. "
                              "Where a patch cannot be applied, isolate the system or apply the vendor's mitigation.",
            "decision": f"Approve an out-of-cycle emergency maintenance window for {len(internet) or 'the affected'} internet-facing systems, accepting brief service interruption.",
            "owner": TEAM_FOR["threat"], "timeframe": "72 hours",
        })

    # 2. Remediation keeping pace?
    if v_now["crit_high_open"]:
        overdue_teams = Counter(f["owner_team"] for f in data.findings if metrics.is_open(f, data.today)
                                and f["severity"] in ("critical", "high") and f["due_date"] < data.today.isoformat())
        team, team_n = (overdue_teams.most_common(1) or [(None, 0)])[0]
        mttr = v_now["mttr_days"]["critical"]
        trend = v_now["crit_high_open"] - v_then["crit_high_open"]
        if v_now["sla_compliance"] < 85:
            evidence = [f"{v_now['crit_high_overdue']} of {v_now['crit_high_open']} critical/high vulnerabilities are past their fix deadline ({v_now['sla_compliance']}% on time)",
                        f"Critical vulnerabilities take {mttr} days to fix on average vs. a 15-day target" if mttr else "No criticals remediated this period",
                        f"Open critical/high count {'rose' if trend > 0 else 'fell'} by {abs(trend)} over the period"]
            if team and tech:
                evidence.append(f"{team} owns {team_n} ({round(100 * team_n / max(1, v_now['crit_high_overdue']))}%) of overdue items")
            insights.append({
                "key": "sla", "area": "Vulnerability management", "impact": 70 + min(20, (85 - v_now["sla_compliance"]) / 2),
                "title": "Fixes for serious vulnerabilities are falling behind schedule",
                "evidence": evidence,
                "why": "The longer a serious weakness stays open, the larger the window for an attacker. Overdue items are also the most common "
                       "audit finding against ISO 27001 (A.8.8) and SOC 2, which affects customer trust and contract renewals.",
                "recommendation": "Introduce an escalation path: items 7 days past due go to the owning business-unit leader, 30 days past due to the executive team. "
                                  "Report remediation performance by team monthly.",
                "decision": "Endorse the remediation escalation policy and require formal, time-bound risk acceptance for any item that cannot be fixed.",
                "owner": TEAM_FOR["vulnerability"], "timeframe": "30 days",
            })
        elif trend < 0:
            insights.append(_positive("remediation", "Vulnerability management", "Remediation is keeping pace with new findings",
                                      [f"{v_now['sla_compliance']}% of critical/high vulnerabilities are within SLA", f"Open critical/high count fell by {abs(trend)}"]))

    # 3. Detection & response
    daily = Counter(a["_det"].date() for a in data.alerts if a["_det"] and a["_det"] >= start_dt)
    spike_day, spike_n = max(daily.items(), key=lambda kv: kv[1]) if daily else (None, 0)
    typical = median(daily.values()) if daily else 0
    cats = Counter(a["category"] for a in data.alerts if a["_det"] and spike_day and a["_det"].date() == spike_day)
    vol_change = round(100 * (a_now["total"] - a_then["total"]) / max(1, a_then["total"]))
    crit_mttr, crit_mttr_then = a_now["mttr_hours"]["critical"], a_then["mttr_hours"]["critical"]
    if spike_day and spike_n >= 1.8 * typical:
        top_cats = ", ".join(c.replace("_", " ") for c, _ in cats.most_common(2))
        insights.append({
            "key": "campaign", "area": "Detection & response", "impact": 75,
            "title": "A targeted phishing and account-takeover campaign was detected and contained" if "phishing" in top_cats or "identity" in top_cats or "bec" in top_cats
                     else "An unusual surge in security alerts was detected and contained",
            "evidence": [f"Alert volume peaked at {spike_n} on {spike_day:%b %d} — {round(spike_n / max(1, typical), 1)}× a typical day",
                         f"Dominant activity: {top_cats}",
                         f"{a_now['incidents']} confirmed incidents this period; critical alerts resolved in {crit_mttr}h on average"],
            "why": "Identity is now the primary way attackers get in: a single compromised account can lead to fraudulent payments (business email compromise) "
                   "or ransomware. Our controls caught this campaign, but it relied on people spotting it rather than prevention.",
            "recommendation": "Roll out phishing-resistant MFA (security keys / passkeys) for executives, finance, and IT administrators first, "
                              "and block legacy authentication protocols.",
            "decision": "Fund phishing-resistant MFA for approximately 150 high-risk users this quarter.",
            "owner": TEAM_FOR["detection"], "timeframe": "This quarter",
        })
    if crit_mttr and crit_mttr_then and crit_mttr < crit_mttr_then:
        insights.append(_positive("mttr", "Detection & response", "Response to critical alerts is getting faster",
                                  [f"Critical alert response time improved from {crit_mttr_then}h to {crit_mttr}h",
                                   f"Median time to detect: {a_now['mttd_minutes']} minutes"]))

    # 4. Coverage blind spots
    if cov["edr_coverage"] < 95:
        unmanaged = cov["edr"]["missing"] + cov["edr"]["rfm"]
        cloud_missing = sum(1 for a in data.assets.values() if a["environment"] in ("aws", "azure", "gcp") and a["edr_status"] == "missing")
        insights.append({
            "key": "coverage", "area": "Security coverage", "impact": 60 + (95 - cov["edr_coverage"]) * 2,
            "title": "Some systems are invisible to our endpoint protection",
            "evidence": [f"Endpoint protection covers {cov['edr_coverage']}% of managed systems — {unmanaged} systems unprotected or degraded",
                         f"{cloud_missing} of the unprotected systems run in the cloud",
                         f"{cov['scan_coverage']}% of assets were vulnerability-scanned in the last 30 days"],
            "why": "Attackers look for the systems we cannot see. An unprotected system is where ransomware typically lands and spreads from, "
                   "and incidents there take far longer to detect and investigate.",
            "recommendation": "Make endpoint protection a deployment requirement for new systems and quarantine systems that report without it.",
            "decision": "Mandate EDR coverage as a production-readiness requirement, including for cloud workloads.",
            "owner": TEAM_FOR["coverage"], "timeframe": "60 days",
        })

    # 5. Third-party risk
    flagged_t1 = [v for v in tprm["vendors"] if v["tier"] == 1 and v["reasons"]]
    if flagged_t1 or tprm["overdue_assessments"]:
        worst = flagged_t1[0] if flagged_t1 else tprm["vendors"][0]
        insights.append({
            "key": "vendors", "area": "Third-party risk", "impact": 65 + 5 * len(flagged_t1),
            "title": f"{len(flagged_t1)} critical suppliers show weakening security" if flagged_t1 else "Supplier security reviews are overdue",
            "evidence": [f"{tprm['needs_attention']} of {tprm['vendor_count']} vendors need attention; {tprm['overdue_assessments']} assessments overdue",
                         f"{worst['name']} ({worst['data_access']}): {'; '.join(worst['reasons'])}",
                         f"Portfolio average: Bitsight {tprm['avg_bitsight']}, SecurityScorecard {tprm['avg_ssc']}"],
            "why": f"Critical suppliers hold our data and connect to our systems; a breach at {worst['name']} would be treated as our breach by customers and regulators.",
            "recommendation": "Request remediation plans from flagged tier-1 vendors within 30 days and complete overdue assessments before renewal.",
            "decision": f"Decide whether {worst['name']}'s renewal should be made contingent on security improvements.",
            "owner": TEAM_FOR["third_party"], "timeframe": "30 days",
        })

    # 6. Cloud toxic combinations
    toxic = [c for c in data.cloud if c["status"] == "open" and c["category"] == "toxic_combination"]
    if toxic:
        insights.append({
            "key": "cloud", "area": "Cloud security", "impact": 72 + min(15, len(toxic)),
            "title": "Some cloud systems combine several weaknesses into a direct path to sensitive data",
            "evidence": [f"{len(toxic)} open 'toxic combinations' (internet exposure + exploitable vulnerability + excessive privileges)",
                         f"{ctx['cloud_critical_open']} critical cloud issues open in total"],
            "why": "Individually these are moderate issues; combined, they give an attacker a one-step route from the internet to privileged access in our cloud.",
            "recommendation": "Fix toxic combinations within 7 days and add preventive guardrails (e.g. block public storage, require least-privilege roles) in deployment pipelines.",
            "decision": "Approve preventive cloud guardrails that may block non-compliant deployments.",
            "owner": TEAM_FOR["cloud"], "timeframe": "7 days",
        })

    # 7. Audit readiness
    horizon = (data.today + timedelta(days=90)).isoformat()
    audits = [r for r in data.roadmap if r["item_type"] in ("audit", "assessment") and data.today.isoformat() <= r["start_date"] <= horizon]
    weak_fw = [f for f in ctx["frameworks"] if f["pct"] < 85]
    if audits and weak_fw:
        insights.append({
            "key": "audit", "area": "Compliance", "impact": 58,
            "title": f"{len(audits)} audits/assessments in the next 90 days with known control gaps",
            "evidence": [f"{a['title']} starts {a['start_date']}" for a in audits[:3]] +
                        [f"{f['framework']}: {f['pct']}% of controls implemented" for f in weak_fw],
            "why": "Audit findings can delay certifications that customers require during procurement, directly affecting revenue.",
            "recommendation": "Prioritize remediation of controls tied to vulnerability management and supplier monitoring, which feed directly from this dashboard's data.",
            "decision": None, "owner": TEAM_FOR["compliance"], "timeframe": "Before audit fieldwork",
        })

    if risk_now["score"] < risk_then["score"] - 2:
        insights.append(_positive("risk", "Overall posture", "Overall cyber risk is trending down",
                                  [f"Enterprise risk score improved from {risk_then['score']} to {risk_now['score']}"]))

    concerns = sorted([i for i in insights if not i.get("positive")], key=lambda i: -i["impact"])[:cfg["max_insights"]]
    wins = [i for i in insights if i.get("positive")][: (1 if audience == "board" else 3)]
    decisions = [{"decision": i["decision"], "owner": i["owner"], "timeframe": i["timeframe"], "area": i["area"]} for i in concerns if i["decision"]]

    change = round(risk_now["score"] - risk_then["score"], 1)
    direction = "improved" if change < 0 else "worsened" if change > 0 else "held steady"
    bluf = (f"Overall cyber risk is {risk_now['rating'].lower()} at {risk_now['score']}/100 and has {direction}"
            f"{f' by {abs(change)} points' if change else ''} over the last {period_days} days. "
            + (f"The most urgent issue: {concerns[0]['title'].lower()}. " if concerns else "")
            + (f"Leadership is asked to make {len(decisions)} decision{'s' if len(decisions) != 1 else ''}." if decisions else "No leadership decisions are required this period."))

    goals = [metrics.goal_progress(dict(g), ctx) for g in conn.execute("SELECT * FROM goals")]

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "period": {"days": period_days, "start": start.isoformat(), "end": data.today.isoformat()},
        "audience": {"key": audience, **cfg},
        "bluf": bluf,
        "risk": {"score": risk_now["score"], "rating": risk_now["rating"], "previous": risk_then["score"], "change": change,
                 "components": risk_now["components"]},
        "scorecard": [
            {"label": "Enterprise risk score", **_delta(risk_now["score"], risk_then["score"], "/100")},
            {"label": "Open critical vulnerabilities", **_delta(v_now["by_severity"]["critical"], v_then["by_severity"]["critical"])},
            {"label": "Actively exploited CVEs open", **_delta(v_now["kev_open"], v_then["kev_open"])},
            {"label": "Critical/high fixed on time", **_delta(v_now["sla_compliance"], v_then["sla_compliance"], "%", "higher")},
            {"label": "Security alerts", **_delta(a_now["total"], a_then["total"])},
            {"label": "Confirmed incidents", **_delta(a_now["incidents"], a_then["incidents"])},
            {"label": "Critical alert response time", **_delta(crit_mttr, crit_mttr_then, "h")},
            {"label": "Endpoint protection coverage", "value": cov["edr_coverage"], "previous": None, "change": None, "unit": "%", "improved": None},
            {"label": "Compliance (avg. across frameworks)", "value": comp_avg, "previous": None, "change": None, "unit": "%", "improved": None},
        ],
        "insights": concerns, "wins": wins, "decisions": decisions,
        "outlook": sorted([{k: r[k] for k in ("title", "item_type", "framework", "start_date", "due_date", "owner", "status")}
                           for r in data.roadmap if r["status"] != "complete" and r["due_date"] >= data.today.isoformat() and r["start_date"] <= horizon],
                          key=lambda r: r["start_date"]),
        "goals": goals,
    }


def _positive(key, area, title, evidence):
    return {"key": key, "area": area, "title": title, "evidence": evidence, "positive": True, "impact": 0}


def to_markdown(r):
    lines = [f"# Cybersecurity Executive Report", f"**Audience:** {r['audience']['label']}  ",
             f"**Period:** {r['period']['start']} to {r['period']['end']}  ", "", "## Bottom line", r["bluf"], "",
             "## Scorecard", "| Metric | Current | Previous | Change |", "|---|---|---|---|"]
    for s in r["scorecard"]:
        prev = "—" if s["previous"] is None else f"{s['previous']}{s['unit']}"
        chg = "—" if not s["change"] else f"{s['change']:+g}{s['unit']}"
        lines.append(f"| {s['label']} | {s['value']}{s['unit']} | {prev} | {chg} |")
    lines += ["", "## Top takeaways"]
    for n, i in enumerate(r["insights"], 1):
        lines += [f"### {n}. {i['title']}", *[f"- {e}" for e in i["evidence"]], "", f"**Why it matters:** {i['why']}", "",
                  f"**Recommendation:** {i['recommendation']}", ""]
        if i["decision"]:
            lines += [f"**Decision needed:** {i['decision']}", ""]
    if r["decisions"]:
        lines += ["## Decisions requested", "| # | Decision | Owner | Timeframe |", "|---|---|---|---|"]
        lines += [f"| {n} | {d['decision']} | {d['owner']} | {d['timeframe']} |" for n, d in enumerate(r["decisions"], 1)]
    if r["wins"]:
        lines += ["", "## What's working"] + [f"- **{w['title']}** — {'; '.join(w['evidence'])}" for w in r["wins"]]
    if r["outlook"]:
        lines += ["", "## Next 90 days"] + [f"- {o['start_date']}: {o['title']} ({o['owner']})" for o in r["outlook"]]
    return "\n".join(lines) + "\n"
