"""Live threat intelligence ingestion and correlation.

Sources (all public, no API key required):
  * CISA Known Exploited Vulnerabilities (KEV) catalog - JSON
  * SecurityWeek, The Hacker News, BleepingComputer, Dark Reading - RSS
  * FIRST EPSS - probability a CVE is exploited in the next 30 days
  * NVD - CVSS base scores for CVEs not in our local catalog

Fetched data is cached in SQLite so the dashboard keeps working offline.
"""
import hashlib
import html
import json
import re
from datetime import date, datetime, timedelta, timezone

import feedparser
import httpx

from . import catalog
from .db import get_conn, jloads, rows

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")
# Emoji and pictographic symbols some outlets put in headlines
EMOJI_RE = re.compile("[\U0001F000-\U0001FFFF\u2600-\u27BF\u2B00-\u2BFF\u2190-\u21FF\u25A0-\u25FF\uFE0F\u200D]")
HEADERS = {"User-Agent": "Cyber-Risk-Dashboard/1.0 (demo)"}
TIMEOUT = httpx.Timeout(20.0)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

NEWS_FEEDS = {
    "securityweek": ("SecurityWeek", "https://www.securityweek.com/feed/"),
    "thehackernews": ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    "bleepingcomputer": ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    "darkreading": ("Dark Reading", "https://www.darkreading.com/rss.xml"),
}


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean(text, limit=400):
    text = EMOJI_RE.sub("", html.unescape(TAG_RE.sub(" ", text or "")))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def watchlist(conn):
    """Product keywords from our tech stack, used to flag relevant news."""
    words = set(catalog.TECH_STACK)
    for r in conn.execute("SELECT software FROM assets"):
        words.update(jloads(r["software"], []))
    # Very generic names would flag almost every article
    return sorted(w for w in words if w not in {"Windows 11", "macOS", "Chrome", "Microsoft Office"} and len(w) > 3)


def _match_products(text, words):
    low = text.lower()
    return [w for w in words if re.search(r"\b" + re.escape(w.lower()) + r"\b", low)]


# --------------------------------------------------------------------------- fetchers
def fetch_kev(client: httpx.Client):
    data = client.get(KEV_URL).raise_for_status().json()
    vulns = data.get("vulnerabilities", [])
    with get_conn() as conn:
        conn.executemany(
            "INSERT OR REPLACE INTO kev (cve,vendor,product,name,date_added,due_date,ransomware,description,action) VALUES (?,?,?,?,?,?,?,?,?)",
            [(v["cveID"], v.get("vendorProject"), v.get("product"), v.get("vulnerabilityName"), v.get("dateAdded"),
              v.get("dueDate"), v.get("knownRansomwareCampaignUse"), v.get("shortDescription"), v.get("requiredAction"))
             for v in vulns])
    return len(vulns)


def fetch_feed(client: httpx.Client, feed_id: str):
    name, url = NEWS_FEEDS[feed_id]
    parsed = feedparser.parse(client.get(url).raise_for_status().content)
    with get_conn() as conn:
        words = watchlist(conn)
        count = 0
        for e in parsed.entries[:60]:
            link = e.get("link")
            if not link:
                continue
            body = " ".join([e.get("title", ""), e.get("summary", "")] + [c.get("value", "") for c in e.get("content", [])])
            published = None
            if e.get("published_parsed"):
                published = datetime(*e.published_parsed[:6], tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            cves = sorted({c.upper() for c in CVE_RE.findall(body)})
            conn.execute(
                "INSERT OR REPLACE INTO articles (id,source,title,link,published,summary,cves,products) VALUES (?,?,?,?,?,?,?,?)",
                (hashlib.sha1(link.encode()).hexdigest(), name, _clean(e.get("title", ""), 300), link, published,
                 _clean(e.get("summary", "")), json.dumps(cves), json.dumps(_match_products(body, words))))
            count += 1
    return count


def fetch_epss(client: httpx.Client, cves):
    cves = sorted(set(cves))
    total = 0
    for i in range(0, len(cves), 80):
        batch = cves[i:i + 80]
        data = client.get(EPSS_URL, params={"cve": ",".join(batch)}).raise_for_status().json()
        with get_conn() as conn:
            for item in data.get("data", []):
                conn.execute("INSERT OR REPLACE INTO epss (cve,score,percentile,fetched_at) VALUES (?,?,?,?)",
                             (item["cve"], float(item["epss"]), float(item["percentile"]), _now()))
                total += 1
    return total


def nvd_cvss(client: httpx.Client, cve: str):
    data = client.get(NVD_URL, params={"cveId": cve}).raise_for_status().json()
    for v in data.get("vulnerabilities", []):
        metrics = v["cve"].get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
            if metrics.get(key):
                return metrics[key][0]["cvssData"]["baseScore"]
    return None


def env_cves(conn):
    return [r["cve"] for r in conn.execute("SELECT DISTINCT cve FROM findings WHERE cve IS NOT NULL")]


def refresh(sources=None):
    """Pulls every enabled threat feed. Returns per-source status."""
    from .integrations import set_status, enabled_ids
    sources = sources or [s for s in ["cisa_kev", *NEWS_FEEDS, "epss"] if s in enabled_ids()]
    results = {}
    with httpx.Client(headers=HEADERS, timeout=TIMEOUT, follow_redirects=True) as client:
        for s in sources:
            try:
                if s == "cisa_kev":
                    n = fetch_kev(client)
                elif s == "epss":
                    with get_conn() as conn:
                        n = fetch_epss(client, env_cves(conn))
                else:
                    n = fetch_feed(client, s)
                set_status(s, "ok", f"Fetched {n} records", n)
                results[s] = {"ok": True, "count": n}
            except Exception as exc:  # network errors should never break the dashboard
                set_status(s, "error", f"{type(exc).__name__}: {exc}"[:300], None)
                results[s] = {"ok": False, "error": str(exc)[:300]}
    return results


def enrich_cvss(cves):
    """Replace placeholder CVSS for injected CVEs with the real NVD base score."""
    with httpx.Client(headers=HEADERS, timeout=TIMEOUT) as client:
        for cve in cves:
            try:
                score = nvd_cvss(client, cve)
            except Exception:
                score = None
            if score:
                with get_conn() as conn:
                    conn.execute("UPDATE findings SET cvss=?, severity=?, vendor_score=? WHERE cve=?",
                                 (score, catalog.severity_from_cvss(score), round(score * 10, 1), cve))


# --------------------------------------------------------------------------- correlation
WEIGHTS = {"severity": 20, "kev": 15, "ransomware": 10, "epss": 10, "emerging": 20, "exposure": 15, "criticality": 10}


def active_threats(conn, news_days=45):
    """Joins vulnerabilities found in our environment with external threat intel
    and ranks them with a transparent, additive priority score (0-100)."""
    open_findings = rows(conn, """
        SELECT f.cve, f.title, f.cvss, f.product, f.severity, f.source, f.due_date, f.first_seen, a.id AS asset_id, a.hostname,
               a.criticality, a.internet_facing, a.business_unit, a.owner
        FROM findings f JOIN assets a ON a.id = f.asset_id
        WHERE f.cve IS NOT NULL AND f.status IN ('open','in_progress')""")
    kev = {r["cve"]: r for r in rows(conn, "SELECT * FROM kev")}
    epss = {r["cve"]: r for r in rows(conn, "SELECT * FROM epss")}
    since = (datetime.now(timezone.utc) - timedelta(days=news_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    recent_cutoff = (datetime.now(timezone.utc) - timedelta(days=14)).strftime("%Y-%m-%dT%H:%M:%SZ")
    new_kev_cutoff = (date.today() - timedelta(days=30)).isoformat()
    news, product_news = {}, []
    for a in rows(conn, "SELECT id,source,title,link,published,cves,products FROM articles WHERE published >= ? ORDER BY published DESC", (since,)):
        item = {k: a[k] for k in ("source", "title", "link", "published")}
        for c in jloads(a["cves"], []):
            news.setdefault(c, []).append(item)
        if a["published"] >= recent_cutoff:
            product_news.append((jloads(a["products"], []), item))

    grouped = {}
    for f in open_findings:
        g = grouped.setdefault(f["cve"], {"cve": f["cve"], "title": f["title"], "cvss": f["cvss"], "severity": f["severity"], "product": f["product"],
                                           "sources": set(), "assets": {}, "earliest_due": f["due_date"]})
        g["sources"].add(f["source"])
        g["assets"][f["asset_id"]] = {k: f[k] for k in ("asset_id", "hostname", "criticality", "internet_facing", "business_unit", "owner")}
        g["earliest_due"] = min(g["earliest_due"], f["due_date"])

    today = date.today().isoformat()
    threats = []
    for cve, g in grouped.items():
        k, e, n = kev.get(cve), epss.get(cve), news.get(cve, [])
        epss_score = e["score"] if e else 0.0
        if not (k or n or epss_score >= 0.5):
            continue  # not an active threat, handled by normal vuln management
        assets = list(g["assets"].values())
        internet = sum(a["internet_facing"] for a in assets)
        # Trending: other recent articles about the same product (e.g. a zero-day wave against one appliance)
        product_text = f"{(k or {}).get('vendor', '')} {(k or {}).get('product', '')} {g['product'] or ''}".lower()
        trending = [item for prods, item in product_news
                    if item not in n and any(p.lower() in product_text for p in prods)]
        newly_listed = bool(k and k["date_added"] >= new_kev_cutoff)
        breakdown = {
            "severity": round(WEIGHTS["severity"] * (g["cvss"] or 0) / 10, 1),
            "kev": WEIGHTS["kev"] if k else 0,
            "ransomware": WEIGHTS["ransomware"] if k and k["ransomware"] == "Known" else 0,
            "epss": round(WEIGHTS["epss"] * epss_score, 1),
            "emerging": min(WEIGHTS["emerging"], 6 * len(n) + 2 * len(trending) + (8 if newly_listed else 0)),
            "exposure": min(WEIGHTS["exposure"], 2 * len(assets) + 5 * internet),
            "criticality": 2 * max(a["criticality"] for a in assets),
        }
        threats.append({
            "cve": cve, "title": (k or {}).get("name") or g["title"], "cvss": g["cvss"], "severity": g["severity"],
            "priority": round(min(100, sum(breakdown.values()))), "breakdown": breakdown,
            "in_kev": bool(k), "kev_date_added": (k or {}).get("date_added"), "ransomware": (k or {}).get("ransomware") == "Known",
            "vendor": (k or {}).get("vendor"), "product": (k or {}).get("product"),
            "description": (k or {}).get("description"),
            "required_action": (k or {}).get("action") or "Apply the vendor security update or mitigation.",
            "epss": epss_score, "epss_percentile": e["percentile"] if e else None,
            "news": (n + trending)[:6], "news_count": len(n), "trending_count": len(trending), "newly_listed": newly_listed,
            "sources": sorted(g["sources"]),
            "affected_assets": sorted(assets, key=lambda a: (-a["internet_facing"], -a["criticality"])),
            "asset_count": len(assets), "internet_facing_count": internet,
            "sla_due": g["earliest_due"], "overdue": g["earliest_due"] < today,
        })
    threats.sort(key=lambda t: -t["priority"])
    return threats


def unverified_exposure(conn, limit=15):
    """KEV entries for products we run but where no scanner reported the CVE -
    either we're patched or the scanners lack coverage. Worth verifying."""
    stack = {w.lower() for w in watchlist(conn)}
    found = set(env_cves(conn))
    since = (date.today() - timedelta(days=120)).isoformat()
    out = []
    for k in rows(conn, "SELECT * FROM kev WHERE date_added >= ? ORDER BY date_added DESC", (since,)):
        if k["cve"] in found:
            continue
        text = f"{k['vendor']} {k['product']}".lower()
        hit = next((w for w in stack if w in text or k["product"].lower() in w), None)
        if hit:
            out.append({**k, "matched_product": hit})
    return out[:limit]
