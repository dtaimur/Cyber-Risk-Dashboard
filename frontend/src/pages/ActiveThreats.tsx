import { useEffect, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { ChevronDown, ChevronRight, ExternalLink, Globe, Newspaper } from 'lucide-react'
import { useApi } from '../api'
import { TOOL_NAME, fmtDate, timeAgo } from '../format'
import { useAssetDrawer } from '../components/AssetDrawer'
import { Card, ErrorBox, Loading, PageHeader } from '../components/ui'
import { Kpi } from '../components/Metric'
import { TicketButton } from '../components/Tickets'

const FACTOR_LABEL: Record<string, string> = {
  severity: 'CVSS severity', kev: 'Known exploited', ransomware: 'Ransomware use', epss: 'EPSS likelihood',
  emerging: 'Emerging / in news', exposure: 'Exposure', criticality: 'Asset criticality',
}

function prioColor(p: number) {
  return p >= 75 ? 'var(--critical)' : p >= 60 ? 'var(--high)' : 'var(--medium)'
}

export default function ActiveThreats() {
  const { data: d, error, reload } = useApi<any>('/threats/active')
  const { hash } = useLocation()
  const focus = hash.slice(1)

  useEffect(() => {
    if (d && focus) document.getElementById(focus)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }, [d, focus])

  if (error) return <ErrorBox error={error} onRetry={reload} />
  if (!d) return <Loading />
  const s = d.stats

  return (
    <>
      <PageHeader title="Active Threats"
        subtitle="Vulnerabilities we have that are exploited, likely to be exploited, or in the news, ranked by priority" />
      <div className="grid g-6">
        <Kpi label="Active threats" metric="active_threats" params={{ filter: "all" }} value={s.total} foot="Correlated with our scans" />
        <Kpi label="On CISA KEV" metric="active_threats" params={{ filter: "kev" }} value={s.kev} tone={s.kev ? 'bad' : 'good'} foot="Confirmed exploitation" />
        <Kpi label="Ransomware-linked" metric="active_threats" params={{ filter: "ransomware" }} value={s.ransomware} tone={s.ransomware ? 'bad' : 'good'} />
        <Kpi label="In recent news" metric="active_threats" params={{ filter: "news" }} value={s.in_news} foot="CVE cited in an article" />
        <Kpi label="Internet-facing assets" metric="active_threats" params={{ filter: "internet" }} value={s.internet_facing_assets} foot="Exposed to these threats" />
        <Kpi label="Past remediation SLA" metric="active_threats" params={{ filter: "overdue" }} value={s.overdue} tone={s.overdue ? 'bad' : 'good'} />
      </div>

      <Card className="mt" title="How priority is calculated" subtitle="Additive score out of 100 — every factor is visible on each threat">
        <div className="breakdown">
          {Object.entries(d.weights).map(([k, w]) => <div key={k}>{FACTOR_LABEL[k]}<b>up to {w as number}</b></div>)}
        </div>
      </Card>

      <div className="grid g-3 mt" style={{ alignItems: 'start' }}>
        <div className="span-2" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {d.threats.map((t: any, i: number) => <ThreatCard key={t.cve} t={t} defaultOpen={i === 0 || t.cve === focus} focused={t.cve === focus} />)}
          {d.threats.length === 0 && <Card><div className="empty">No active threats correlated with our environment.</div></Card>}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <Card title="Verify exposure" subtitle="Recently exploited CVEs in products we run that no scanner has reported — confirm we're patched or that scanners cover these systems">
            <div className="list">
              {d.unverified.map((k: any) => (
                <div key={k.cve} className="list-item">
                  <span className="sev-bar" style={{ background: 'var(--medium)' }} />
                  <div style={{ minWidth: 0 }}>
                    <div><span className="mono" style={{ fontWeight: 600 }}>{k.cve}</span> <span className="muted" style={{ fontSize: 12 }}>added {fmtDate(k.date_added)}</span></div>
                    <div style={{ fontSize: 12.5 }}>{k.vendor} {k.product}</div>
                    <div className="muted" style={{ fontSize: 12 }}>{k.name}</div>
                  </div>
                </div>
              ))}
              {d.unverified.length === 0 && <div className="empty">Nothing to verify</div>}
            </div>
          </Card>
          <Card title="Tech-stack watchlist" subtitle="News from the last 3 weeks mentioning products we run">
            <div className="list">
              {d.watchlist.map((w: any) => (
                <a key={w.id} className="list-item" href={w.link} target="_blank" rel="noopener noreferrer" style={{ color: 'inherit', textDecoration: 'none' }}>
                  <Newspaper size={15} className="muted" style={{ flexShrink: 0, marginTop: 2 }} />
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 500 }}>{w.title}</div>
                    <div className="chips" style={{ marginTop: 4 }}>
                      {w.products.map((p: string) => <span key={p} className="badge badge-accent">{p}</span>)}
                      <span className="muted" style={{ fontSize: 11.5 }}>{w.source} · {timeAgo(w.published)}</span>
                    </div>
                  </div>
                </a>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </>
  )
}

function ThreatCard({ t, defaultOpen, focused }: { t: any; defaultOpen: boolean; focused: boolean }) {
  const [open, setOpen] = useState(defaultOpen)
  const openAsset = useAssetDrawer()
  return (
    <div id={t.cve} className={`threat ${focused ? 'focus' : ''}`}>
      <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start', cursor: 'pointer' }} onClick={() => setOpen(!open)}>
        <div className="prio" style={{ background: prioColor(t.priority), color: t.priority >= 75 ? '#fff' : '#1a1a19' }}>{t.priority}<small>PRIORITY</small></div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <span className="mono" style={{ fontWeight: 700, fontSize: 14 }}>{t.cve}</span>
            {t.in_kev && <span className="badge badge-kev">CISA KEV</span>}
            {t.newly_listed && <span className="badge badge-kev">New this month</span>}
            {t.ransomware && <span className="badge">Ransomware</span>}
            {t.news_count + t.trending_count > 0 && <span className="badge badge-accent"><Newspaper size={11} /> {t.news_count + t.trending_count} news</span>}
            {t.overdue && <span className="badge" style={{ color: 'var(--bad-text)' }}>Past SLA</span>}
          </div>
          <div style={{ fontWeight: 600, marginTop: 4 }}>{t.title}</div>
          <div className="muted" style={{ fontSize: 12.5, marginTop: 2 }}>
            CVSS {t.cvss ?? '—'} · EPSS {(t.epss * 100).toFixed(1)}% · {t.asset_count} asset{t.asset_count !== 1 && 's'}
            {t.internet_facing_count > 0 && <> · <span style={{ color: 'var(--bad-text)' }}>{t.internet_facing_count} internet-facing</span></>}
            {' '}· found by {t.sources.map((s: string) => TOOL_NAME[s]).join(', ')}
          </div>
        </div>
        <div onClick={(e) => e.stopPropagation()} style={{ flexShrink: 0 }}>
          <TicketButton ticket={t.ticket} src={{ source_type: 'threat', cve: t.cve }} />
        </div>
        {open ? <ChevronDown size={18} className="muted" /> : <ChevronRight size={18} className="muted" />}
      </div>

      {open && (
        <div style={{ marginTop: 14 }}>
          <div className="breakdown" style={{ marginBottom: 14 }}>
            {Object.entries(t.breakdown).map(([k, v]) => <div key={k}>{FACTOR_LABEL[k]}<b>+{v as number}</b></div>)}
          </div>
          {t.description && <p className="text-2" style={{ margin: '0 0 10px', fontSize: 13 }}>{t.description}</p>}
          <div style={{ background: 'var(--accent-soft)', borderRadius: 4, padding: '10px 12px', fontSize: 13, marginBottom: 14 }}>
            <b>Required action:</b> {t.required_action}
            <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>Internal SLA due {fmtDate(t.sla_due)}{t.kev_date_added && ` · added to KEV ${fmtDate(t.kev_date_added)}`}</div>
          </div>
          <div className="grid g-2" style={{ gap: 14 }}>
            <div>
              <div className="card-sub" style={{ marginBottom: 6 }}>Affected assets</div>
              <table>
                <tbody>
                  {t.affected_assets.slice(0, 8).map((a: any) => (
                    <tr key={a.asset_id} className="clickable" onClick={() => openAsset(a.asset_id)}>
                      <td>{a.hostname} {a.internet_facing ? <Globe size={12} color="var(--critical)" aria-label="Internet-facing" /> : null}</td>
                      <td className="text-2">{a.business_unit}</td>
                      <td className="muted">{a.owner}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {t.affected_assets.length > 8 && <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>+{t.affected_assets.length - 8} more</div>}
            </div>
            <div>
              <div className="card-sub" style={{ marginBottom: 6 }}>Threat intelligence</div>
              {t.news.length === 0 && <div className="muted" style={{ fontSize: 12.5 }}>No recent news coverage. Prioritized by KEV listing and EPSS.</div>}
              {t.news.map((n: any) => (
                <a key={n.link} href={n.link} target="_blank" rel="noopener noreferrer" style={{ display: 'block', fontSize: 12.5, marginBottom: 8 }}>
                  {n.title} <ExternalLink size={11} />
                  <div className="muted" style={{ fontSize: 11.5 }}>{n.source} · {timeAgo(n.published)}</div>
                </a>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
