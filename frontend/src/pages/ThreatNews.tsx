import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ExternalLink, Target } from 'lucide-react'
import { useApi } from '../api'
import { fmtDate, timeAgo } from '../format'
import { Card, ErrorBox, Loading, PageHeader } from '../components/ui'

export default function ThreatNews() {
  const [source, setSource] = useState('')
  const [relevant, setRelevant] = useState(false)
  const [q, setQ] = useState('')
  const params = new URLSearchParams({ limit: '80' })
  if (source) params.set('source', source)
  if (relevant) params.set('relevant', 'true')
  if (q) params.set('q', q)
  const news = useApi<any>(`/threats/news?${params}`)
  const kev = useApi<any>('/threats/kev?limit=25')

  return (
    <>
      <PageHeader title="Threat News"
        subtitle="Security news and the CISA Known Exploited Vulnerabilities catalog, matched against our environment" />
      <div className="grid g-3">
        <div className="span-2">
          <Card title="Latest security news" subtitle="Highlighted items mention products we run or CVEs found in our scans">
            <div className="filters">
              <input className="input" placeholder="Search headlines…" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 220 }} />
              <select className="select" value={source} onChange={(e) => setSource(e.target.value)} aria-label="Source">
                <option value="">All sources</option>
                {news.data?.sources.map((s: string) => <option key={s}>{s}</option>)}
              </select>
              <div className="seg">
                <button className={!relevant ? 'on' : ''} onClick={() => setRelevant(false)}>All</button>
                <button className={relevant ? 'on' : ''} onClick={() => setRelevant(true)}>Relevant to us</button>
              </div>
            </div>
            {news.error && <ErrorBox error={news.error} />}
            {!news.data && !news.error && <Loading />}
            {news.data?.items.length === 0 && <div className="empty">No articles yet. Use "Refresh threat intel" in the top bar.</div>}
            <div className="list">
              {news.data?.items.map((a: any) => (
                <article key={a.id} className="list-item">
                  <span className="sev-bar" style={{ background: a.relevant ? 'var(--accent)' : 'transparent' }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'baseline', flexWrap: 'wrap' }}>
                      <a href={a.link} target="_blank" rel="noopener noreferrer" style={{ fontWeight: 600, color: 'var(--text)' }}>
                        {a.title} <ExternalLink size={12} className="muted" />
                      </a>
                    </div>
                    <div className="muted" style={{ fontSize: 12, margin: '2px 0 6px' }}>{a.source} · {timeAgo(a.published)}</div>
                    {a.summary && <div className="text-2" style={{ fontSize: 13 }}>{a.summary}</div>}
                    {(a.cves.length > 0 || a.products.length > 0) && (
                      <div className="chips" style={{ marginTop: 8 }}>
                        {a.cves.map((c: any) => (
                          <span key={c.id} className={`badge ${c.in_environment ? 'badge-kev' : ''}`} title={c.in_environment ? 'Found in our vulnerability scans' : 'Not found in our environment'}>
                            {c.in_environment && <Target size={11} />}<span className="mono">{c.id}</span>{c.in_kev && ' · KEV'}
                          </span>
                        ))}
                        {a.products.map((p: string) => <span key={p} className="badge badge-accent">We run: {p}</span>)}
                      </div>
                    )}
                  </div>
                </article>
              ))}
            </div>
          </Card>
        </div>

        <Card title="CISA KEV — latest additions"
          subtitle={kev.data ? `${kev.data.total.toLocaleString()} exploited CVEs in catalog · ${kev.data.added_30d} added in last 30 days` : ''}
          action={<Link to="/threats/active" className="btn btn-sm">Correlation</Link>}>
          {!kev.data && <Loading />}
          <div className="list">
            {kev.data?.items.map((k: any) => (
              <div key={k.cve} className="list-item">
                <span className="sev-bar" style={{ background: k.in_environment ? 'var(--critical)' : 'var(--axis)' }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                    <span className="mono" style={{ fontWeight: 600 }}>{k.cve}</span>
                    <span className="muted" style={{ fontSize: 12 }}>{fmtDate(k.date_added)}</span>
                  </div>
                  <div style={{ fontSize: 12.5 }}>{k.vendor} {k.product}</div>
                  <div className="muted" style={{ fontSize: 12 }}>{k.name}</div>
                  <div className="chips" style={{ marginTop: 4 }}>
                    {k.in_environment && <span className="badge badge-kev"><Target size={11} /> In our environment</span>}
                    {k.ransomware === 'Known' && <span className="badge">Ransomware use</span>}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </>
  )
}
