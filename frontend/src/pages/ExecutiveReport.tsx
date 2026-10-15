import { useState } from 'react'
import { CheckCircle2, Download, FileText, Printer } from 'lucide-react'
import { post } from '../api'
import { fmtDate, riskColor, riskTextColor } from '../format'
import { Card, Meter, PageHeader, Spinner } from '../components/ui'

const AUDIENCES = [
  { key: 'board', label: 'Board of Directors', desc: 'Top 3 takeaways, business language' },
  { key: 'executive', label: 'Executive Leadership', desc: 'Top 4 takeaways with decisions' },
  { key: 'security', label: 'Security & IT Leadership', desc: 'Up to 6 takeaways with technical detail' },
]

export default function ExecutiveReport() {
  const [period, setPeriod] = useState(30)
  const [audience, setAudience] = useState('executive')
  const [report, setReport] = useState<any>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function generate() {
    setBusy(true); setError(null)
    try { setReport(await post('/report', { period_days: period, audience })) }
    catch (e: any) { setError(e.message) }
    finally { setBusy(false) }
  }

  async function downloadMarkdown() {
    const md = await post<string>('/report/markdown', { period_days: period, audience })
    const url = URL.createObjectURL(new Blob([md], { type: 'text/markdown' }))
    const a = Object.assign(document.createElement('a'), { href: url, download: `cyber-report-${new Date().toISOString().slice(0, 10)}.md` })
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <>
      <div className="no-print">
        <PageHeader title="Executive Report"
          subtitle="Leadership briefing generated from current dashboard data" />
        <Card>
          <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap', alignItems: 'flex-end' }}>
            <label className="field">Reporting period
              <div className="seg">{[30, 90].map((n) => <button key={n} className={period === n ? 'on' : ''} onClick={() => setPeriod(n)}>Last {n} days</button>)}</div>
            </label>
            <label className="field">Audience
              <div className="seg">{AUDIENCES.map((a) => <button key={a.key} className={audience === a.key ? 'on' : ''} onClick={() => setAudience(a.key)} title={a.desc}>{a.label}</button>)}</div>
            </label>
            <button className="btn btn-primary" onClick={generate} disabled={busy}>{busy ? <Spinner /> : <FileText size={15} />} Generate report</button>
            {report && <>
              <button className="btn" onClick={() => window.print()}><Printer size={15} /> Print / PDF</button>
              <button className="btn" onClick={downloadMarkdown}><Download size={15} /> Markdown</button>
            </>}
          </div>
          <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>{AUDIENCES.find((a) => a.key === audience)?.desc}</div>
          {error && <div className="delta-bad" style={{ marginTop: 8 }}>{error}</div>}
        </Card>
      </div>
      {report && <Report r={report} />}
    </>
  )
}

function Report({ r }: { r: any }) {
  return (
    <article className="report mt">
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
        <div>
          <div className="muted" style={{ fontSize: 12, textTransform: 'uppercase', letterSpacing: '.08em' }}>Cybersecurity briefing · {r.audience.label}</div>
          <h1 style={{ fontSize: 26, marginTop: 4 }}>Cyber Risk Report</h1>
          <div className="text-2">{fmtDate(r.period.start, { month: 'long', day: 'numeric' })} – {fmtDate(r.period.end, { month: 'long', day: 'numeric', year: 'numeric' })}</div>
        </div>
        <div style={{ textAlign: 'right' }}>
          <div className="muted" style={{ fontSize: 12 }}>Enterprise risk score</div>
          <div style={{ fontSize: 40, fontWeight: 700, color: riskTextColor(r.risk.score), lineHeight: 1.1 }}>{r.risk.score}</div>
          <div style={{ fontSize: 13 }}>{r.risk.rating} · <span className={r.risk.change <= 0 ? 'delta-good' : 'delta-bad'}>{r.risk.change > 0 ? '+' : ''}{r.risk.change}</span> vs. {r.risk.previous}</div>
        </div>
      </div>

      <h2>Bottom line</h2>
      <p className="bluf">{r.bluf}</p>

      {r.decisions.length > 0 && (
        <>
          <h2>Decisions requested from leadership</h2>
          <table>
            <thead><tr><th>#</th><th>Decision</th><th>Owner</th><th>Timeframe</th></tr></thead>
            <tbody>{r.decisions.map((d: any, i: number) => <tr key={i}><td>{i + 1}</td><td style={{ fontWeight: 500 }}>{d.decision}</td><td className="text-2">{d.owner}</td><td className="text-2">{d.timeframe}</td></tr>)}</tbody>
          </table>
        </>
      )}

      <h2>Top takeaways</h2>
      {r.insights.map((i: any, n: number) => (
        <div className="insight" key={i.key}>
          <div className="muted" style={{ fontSize: 11.5, textTransform: 'uppercase', letterSpacing: '.06em' }}>{n + 1} · {i.area}</div>
          <h3>{i.title}</h3>
          <ul>{i.evidence.map((e: string) => <li key={e}>{e}</li>)}</ul>
          <div className="why"><span className="k">Why it matters</span><span>{i.why}</span></div>
          <div className="rec"><span className="k">Recommendation</span><span>{i.recommendation}<div className="muted" style={{ fontSize: 12, marginTop: 2 }}>Owner: {i.owner} · {i.timeframe}</div></span></div>
          {i.decision && <div className="dec"><span className="k">Decision needed</span><span style={{ fontWeight: 500 }}>{i.decision}</span></div>}
        </div>
      ))}

      {r.wins.length > 0 && (
        <>
          <h2>What's working</h2>
          {r.wins.map((w: any) => (
            <div key={w.key} style={{ display: 'flex', gap: 10, marginBottom: 10 }}>
              <CheckCircle2 size={18} color="var(--good)" style={{ flexShrink: 0, marginTop: 1 }} />
              <div><b>{w.title}</b><div className="text-2" style={{ fontSize: 13 }}>{w.evidence.join(' · ')}</div></div>
            </div>
          ))}
        </>
      )}

      <h2>Scorecard</h2>
      <table>
        <thead><tr><th>Metric</th><th className="num">Now</th><th className="num">Start of period</th><th className="num">Change</th></tr></thead>
        <tbody>
          {r.scorecard.map((s: any) => (
            <tr key={s.label}>
              <td>{s.label}</td>
              <td className="num" style={{ fontWeight: 600 }}>{s.value ?? '—'}{s.unit}</td>
              <td className="num muted">{s.previous === null ? '—' : `${s.previous}${s.unit}`}</td>
              <td className={`num ${s.improved === true ? 'delta-good' : s.improved === false ? 'delta-bad' : 'muted'}`}>{s.change ? `${s.change > 0 ? '+' : ''}${s.change}${s.unit}` : '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>Risk breakdown</h2>
      {r.risk.components.map((c: any) => (
        <div className="comp-row" key={c.key}>
          <div className="lbl">{c.label}<small>{Math.round(c.weight * 100)}% weight</small></div>
          <Meter value={c.risk} color={riskColor(c.risk)} />
          <div className="val">{Math.round(c.risk)}</div>
        </div>
      ))}

      {r.goals.length > 0 && (
        <>
          <h2>Security goals</h2>
          {r.goals.map((g: any) => (
            <div className="comp-row" key={g.id} style={{ gridTemplateColumns: '1fr 160px 120px' }}>
              <div className="lbl">{g.title}<small>Current {g.current ?? '—'} {g.unit} · target {g.target}</small></div>
              <Meter value={g.progress} color={g.met ? 'var(--good)' : 'var(--s1)'} />
              <div className="val" style={{ fontSize: 12 }}>{g.met ? 'Met' : `${g.progress}% to target`}</div>
            </div>
          ))}
        </>
      )}

      {r.outlook.length > 0 && (
        <>
          <h2>Next 90 days</h2>
          <table><tbody>
            {r.outlook.map((o: any) => <tr key={o.title}><td className="muted" style={{ width: 110 }}>{fmtDate(o.start_date)}</td><td>{o.title}</td><td className="text-2">{o.owner}</td></tr>)}
          </tbody></table>
        </>
      )}
      <div className="muted" style={{ fontSize: 11.5, marginTop: 28 }}>Generated {new Date(r.generated_at).toLocaleString()} by the Cyber Risk Dashboard from live threat intelligence and connected security tools.</div>
    </article>
  )
}
