import { Link } from 'react-router-dom'
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { ArrowRight } from 'lucide-react'
import { useApi } from '../api'
import { useAuth } from '../auth'
import { SEVS, SEV_COLOR, TOOL_NAME, cap, fmtDate, riskColor, riskTextColor } from '../format'
import { Card, ChartTooltip, Delta, ErrorBox, Legend, Loading, Meter, PageHeader, axisProps } from '../components/ui'
import { Kpi, MetricLink } from '../components/Metric'

const MONTHS = ['11 mo', '10 mo', '9 mo', '8 mo', '7 mo', '6 mo', '5 mo', '4 mo', '3 mo', '2 mo', '1 mo', 'Now']

export default function ExecutiveSummary() {
  const { data: d, error, reload } = useApi<any>('/summary')
  const { can } = useAuth()
  const ops = can('view_details')
  if (error) return <ErrorBox error={error} onRetry={reload} />
  if (!d) return <Loading />
  const { risk, kpis, third_party: tp } = d

  return (
    <>
      <PageHeader title="Executive Summary"
        subtitle="Risk posture, priorities, and owners"
        actions={<Link to="/report" className="btn btn-primary">Generate executive report <ArrowRight size={14} /></Link>} />

      <div className="grid g-3">
        <Card className="span-2" title="Enterprise risk score" subtitle="Composite of six weighted components · higher means more risk">
          <div className="hero">
            <MetricLink metric="risk_score" style={{ padding: 8, margin: -8 }}>
              <div className="hero-score" style={{ color: riskTextColor(risk.score) }}>{risk.score}<small>/100</small></div>
              <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginTop: 10 }}>
                <span className="rating-pill"><span style={{ width: 8, height: 8, borderRadius: 2, background: riskColor(risk.score) }} />{risk.rating}</span>
                <span style={{ fontSize: 13 }}><Delta value={risk.change_30d} /> <span className="muted">vs 30 days ago</span></span>
              </div>
              <div style={{ height: 90, marginTop: 14 }}>
                <ResponsiveContainer>
                  <AreaChart data={risk.history} margin={{ top: 4, right: 4, bottom: 0, left: 4 }}>
                    <YAxis hide domain={['dataMin - 5', 'dataMax + 5']} />
                    <XAxis dataKey="date" hide />
                    <Tooltip content={<ChartTooltip labelFormatter={(l: string) => `Week of ${fmtDate(l)}`} />} />
                    <Area type="monotone" dataKey="score" name="Risk score" stroke="var(--s1)" strokeWidth={2} fill="none" isAnimationActive={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
              <div className="muted" style={{ fontSize: 11 }}>13-week trend, recomputed from historical records · click for details</div>
            </MetricLink>
            <div>
              {risk.components.map((c: any) => (
                <MetricLink metric={`risk_${c.key}`} className="comp-row" key={c.key} style={{ padding: '6px 8px', margin: '0 -8px' }}>
                  <div className="lbl">{c.label}<small>{Math.round(c.weight * 100)}% weight</small></div>
                  <div>
                    <Meter value={c.risk} color={riskColor(c.risk)} />
                    <div className="muted" style={{ fontSize: 11, marginTop: 4 }}>{c.detail}</div>
                  </div>
                  <div className="val">{Math.round(c.risk)}</div>
                </MetricLink>
              ))}
            </div>
          </div>
        </Card>

        <Card title="What needs action" subtitle="Prioritized next steps with owners"
          action={ops ? <Link to="/threats/active" className="btn btn-sm">All threats</Link> : undefined}>
          <div className="list">
            {d.actions.map((a: any, i: number) => (
              <Link to={ops ? a.link : '#'} onClick={ops ? undefined : (e) => e.preventDefault()} key={i} className="list-item" style={{ color: 'inherit', textDecoration: 'none', cursor: ops ? 'pointer' : 'default' }}>
                <span className="sev-bar" style={{ background: SEV_COLOR[a.priority] }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600 }}>{a.title}</div>
                  <div className="muted" style={{ fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.detail}</div>
                </div>
                <div style={{ textAlign: 'right', flexShrink: 0 }}>
                  <div className="badge">{a.area}</div>
                  <div className="muted" style={{ fontSize: 11.5, marginTop: 4 }}>{a.owner}</div>
                </div>
              </Link>
            ))}
          </div>
        </Card>
      </div>

      <div className="grid g-6 mt">
        <Kpi label="Open critical vulnerabilities" metric="open_critical" value={kpis.open_critical} foot={`${kpis.open_high} high severity`} tone={kpis.open_critical ? 'bad' : 'good'} />
        <Kpi label="Actively exploited CVEs (KEV)" metric="kev_open" value={kpis.kev_open} foot={`${kpis.active_threats} active threats tracked`} tone={kpis.kev_open ? 'bad' : 'good'} />
        <Kpi label="Critical/high within SLA" metric="sla_compliance" value={kpis.sla_compliance} unit="%" foot={`${kpis.crit_high_overdue} past due`} />
        <Kpi label="Security alerts (30d)" metric="alerts" params={{ days: 30 }} value={kpis.alerts_30d.toLocaleString()} foot={`${kpis.open_crit_high_alerts} critical/high open`} />
        <Kpi label="Critical alert MTTR" metric="mttr_critical_alerts" params={{ days: 30 }} value={kpis.mttr_critical_hours} unit="h" foot={`${kpis.incidents_30d} incidents · MTTD ${kpis.mttd_minutes}m`} />
        <Kpi label="EDR coverage" metric="edr_coverage" value={kpis.edr_coverage} unit="%" foot={`Scan coverage ${kpis.scan_coverage}%`} />
      </div>

      <div className="grid g-2 mt">
        <Card title="Alerts by security platform" subtitle="Last 30 days, by severity"
          action={ops ? <Link to="/alerts" className="btn btn-sm">Alert stream</Link> : undefined}>
          <div style={{ height: 300 }}>
            <ResponsiveContainer>
              <BarChart data={d.alerts_by_platform.map((p: any) => ({ ...p, name: TOOL_NAME[p.source] }))} layout="vertical" margin={{ left: 10, right: 16 }} barCategoryGap={10}>
                <CartesianGrid horizontal={false} stroke="var(--grid)" />
                <XAxis type="number" {...axisProps} />
                <YAxis type="category" dataKey="name" {...axisProps} width={84} />
                <Tooltip cursor={{ fill: 'var(--surface-2)' }} content={<ChartTooltip />} />
                {SEVS.map((s, i) => (
                  <Bar key={s} dataKey={s} name={cap(s)} stackId="a" fill={SEV_COLOR[s]} stroke="var(--surface)" strokeWidth={1}
                    radius={i === SEVS.length - 1 ? [0, 4, 4, 0] : 0} isAnimationActive={false} />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
          <Legend items={SEVS.map((s) => ({ label: cap(s), color: SEV_COLOR[s] }))} />
          {Object.values(d.modes).includes('live') && (
            <div className="muted" style={{ fontSize: 12, marginTop: 12, display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
              Live connections:
              {Object.entries(d.modes).filter(([, m]) => m === 'live').map(([k]) => <span key={k}><span className="live-dot" /> {TOOL_NAME[k]}</span>)}
            </div>
          )}
        </Card>

        <Card title="Third-party risk" subtitle="External security ratings from Bitsight and SecurityScorecard">
          <div className="grid g-4" style={{ gap: 10, marginBottom: 12 }}>
            <MiniStat metric="avg_bitsight" label="Avg Bitsight" value={tp.avg_bitsight} foot="250–900" />
            <MiniStat metric="avg_ssc" label="Avg SecurityScorecard" value={tp.avg_ssc} foot="0–100" />
            <MiniStat metric="vendors_attention" label="Need attention" value={tp.needs_attention} foot={`of ${tp.vendor_count} vendors`} bad={tp.needs_attention > 0} />
            <MiniStat metric="overdue_assessments" label="Overdue assessments" value={tp.overdue_assessments} foot={`${tp.due_soon} due in 60 days`} bad={tp.overdue_assessments > 0} />
          </div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Vendor</th><th>Tier</th><th className="num">Bitsight</th><th className="num">SSC</th><th>Flags</th></tr></thead>
              <tbody>
                {tp.vendors.slice(0, 5).map((v: any) => (
                  <tr key={v.id}>
                    <td><div style={{ fontWeight: 500 }}>{v.name}</div><div className="muted" style={{ fontSize: 11.5 }}>{v.data_access}</div></td>
                    <td>T{v.tier}</td>
                    <td className="num">{v.bitsight_rating}<div style={{ fontSize: 11 }}><Delta value={v.bitsight_change_90d} better="higher" /></div></td>
                    <td className="num">{v.ssc_score} <span className="muted">({v.ssc_grade})</span></td>
                    <td style={{ fontSize: 12 }}>{v.reasons.length ? v.reasons.join(' · ') : <span className="muted">—</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ height: 70, marginTop: 8 }}>
            <ResponsiveContainer>
              <AreaChart data={tp.trend.map((t: any, i: number) => ({ ...t, m: MONTHS[i + 12 - tp.trend.length] }))} margin={{ top: 4, right: 4, left: 4, bottom: 0 }}>
                <XAxis dataKey="m" hide />
                <YAxis hide domain={['dataMin - 10', 'dataMax + 10']} />
                <Tooltip content={<ChartTooltip />} />
                <Area dataKey="bitsight" name="Avg Bitsight" stroke="var(--s1)" strokeWidth={2} fill="none" isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="muted" style={{ fontSize: 11 }}>Portfolio average Bitsight rating, last 12 months</div>
        </Card>
      </div>

      <div className="grid g-2 mt">
        <Card title="Open vulnerabilities by tool" action={ops ? <Link to="/vulnerabilities" className="btn btn-sm">Details</Link> : undefined}>
          <table>
            <thead><tr><th>Tool</th>{SEVS.map((s) => <th key={s} className="num">{cap(s)}</th>)}<th className="num">Past SLA</th></tr></thead>
            <tbody>
              {d.vulns_by_source.map((r: any) => (
                <tr key={r.source}>
                  <td>{ops ? <Link to={`/vulnerabilities/${r.source}`}>{TOOL_NAME[r.source]}</Link> : TOOL_NAME[r.source]}</td>
                  {SEVS.map((s) => <td key={s} className="num">{r[s]}</td>)}
                  <td className="num" style={{ color: r.overdue ? 'var(--bad-text)' : undefined }}>{r.overdue}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
        <Card title="Compliance posture" action={<Link to="/compliance" className="btn btn-sm">Roadmap</Link>}>
          {d.frameworks.map((f: any) => (
            <MetricLink metric="compliance" params={{ framework: f.framework }} className="comp-row" key={f.framework} style={{ gridTemplateColumns: '150px 1fr 52px', padding: '6px 8px', margin: '0 -8px' }}>
              <div className="lbl">{f.framework}</div>
              <Meter value={f.pct} color={f.pct >= 85 ? 'var(--good)' : f.pct >= 65 ? 'var(--medium)' : 'var(--critical)'} />
              <div className="val">{f.pct}%</div>
            </MetricLink>
          ))}
          <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>Implemented = 1, partial = 0.5. Some controls are evaluated automatically from live tool data.</div>
        </Card>
      </div>
    </>
  )
}

function MiniStat({ metric, label, value, foot, bad }: { metric: string; label: string; value: any; foot: string; bad?: boolean }) {
  return (
    <MetricLink metric={metric} className="ministat" style={{ background: 'var(--head)', border: '1px solid var(--border)', borderRadius: 3, padding: '7px 10px' }}>
      <div className="kpi-label" style={{ fontSize: 11.5 }}>{label}</div>
      <div style={{ fontSize: 20, fontWeight: 650, color: bad ? 'var(--bad-text)' : undefined }}>{value}</div>
      <div className="muted" style={{ fontSize: 11 }}>{foot}</div>
    </MetricLink>
  )
}
