import { useState } from 'react'
import { Area, AreaChart, CartesianGrid, Line, LineChart, ReferenceArea, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { useApi } from '../api'
import { SEVS, TOOL_COLOR, TOOL_NAME, cap, fmtCategory, fmtDate, timeAgo } from '../format'
import { useAssetDrawer } from '../components/AssetDrawer'
import { HBarList } from '../components/charts'
import { Card, ChartTooltip, ErrorBox, Legend, Loading, PageHeader, SevBadge, axisProps } from '../components/ui'
import { Kpi } from '../components/Metric'

const SOURCES = ['crowdstrike', 'expel', 'wiz', 'qualys']
const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

export default function Alerts() {
  const [days, setDays] = useState(90)
  const { data: t, error, reload } = useApi<any>(`/alerts/trends?days=${days}`)

  return (
    <>
      <PageHeader title="Alerts & Forensic Trends"
        subtitle="Detections from CrowdStrike, Expel, Wiz, and Qualys"
        actions={<div className="seg">{[30, 90, 180].map((n) => <button key={n} className={days === n ? 'on' : ''} onClick={() => setDays(n)}>{n} days</button>)}</div>} />
      {error && <ErrorBox error={error} onRetry={reload} />}
      {!t ? (!error && <Loading />) : (
        <>
          <div className="grid g-6">
            <Kpi label={`Alerts (${days}d)`} metric="alerts" params={{ days }} value={t.summary.total.toLocaleString()} foot={`~${t.baseline_daily} per day typical`} />
            <Kpi label="Open now" metric="open_alerts" value={t.summary.open_total} foot={`${t.summary.open_crit_high} critical/high`} />
            <Kpi label="Confirmed incidents" metric="incidents" params={{ days }} value={t.summary.incidents} tone={t.summary.incidents ? 'bad' : 'good'} />
            <Kpi label="Median time to detect" metric="mttd" params={{ days }} value={t.summary.mttd_minutes} unit="min" />
            <Kpi label="Critical MTTR" metric="mttr_critical_alerts" params={{ days }} value={t.summary.mttr_hours.critical} unit="h" foot={`High ${t.summary.mttr_hours.high ?? '—'}h`} />
            <Kpi label="False positive rate" metric="false_positive_rate" params={{ days }} value={t.summary.false_positive_rate} unit="%" />
          </div>

          <Card className="mt" title="Alert volume by source"
            subtitle={t.anomalies.length ? `${t.anomalies.length} anomalous day${t.anomalies.length > 1 ? 's' : ''} (≥1.8× the median) flagged` : 'Daily detections'}>
            <div style={{ height: 260 }}>
              <ResponsiveContainer>
                <AreaChart data={t.daily} margin={{ top: 10, right: 10, left: -12, bottom: 0 }}>
                  <CartesianGrid vertical={false} stroke="var(--grid)" />
                  <XAxis dataKey="date" tickFormatter={(d) => fmtDate(d)} {...axisProps} minTickGap={30} />
                  <YAxis {...axisProps} allowDecimals={false} />
                  <Tooltip content={<ChartTooltip labelFormatter={(l: string) => fmtDate(l, { weekday: 'short', month: 'short', day: 'numeric' })} />} />
                  {t.anomalies.length > 0 && (
                    <ReferenceArea x1={t.anomalies[0].date} x2={t.anomalies[t.anomalies.length - 1].date}
                      fill="var(--critical)" fillOpacity={0.12} stroke="var(--critical)" strokeOpacity={0.5} strokeDasharray="3 3"
                      label={{ value: 'Anomalous activity', position: 'insideTop', fill: 'var(--text-2)', fontSize: 11 }} />
                  )}
                  {SOURCES.map((s) => (
                    <Area key={s} type="monotone" dataKey={s} name={TOOL_NAME[s]} stackId="1" stroke="var(--surface)" strokeWidth={1} fill={TOOL_COLOR[s]} fillOpacity={0.9} isAnimationActive={false} />
                  ))}
                </AreaChart>
              </ResponsiveContainer>
            </div>
            <Legend items={[...SOURCES.map((s) => ({ label: TOOL_NAME[s], color: TOOL_COLOR[s] })), { label: 'Anomalous period', color: 'rgba(208,59,59,.35)' }]} />
          </Card>

          <div className="grid g-2 mt">
            <Card title="Time to detect" subtitle="Weekly median minutes from event to alert">
              <TrendLine data={t.weekly} dataKey="mttd_minutes" name="MTTD" unit=" min" color="var(--s1)" />
            </Card>
            <Card title="Time to respond" subtitle="Weekly median hours to resolve critical/high alerts">
              <TrendLine data={t.weekly} dataKey="mttr_hours" name="MTTR" unit="h" color="var(--s2)" />
            </Card>
          </div>

          <div className="grid g-3 mt">
            <Card title="MITRE ATT&CK tactics" subtitle="Where in the attack chain activity is detected">
              <HBarList data={t.tactics} labelKey="tactic" />
            </Card>
            <Card title="Top techniques"><HBarList data={t.techniques} labelKey="technique" color="var(--s7)" /></Card>
            <Card title="Activity by hour (UTC)" subtitle="When detections occur — off-hours activity can indicate automation or intrusions">
              <Heatmap grid={t.heatmap} />
            </Card>
          </div>

          <div className="grid g-3 mt">
            <Card title="Most-targeted hosts"><TopHosts data={t.top_hosts} /></Card>
            <Card title="Most-targeted users" subtitle="Identity, phishing, and BEC alerts"><HBarList data={t.top_users} labelKey="user" color="var(--s2)" /></Card>
            <Card title="Alert categories"><HBarList data={t.categories} labelKey="category" format={fmtCategory} color="var(--s3)" /></Card>
          </div>
        </>
      )}
      <div className="mt"><AlertStream /></div>
    </>
  )
}

function TrendLine({ data, dataKey, name, unit, color }: any) {
  return (
    <div style={{ height: 200 }}>
      <ResponsiveContainer>
        <LineChart data={data} margin={{ top: 6, right: 10, left: -12, bottom: 0 }}>
          <CartesianGrid vertical={false} stroke="var(--grid)" />
          <XAxis dataKey="date" tickFormatter={(d) => fmtDate(d)} {...axisProps} minTickGap={24} />
          <YAxis {...axisProps} />
          <Tooltip content={<ChartTooltip unit={unit} labelFormatter={(l: string) => `Week ending ${fmtDate(l)}`} />} />
          <Line dataKey={dataKey} name={name} stroke={color} strokeWidth={2} dot={{ r: 3, fill: color }} connectNulls isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}

function Heatmap({ grid }: { grid: number[][] }) {
  const max = Math.max(1, ...grid.flat())
  return (
    <div>
      <div className="heat">
        {grid.map((row, d) => [
          <div key={`l${d}`} style={{ alignSelf: 'center' }}>{DAYS[d]}</div>,
          ...row.map((v, h) => (
            <div key={`${d}-${h}`} className="cell" title={`${DAYS[d]} ${h}:00 — ${v} alerts`}
              style={{ background: v ? `color-mix(in srgb, var(--s1) ${Math.round(15 + (85 * v) / max)}%, var(--surface-2))` : 'var(--surface-2)' }} />
          )),
        ])}
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10.5, color: 'var(--muted)', marginTop: 4, paddingLeft: 38 }}>
        <span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>23:00</span>
      </div>
    </div>
  )
}

function TopHosts({ data }: { data: any[] }) {
  const open = useAssetDrawer()
  return (
    <table><tbody>
      {data.map((h) => <tr key={h.asset_id} className="clickable" onClick={() => open(h.asset_id)}><td>{h.hostname}</td><td className="num">{h.count}</td></tr>)}
    </tbody></table>
  )
}

function AlertStream() {
  const [source, setSource] = useState('')
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [q, setQ] = useState('')
  const [page, setPage] = useState(0)
  const open = useAssetDrawer()
  const p = new URLSearchParams({ limit: '25', offset: String(page * 25) })
  if (source) p.set('source', source)
  if (severity) p.set('severity', severity)
  if (status) p.set('status', status)
  if (q) p.set('q', q)
  const { data } = useApi<any>(`/alerts?${p}`)
  const reset = (fn: (v: string) => void) => (e: any) => { fn(e.target.value); setPage(0) }

  return (
    <Card title="Consolidated alert stream" subtitle="Normalized detections from every connected tool">
      <div className="filters">
        <input className="input" placeholder="Search title, host, user, technique…" value={q} onChange={reset(setQ)} style={{ width: 260 }} />
        <select className="select" value={source} onChange={reset(setSource)} aria-label="Source">
          <option value="">All sources</option>{SOURCES.map((s) => <option key={s} value={s}>{TOOL_NAME[s]}</option>)}
        </select>
        <select className="select" value={severity} onChange={reset(setSeverity)} aria-label="Severity">
          <option value="">All severities</option>{SEVS.map((s) => <option key={s} value={s}>{cap(s)}</option>)}
        </select>
        <select className="select" value={status} onChange={reset(setStatus)} aria-label="Status">
          <option value="">All statuses</option><option value="open">Open</option><option value="new">New</option>
          <option value="investigating">Investigating</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option>
        </select>
        <span className="muted" style={{ marginLeft: 'auto', fontSize: 12 }}>{data?.total?.toLocaleString() ?? '…'} alerts</span>
      </div>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Severity</th><th>Alert</th><th>Source</th><th>Tactic / technique</th><th>Host / user</th><th>Status</th><th>Detected</th></tr></thead>
          <tbody>
            {data?.items.map((a: any) => (
              <tr key={a.id} className={a.asset_id ? 'clickable' : ''} onClick={() => a.asset_id && open(a.asset_id)}>
                <td><SevBadge sev={a.severity} /></td>
                <td>{a.title} {a.is_incident ? <span className="badge badge-kev">Incident</span> : null}</td>
                <td><span className="badge"><span className="sw" style={{ background: TOOL_COLOR[a.source] }} />{TOOL_NAME[a.source]}</span></td>
                <td style={{ fontSize: 12.5 }}>{a.tactic}<div className="muted">{a.technique}</div></td>
                <td style={{ fontSize: 12.5 }}>{a.hostname}<div className="muted">{a.user_name}</div></td>
                <td>{cap((a.status || '').replace('_', ' '))}</td>
                <td className="muted" title={a.detected_at}>{timeAgo(a.detected_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {data && data.total > 25 && (
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 10, alignItems: 'center' }}>
          <span className="muted" style={{ fontSize: 12 }}>Page {page + 1} of {Math.ceil(data.total / 25)}</span>
          <button className="btn btn-sm" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
          <button className="btn btn-sm" disabled={(page + 1) * 25 >= data.total} onClick={() => setPage(page + 1)}>Next</button>
        </div>
      )}
    </Card>
  )
}
