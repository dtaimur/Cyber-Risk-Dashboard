import { useState } from 'react'
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Globe } from 'lucide-react'
import { useApi } from '../api'
import { SEVS, SEV_COLOR, TOOL_NAME, cap, fmtDate } from '../format'
import { useAssetDrawer } from './AssetDrawer'
import { Card, ChartTooltip, Legend, SevBadge, axisProps } from './ui'

const sevLegend = SEVS.map((s) => ({ label: cap(s), color: SEV_COLOR[s] }))

export function SeverityTrend({ data, title = 'Open vulnerabilities over time', subtitle = 'Weekly snapshot, by severity' }: { data: any[]; title?: string; subtitle?: string }) {
  return (
    <Card title={title} subtitle={subtitle}>
      <div style={{ height: 230 }}>
        <ResponsiveContainer>
          <AreaChart data={data} margin={{ top: 6, right: 8, left: -12, bottom: 0 }}>
            <CartesianGrid vertical={false} stroke="var(--grid)" />
            <XAxis dataKey="date" tickFormatter={(d) => fmtDate(d)} {...axisProps} minTickGap={24} />
            <YAxis {...axisProps} allowDecimals={false} />
            <Tooltip content={<ChartTooltip labelFormatter={(l: string) => `Week ending ${fmtDate(l)}`} />} />
            {[...SEVS].reverse().map((s) => (
              <Area key={s} type="monotone" dataKey={s} name={cap(s)} stackId="1" stroke="var(--surface)" strokeWidth={1}
                fill={SEV_COLOR[s]} fillOpacity={0.9} isAnimationActive={false} />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <Legend items={sevLegend} />
    </Card>
  )
}

export function NewVsRemediated({ data }: { data: any[] }) {
  return (
    <Card title="Remediation velocity" subtitle="New findings vs. findings remediated per week">
      <div style={{ height: 230 }}>
        <ResponsiveContainer>
          <BarChart data={data} margin={{ top: 6, right: 8, left: -12, bottom: 0 }} barGap={2}>
            <CartesianGrid vertical={false} stroke="var(--grid)" />
            <XAxis dataKey="date" tickFormatter={(d) => fmtDate(d)} {...axisProps} minTickGap={24} />
            <YAxis {...axisProps} allowDecimals={false} />
            <Tooltip cursor={{ fill: 'var(--surface-2)' }} content={<ChartTooltip labelFormatter={(l: string) => `Week ending ${fmtDate(l)}`} />} />
            <Bar dataKey="new" name="New" fill="var(--s2)" radius={[4, 4, 0, 0]} isAnimationActive={false} />
            <Bar dataKey="remediated" name="Remediated" fill="var(--s1)" radius={[4, 4, 0, 0]} isAnimationActive={false} />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <Legend items={[{ label: 'New', color: 'var(--s2)' }, { label: 'Remediated', color: 'var(--s1)' }]} />
    </Card>
  )
}

export function AgingChart({ data }: { data: any[] }) {
  return (
    <Card title="Open vulnerability age" subtitle="How long open findings have been exposed">
      <div style={{ height: 230 }}>
        <ResponsiveContainer>
          <BarChart data={data} margin={{ top: 6, right: 8, left: -12, bottom: 0 }}>
            <CartesianGrid vertical={false} stroke="var(--grid)" />
            <XAxis dataKey="bucket" {...axisProps} />
            <YAxis {...axisProps} allowDecimals={false} />
            <Tooltip cursor={{ fill: 'var(--surface-2)' }} content={<ChartTooltip />} />
            {SEVS.map((s, i) => (
              <Bar key={s} dataKey={s} name={cap(s)} stackId="a" fill={SEV_COLOR[s]} stroke="var(--surface)" strokeWidth={1}
                radius={i === SEVS.length - 1 ? [4, 4, 0, 0] : 0} isAnimationActive={false} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
      <Legend items={sevLegend} />
    </Card>
  )
}

export function HBarList({ data, labelKey, valueKey = 'count', color = 'var(--s1)', format }: {
  data: any[]; labelKey: string; valueKey?: string; color?: string; format?: (s: string) => string
}) {
  const max = Math.max(1, ...data.map((d) => d[valueKey]))
  return (
    <div>
      {data.map((d) => (
        <div key={d[labelKey]} style={{ display: 'grid', gridTemplateColumns: 'minmax(120px, 42%) 1fr 44px', gap: 10, alignItems: 'center', padding: '4px 0' }}>
          <div style={{ fontSize: 12.5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={d[labelKey]}>
            {format ? format(d[labelKey]) : d[labelKey]}
          </div>
          <div className="meter" style={{ height: 10 }}><span style={{ width: `${(100 * d[valueKey]) / max}%`, background: color }} /></div>
          <div className="num" style={{ fontSize: 12.5 }}>{d[valueKey]}</div>
        </div>
      ))}
    </div>
  )
}

export function TopAssets({ data, title = 'Riskiest assets' }: { data: any[]; title?: string }) {
  const open = useAssetDrawer()
  return (
    <Card title={title} subtitle="Open findings weighted by severity × asset criticality · click to drill down">
      <div className="table-wrap">
        <table>
          <thead><tr><th>Asset</th><th>Business unit</th><th className="num">Crit.</th>{SEVS.map((s) => <th key={s} className="num">{cap(s)}</th>)}</tr></thead>
          <tbody>
            {data.map((a) => (
              <tr key={a.id} className="clickable" onClick={() => open(a.id)}>
                <td><span style={{ fontWeight: 500 }}>{a.hostname}</span> {a.internet_facing ? <Globe size={12} color="var(--critical)" aria-label="Internet-facing" /> : null}
                  <div className="muted" style={{ fontSize: 11.5 }}>{a.os}</div></td>
                <td>{a.business_unit}</td>
                <td className="num">{a.criticality}</td>
                {SEVS.map((s) => <td key={s} className="num">{a[s] || <span className="muted">0</span>}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

export function FindingsTable({ source }: { source?: string }) {
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('open')
  const [q, setQ] = useState('')
  const [page, setPage] = useState(0)
  const open = useAssetDrawer()
  const params = new URLSearchParams({ status, limit: '25', offset: String(page * 25) })
  if (source) params.set('source', source)
  if (severity) params.set('severity', severity)
  if (q) params.set('q', q)
  const { data } = useApi<any>(`/vulnerabilities/findings?${params}`)
  const today = new Date().toISOString().slice(0, 10)

  return (
    <Card title="Findings" subtitle="Drill into individual vulnerabilities and affected assets">
      <div className="filters">
        <input className="input" placeholder="Search CVE, title, or host…" value={q} onChange={(e) => { setQ(e.target.value); setPage(0) }} style={{ width: 260 }} />
        <select className="select" value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(0) }} aria-label="Severity">
          <option value="">All severities</option>
          {SEVS.map((s) => <option key={s} value={s}>{cap(s)}</option>)}
        </select>
        <div className="seg">
          {['open', 'overdue', 'remediated', 'all'].map((s) => (
            <button key={s} className={status === s ? 'on' : ''} onClick={() => { setStatus(s); setPage(0) }}>{cap(s)}</button>
          ))}
        </div>
        <span className="muted" style={{ marginLeft: 'auto', fontSize: 12 }}>{data?.total ?? '…'} findings</span>
      </div>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Severity</th><th>Finding</th><th>Asset</th>{!source && <th>Tool</th>}<th className="num">CVSS</th><th>First seen</th><th>Due</th><th>Owner</th></tr></thead>
          <tbody>
            {data?.items.map((f: any) => {
              const overdue = f.status !== 'remediated' && f.due_date < today
              return (
                <tr key={f.id} className="clickable" onClick={() => open(f.asset_id)}>
                  <td><SevBadge sev={f.severity} /></td>
                  <td style={{ maxWidth: 360 }}>
                    <div>{f.title}</div>
                    <div className="chips" style={{ marginTop: 3 }}>
                      {f.cve && <span className="mono muted">{f.cve}</span>}
                      {f.in_kev ? <span className="badge badge-kev">Actively exploited</span> : null}
                    </div>
                  </td>
                  <td>{f.hostname} {f.internet_facing ? <Globe size={12} color="var(--critical)" aria-label="Internet-facing" /> : null}</td>
                  {!source && <td>{TOOL_NAME[f.source]}</td>}
                  <td className="num">{f.cvss ?? '—'}</td>
                  <td>{fmtDate(f.first_seen)}</td>
                  <td className={overdue ? 'delta-bad' : ''}>{f.status === 'remediated' ? <span className="delta-good">Fixed {fmtDate(f.remediated_at)}</span> : fmtDate(f.due_date)}</td>
                  <td className="text-2">{f.owner_team}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
        {data && data.items.length === 0 && <div className="empty">No findings match these filters</div>}
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
