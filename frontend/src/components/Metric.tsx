import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, Cell, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { ArrowDown, ArrowUp, BarChart3, Bot, PieChart as PieIcon, Calculator, Database, Globe, Hash, Info, LineChart as LineIcon, Search, Target, X } from 'lucide-react'
import { api } from '../api'
import { SEV_COLOR, TOOL_COLOR, cap, fmtDate, timeAgo } from '../format'
import { useAssetDrawer } from './AssetDrawer'
import { ChartTooltip, SevBadge, Spinner, axisProps } from './ui'
import { PRIORITY_COLOR, PriorityBadge, STATUS_COLOR, useTickets } from './Tickets'
import { useAuth } from '../auth'

/* ------------------------------------------------------------------ data */
export type MetricRef = { key: string; params?: Record<string, string | number | undefined> }
type View = 'number' | 'trend' | 'bars' | 'pie'

const detailCache = new Map<string, Promise<any>>()
let catalogPromise: Promise<Record<string, any>> | null = null

function refId(ref: MetricRef) {
  const p = new URLSearchParams()
  Object.entries(ref.params || {}).forEach(([k, v]) => v !== undefined && v !== '' && v !== null && p.set(k, String(v)))
  const qs = p.toString()
  return `${ref.key}${qs ? `?${qs}` : ''}`
}

function loadDetail(ref: MetricRef) {
  const id = refId(ref)
  if (!detailCache.has(id)) {
    const pr = api(`/metrics/${id}`)
    pr.catch(() => detailCache.delete(id))
    detailCache.set(id, pr)
  }
  return detailCache.get(id)!
}

// Data changes when feeds refresh or integrations sync — drop cached details.
if (typeof window !== 'undefined') window.addEventListener('dashboard:refresh', () => detailCache.clear())

function useCatalog() {
  const [cat, setCat] = useState<Record<string, any> | null>(null)
  useEffect(() => {
    catalogPromise ??= api('/metrics')
    catalogPromise.then(setCat).catch(() => {})
  }, [])
  return cat
}

function useDetail(ref: MetricRef | null) {
  const [data, setData] = useState<any>(null)
  const [error, setError] = useState<string | null>(null)
  const id = ref ? refId(ref) : null
  useEffect(() => {
    if (!ref) return
    let live = true
    setData(null); setError(null)
    loadDetail(ref).then((d) => live && setData(d)).catch((e) => live && setError(e.message))
    return () => { live = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id])
  return { data, error }
}

/* ------------------------------------------------------------------ drawer context */
const DrawerCtx = createContext<(ref: MetricRef) => void>(() => {})
export const useMetricDrawer = () => useContext(DrawerCtx)

export function MetricDrawerProvider({ children }: { children: ReactNode }) {
  const [ref, setRef] = useState<MetricRef | null>(null)
  return (
    <DrawerCtx.Provider value={setRef}>
      {children}
      {ref && <MetricDrawer metricRef={ref} onClose={() => setRef(null)} />}
    </DrawerCtx.Provider>
  )
}

/* ------------------------------------------------------------------ colors & formatting */
// Semantic colors for statuses that appear in part-of-whole breakdowns
const STATE_COLOR: Record<string, string> = {
  ...STATUS_COLOR, Open: 'var(--high)', Closed: 'var(--good)', Remediated: 'var(--good)', 'Risk accepted': 'var(--low)',
  'Not ticketed': 'var(--critical)', Tracked: 'var(--good)', 'Done (awaiting rescan)': 'var(--s7)', 'On track': 'var(--good)', Overdue: 'var(--critical)',
  Healthy: 'var(--good)', 'Reduced functionality': 'var(--medium)', 'No sensor': 'var(--critical)',
  implemented: 'var(--good)', partial: 'var(--medium)', 'not implemented': 'var(--critical)',
}
const CATEGORICAL = ['var(--s1)', 'var(--s2)', 'var(--s3)', 'var(--s4)', 'var(--s5)', 'var(--s6)', 'var(--s7)', 'var(--s8)']

function barColor(kind: string, label: string, index = 0, forPie = false) {
  if (kind === 'severity') return SEV_COLOR[label.toLowerCase()] || 'var(--s1)'
  if (kind === 'tool') return TOOL_COLOR[label.toLowerCase()] || 'var(--s1)'
  if (kind === 'status') return STATE_COLOR[label] || CATEGORICAL[index % 8]
  if (kind === 'priority') return PRIORITY_COLOR[label] || 'var(--low)'
  return forPie ? CATEGORICAL[index % 8] : 'var(--s1)'
}

const fmtVal = (v: any, unit = '') => (v === null || v === undefined ? '—' : `${typeof v === 'number' ? v.toLocaleString() : v}${unit}`)

/* ------------------------------------------------------------------ KPI card with view switcher */
const VIEW_ICON: Record<View, ReactNode> = { number: <Hash size={13} />, trend: <LineIcon size={13} />, bars: <BarChart3 size={13} />, pie: <PieIcon size={13} /> }
const VIEW_LABEL: Record<View, string> = { number: 'Number', trend: 'Trend over time', bars: 'Breakdown', pie: 'Pie chart' }

function storedView(id: string): View {
  try { return (localStorage.getItem(`metric-view:${id}`) as View) || 'number' } catch { return 'number' }
}

export function Kpi({ label, value, unit, foot, tone, metric, params }: {
  label: string; value?: ReactNode; unit?: string; foot?: ReactNode; tone?: 'good' | 'bad'
  metric?: string; params?: MetricRef['params']
}) {
  const ref = metric ? { key: metric, params } : null
  const id = ref ? refId(ref) : ''
  const catalog = useCatalog()
  const meta = metric && catalog ? catalog[metric] : null
  const views: View[] = ['number', ...(meta?.trend ? ['trend' as View] : []), ...(meta?.bars ? ['bars' as View] : []), ...(meta?.pie ? ['pie' as View] : [])]
  const [view, setView] = useState<View>(() => (id ? storedView(id) : 'number'))
  const active = views.includes(view) ? view : 'number'
  // When the page doesn't supply the value, the card loads it from the metric catalog
  const selfLoading = value === undefined
  const { data } = useDetail(ref && (active !== 'number' || selfLoading) ? ref : null)
  const shown = selfLoading ? (data ? data.value : <Spinner size={16} />) : value
  const open = useMetricDrawer()

  function choose(v: View, e: React.MouseEvent) {
    e.stopPropagation()
    setView(v)
    try { localStorage.setItem(`metric-view:${id}`, v) } catch { /* storage unavailable */ }
  }

  const valueEl = (
    <div className="kpi-value" style={{ ...(tone ? { color: tone === 'bad' ? 'var(--bad-text)' : 'var(--good-text)' } : {}), ...(active !== 'number' ? { fontSize: 20 } : {}) }}>
      {shown ?? '—'}{unit && <small>{unit}</small>}
    </div>
  )

  return (
    <div className={`card kpi ${ref ? 'kpi-click' : ''}`} onClick={ref ? () => open(ref) : undefined}
      role={ref ? 'button' : undefined} tabIndex={ref ? 0 : undefined}
      onKeyDown={ref ? (e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), open(ref)) : undefined}
      title={ref ? 'Click for details, affected assets, and how this is calculated' : undefined}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 6, alignItems: 'flex-start' }}>
        <div className="kpi-label">{label}</div>
        {ref && views.length > 1 && (
          <div className="viewsw" onClick={(e) => e.stopPropagation()}>
            {views.map((v) => (
              <button key={v} className={active === v ? 'on' : ''} onClick={(e) => choose(v, e)} aria-label={VIEW_LABEL[v]} title={VIEW_LABEL[v]}>{VIEW_ICON[v]}</button>
            ))}
          </div>
        )}
      </div>
      {valueEl}
      {active === 'number' && foot && <div className="kpi-foot">{foot}</div>}
      {active !== 'number' && (
        <div style={{ height: 64, marginTop: 2 }}>
          {!data ? <div className="muted" style={{ fontSize: 12, paddingTop: 20 }}><Spinner size={12} /> Loading…</div>
            : active === 'trend' ? <Sparkline series={data.series} unit={data.unit} />
              : active === 'pie' ? <MiniPie breakdown={data.breakdowns.find((b: any) => b.pie)} />
              : <MiniBars breakdown={data.breakdowns[0]} unit={data.unit} />}
        </div>
      )}
    </div>
  )
}

function Sparkline({ series, unit }: { series: any[] | null; unit: string }) {
  if (!series) return <div className="muted" style={{ fontSize: 12 }}>No history available</div>
  return (
    <ResponsiveContainer>
      <LineChart data={series} margin={{ top: 4, right: 2, left: 2, bottom: 0 }}>
        <YAxis hide domain={['auto', 'auto']} />
        <XAxis dataKey="date" hide />
        <Tooltip content={<ChartTooltip unit={unit} labelFormatter={(l: string) => fmtDate(l)} />} />
        <Line dataKey="value" name="Value" stroke="var(--s1)" strokeWidth={2} dot={false} connectNulls isAnimationActive={false} />
      </LineChart>
    </ResponsiveContainer>
  )
}

function MiniPie({ breakdown }: { breakdown?: any }) {
  if (!breakdown) return <div className="muted" style={{ fontSize: 12 }}>No breakdown available</div>
  const data = breakdown.data.filter((d: any) => d.value > 0)
  const total = data.reduce((a: number, d: any) => a + d.value, 0) || 1
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '64px 1fr', gap: 10, alignItems: 'center', height: '100%' }} title={`By ${breakdown.by.toLowerCase()}`}>
      <ResponsiveContainer>
        <PieChart>
          <Pie data={data} dataKey="value" nameKey="label" innerRadius={17} outerRadius={30} stroke="var(--surface)" strokeWidth={2} isAnimationActive={false}>
            {data.map((d: any, i: number) => <Cell key={d.label} fill={barColor(breakdown.kind, d.label, i, true)} />)}
          </Pie>
          <Tooltip content={<ChartTooltip />} />
        </PieChart>
      </ResponsiveContainer>
      <div>
        {data.slice(0, 4).map((d: any, i: number) => (
          <div key={d.label} style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 11, lineHeight: '15px' }}>
            <i style={{ width: 8, height: 8, borderRadius: 2, background: barColor(breakdown.kind, d.label, i, true), flexShrink: 0 }} />
            <span className="text-2" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{cap(d.label)}</span>
            <span className="num">{Math.round((100 * d.value) / total)}%</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function MiniBars({ breakdown, unit }: { breakdown?: any; unit: string }) {
  if (!breakdown) return <div className="muted" style={{ fontSize: 12 }}>No breakdown available</div>
  const top = breakdown.data.slice(0, 4)
  const max = Math.max(1, ...top.map((d: any) => d.value))
  return (
    <div title={`By ${breakdown.by.toLowerCase()}`}>
      {top.map((d: any) => (
        <div key={d.label} style={{ display: 'grid', gridTemplateColumns: '38% 1fr 40px', gap: 6, alignItems: 'center', fontSize: 11, lineHeight: '15px' }}>
          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} className="text-2">{cap(d.label)}</span>
          <span className="meter" style={{ height: 6 }}><span style={{ width: `${(100 * d.value) / max}%`, background: barColor(breakdown.kind, d.label) }} /></span>
          <span className="num">{fmtVal(d.value, unit.trim() === '%' ? '%' : '')}</span>
        </div>
      ))}
    </div>
  )
}

/* ------------------------------------------------------------------ clickable wrapper for non-card metrics */
export function MetricLink({ metric, params, children, className, style }: {
  metric: string; params?: MetricRef['params']; children: ReactNode; className?: string; style?: React.CSSProperties
}) {
  const open = useMetricDrawer()
  return (
    <div className={`metric-link ${className || ''}`} style={style} role="button" tabIndex={0}
      onClick={(e) => { e.stopPropagation(); open({ key: metric, params }) }}
      onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), open({ key: metric, params }))}
      title="Click for details">
      {children}
    </div>
  )
}

/* ------------------------------------------------------------------ drawer */
function MetricDrawer({ metricRef, onClose }: { metricRef: MetricRef; onClose: () => void }) {
  const { data: d, error } = useDetail(metricRef)
  const navigate = useNavigate()
  const { can } = useAuth()
  function askAnalyst() {
    const scope = d.scope ? ` for ${d.scope}` : ''
    onClose()
    navigate(`/assistant?q=${encodeURIComponent(`Explain the "${d.label}" metric${scope}: what is driving the current value of ${d.value}${d.unit.trim()}, and what should we do about it?`)}`)
  }
  const [view, setView] = useState<'trend' | 'bars' | 'pie'>('trend')
  const [pieIndex, setPieIndex] = useState(0)
  const [bdIndex, setBdIndex] = useState(0)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])
  useEffect(() => { if (d && !d.series) setView('bars') }, [d])
  const pies = d ? d.breakdowns.filter((b: any) => b.pie) : []

  return (
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <aside className="drawer drawer-wide" role="dialog" aria-label="Metric details">
        <div className="card-head" style={{ alignItems: 'flex-start' }}>
          <div>
            <div className="card-sub" style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              Metric details
              {d?.scope && <span className="badge">{d.scope}</span>}
              {d && ['alerts', 'incidents', 'mttd', 'mttr_critical_alerts', 'false_positive_rate', 'alerts_investigating'].includes(d.key) &&
                <span className="badge">Last {d.window_days} days</span>}
            </div>
            <h2 style={{ fontSize: 20, marginTop: 2 }}>{d?.label ?? '…'}</h2>
          </div>
          <button className="btn btn-ghost" onClick={onClose} aria-label="Close"><X size={18} /></button>
        </div>
        {error && <div className="card delta-bad">Could not load metric: {error}</div>}
        {!d && !error && <div className="skeleton" style={{ height: 300 }} />}
        {d && (
          <>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 12, marginBottom: 14, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 44, fontWeight: 700, letterSpacing: -1 }}>{fmtVal(d.value)}</span>
              <span className="text-2" style={{ fontSize: 16 }}>{d.unit.trim()}</span>
              <span className="badge">{d.better === 'lower' ? <><ArrowDown size={11} /> Lower is better</> : <><ArrowUp size={11} /> Higher is better</>}</span>
              {can('use_assistant') && <button className="btn btn-sm" style={{ marginLeft: 'auto' }} onClick={askAnalyst}><Bot size={13} /> Ask the AI analyst</button>}
            </div>

            {(d.series || d.breakdowns.length > 0) && (
              <section className="card" style={{ marginBottom: 14 }}>
                <div className="card-head">
                  <div className="seg">
                    {d.series && <button className={view === 'trend' ? 'on' : ''} onClick={() => setView('trend')}><LineIcon size={13} /> Trend</button>}
                    {d.breakdowns.length > 0 && <button className={view === 'bars' ? 'on' : ''} onClick={() => setView('bars')}><BarChart3 size={13} /> Breakdown</button>}
                    {pies.length > 0 && <button className={view === 'pie' ? 'on' : ''} onClick={() => setView('pie')}><PieIcon size={13} /> Pie</button>}
                  </div>
                  {view === 'pie' && pies.length > 1 && (
                    <select className="select" value={pieIndex} onChange={(e) => setPieIndex(Number(e.target.value))} aria-label="Pie breakdown">
                      {pies.map((b: any, i: number) => <option key={b.by} value={i}>{b.by}</option>)}
                    </select>
                  )}
                  {view === 'bars' && d.breakdowns.length > 1 && (
                    <select className="select" value={bdIndex} onChange={(e) => setBdIndex(Number(e.target.value))} aria-label="Break down by">
                      {d.breakdowns.map((b: any, i: number) => <option key={b.by} value={i}>By {b.by.toLowerCase()}</option>)}
                    </select>
                  )}
                  {view === 'trend' && <span className="muted" style={{ fontSize: 12 }}>{d.series_label}</span>}
                </div>
                <div style={{ height: 230 }}>
                  {view === 'trend' && d.series ? <TrendChart series={d.series} unit={d.unit} monthly={d.series_label?.startsWith('Monthly')} />
                    : view === 'pie' && pies.length ? <PieBreakdown b={pies[Math.min(pieIndex, pies.length - 1)]} />
                    : <BreakdownChart b={d.breakdowns[Math.min(bdIndex, d.breakdowns.length - 1)]} unit={d.unit} />}
                </div>
              </section>
            )}

            <div className="grid g-2" style={{ marginBottom: 14 }}>
              <section className="card">
                <div className="card-title" style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 6 }}><Info size={15} /> What it measures</div>
                <p style={{ margin: 0, fontSize: 13.5 }} className="text-2">{d.description}</p>
              </section>
              <section className="card">
                <div className="card-title" style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 6 }}><Target size={15} /> Why it matters</div>
                <p style={{ margin: 0, fontSize: 13.5 }} className="text-2">{d.why}</p>
              </section>
            </div>

            <section className="card" style={{ marginBottom: 14 }}>
              <div className="card-title" style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 8 }}><Calculator size={15} /> How it's calculated</div>
              <p style={{ margin: '0 0 12px', fontSize: 13.5 }} className="text-2">{d.calculation}</p>
              {Object.keys(d.inputs).length > 0 && (
                <div className="inputs">
                  {Object.entries(d.inputs).map(([k, v]) => (
                    <div key={k}><span className="muted">{k}</span><b>{String(v)}</b></div>
                  ))}
                </div>
              )}
              <div className="card-title" style={{ display: 'flex', gap: 6, alignItems: 'center', margin: '16px 0 8px' }}><Database size={15} /> Where the data comes from</div>
              <div className="list">
                {d.sources.map((s: any) => (
                  <div key={s.name} className="list-item" style={{ padding: '7px 0', alignItems: 'center' }}>
                    <div style={{ flex: 1 }}><b style={{ fontSize: 13 }}>{s.name}</b> <span className="muted" style={{ fontSize: 12.5 }}>— {s.detail}</span></div>
                    {s.mode === 'live' && <span className="badge badge-live"><span className="live-dot" />Live</span>}
                  </div>
                ))}
              </div>
            </section>

            {d.items_redacted ? (
              <section className="card">
                <div className="card-title">{d.items_label}</div>
                <p className="text-2" style={{ fontSize: 13.5, margin: '6px 0 0' }}>
                  {d.items.total.toLocaleString()} record{d.items.total === 1 ? '' : 's'} behind this metric. Asset-level detail (hosts, users, findings)
                  is limited to Security Analyst and Administrator roles.
                </p>
              </section>
            ) : d.items && <ItemsTable label={d.items_label} table={d.items} />}
          </>
        )}
      </aside>
    </div>
  )
}

function TrendChart({ series, unit, monthly }: { series: any[]; unit: string; monthly?: boolean }) {
  const fmt = (l: string) => (monthly ? fmtDate(l, { month: 'short', year: '2-digit' }) : fmtDate(l))
  return (
    <ResponsiveContainer>
      <LineChart data={series} margin={{ top: 8, right: 12, left: -8, bottom: 0 }}>
        <CartesianGrid vertical={false} stroke="var(--grid)" />
        <XAxis dataKey="date" tickFormatter={fmt} {...axisProps} minTickGap={24} />
        <YAxis {...axisProps} domain={['auto', 'auto']} />
        <Tooltip content={<ChartTooltip unit={unit} labelFormatter={(l: string) => (monthly ? fmt(l) : `Week ending ${fmtDate(l)}`)} />} />
        <Line dataKey="value" name="Value" stroke="var(--s1)" strokeWidth={2} dot={{ r: 3, fill: 'var(--s1)' }} connectNulls isAnimationActive={false} />
      </LineChart>
    </ResponsiveContainer>
  )
}

function PieBreakdown({ b }: { b: any }) {
  const data = b.data.filter((x: any) => x.value > 0).map((x: any) => ({ ...x, label: cap(x.label) }))
  const total = data.reduce((a: number, x: any) => a + x.value, 0) || 1
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(180px, 1fr) 1fr', gap: 16, alignItems: 'center', height: '100%' }}>
      <ResponsiveContainer>
        <PieChart>
          <Pie data={data} dataKey="value" nameKey="label" innerRadius="52%" outerRadius="88%" stroke="var(--surface)" strokeWidth={2} paddingAngle={1} isAnimationActive={false}>
            {data.map((x: any, i: number) => <Cell key={x.label} fill={barColor(b.kind, b.data.find((o: any) => cap(o.label) === x.label)?.label ?? x.label, i, true)} />)}
          </Pie>
          <Tooltip content={<ChartTooltip />} />
        </PieChart>
      </ResponsiveContainer>
      <table>
        <tbody>
          {data.map((x: any, i: number) => (
            <tr key={x.label}>
              <td><span style={{ display: 'inline-block', width: 10, height: 10, borderRadius: 3, marginRight: 8, background: barColor(b.kind, b.data.find((o: any) => cap(o.label) === x.label)?.label ?? x.label, i, true) }} />{x.label}</td>
              <td className="num">{x.value.toLocaleString()}</td>
              <td className="num muted">{((100 * x.value) / total).toFixed(1)}%</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function BreakdownChart({ b, unit }: { b: any; unit: string }) {
  const data = b.data.map((x: any) => ({ ...x, label: cap(x.label) }))
  return (
    <ResponsiveContainer>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 24, left: 8, bottom: 0 }} barCategoryGap={6}>
        <CartesianGrid horizontal={false} stroke="var(--grid)" />
        <XAxis type="number" {...axisProps} />
        <YAxis type="category" dataKey="label" {...axisProps} width={170} tickFormatter={(s: string) => (s.length > 26 ? s.slice(0, 25) + '…' : s)} />
        <Tooltip cursor={{ fill: 'var(--surface-2)' }} content={<ChartTooltip unit={unit.trim() === '%' ? '%' : ''} />} />
        <Bar dataKey="value" name={b.by} radius={[0, 4, 4, 0]} isAnimationActive={false}>
          {data.map((x: any, i: number) => <Cell key={x.label} fill={barColor(b.kind, b.data[i]?.label ?? x.label, i)} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

/* ------------------------------------------------------------------ affected records table */
const STATUS_TONE: Record<string, string> = {
  implemented: 'var(--good)', partial: 'var(--medium)', not_implemented: 'var(--critical)', overdue: 'var(--critical)', due_soon: 'var(--medium)',
  new: 'var(--critical)', investigating: 'var(--medium)', resolved: 'var(--good)', false_positive: 'var(--low)',
}

function ItemsTable({ label, table }: { label: string; table: any }) {
  const openAsset = useAssetDrawer()
  const { openTicket } = useTickets()
  const [q, setQ] = useState('')
  const [shown, setShown] = useState(50)
  const today = new Date().toISOString().slice(0, 10)
  const rows = useMemo(() => {
    if (!q) return table.rows
    const needle = q.toLowerCase()
    return table.rows.filter((r: any) => Object.values(r).some((v) => String(v ?? '').toLowerCase().includes(needle)))
  }, [q, table.rows])

  function cell(type: string, v: any, r: any) {
    if (v === null || v === undefined || v === '') return <span className="muted">—</span>
    switch (type) {
      case 'severity': return <SevBadge sev={v} />
      case 'tool': return cap(v === 'crowdstrike' ? 'CrowdStrike' : v)
      case 'date': return fmtDate(v, { month: 'short', day: 'numeric', year: '2-digit' })
      case 'datetime': return <span title={v}>{timeAgo(v)}</span>
      case 'due': return <span className={v < today && r.status !== 'remediated' ? 'delta-bad' : ''}>{fmtDate(v, { month: 'short', day: 'numeric', year: '2-digit' })}</span>
      case 'mono': return <span className="mono">{v}</span>
      case 'upper': return String(v).toUpperCase()
      case 'num': return <span className="num">{typeof v === 'number' ? v.toLocaleString() : v}</span>
      case 'bool': return v ? 'Yes' : 'No'
      case 'label': return cap(String(v).replace('_', ' '))
      case 'edr': return { missing: 'No sensor', rfm: 'Reduced functionality', normal: 'Healthy' }[v as string] ?? v
      case 'status': return <span className="badge"><span className="sw" style={{ background: STATUS_TONE[v] || STATE_COLOR[v] || 'var(--low)' }} />{cap(String(v).replace('_', ' '))}</span>
      case 'priority': return <PriorityBadge priority={v} />
      case 'ticket': return <button className="btn btn-sm mono" onClick={(e) => { e.stopPropagation(); openTicket(v) }}>{v}</button>
      case 'cve': return <Link to={`/threats/active#${v}`} className="mono" onClick={(e) => e.stopPropagation()}>{v}</Link>
      case 'asset': return <span>{v} {r.internet_facing ? <Globe size={11} color="var(--critical)" aria-label="Internet-facing" /> : null}</span>
      default: return <>{String(v)}{r.in_kev && type === 'text' && r.cve && <span className="badge badge-kev" style={{ marginLeft: 6 }}>KEV</span>}</>
    }
  }

  return (
    <section className="card">
      <div className="card-head">
        <div>
          <div className="card-title">{label}</div>
          <div className="card-sub">{table.total.toLocaleString()} record{table.total === 1 ? '' : 's'}{table.total > table.rows.length ? ` · showing first ${table.rows.length}` : ''}{table.rows.some((r: any) => r.asset_id) ? ' · click a row to open the asset' : ''}</div>
        </div>
        {table.rows.length > 8 && (
          <div style={{ position: 'relative' }}>
            <Search size={13} style={{ position: 'absolute', left: 9, top: 10 }} className="muted" />
            <input className="input" placeholder="Filter…" value={q} onChange={(e) => { setQ(e.target.value); setShown(50) }} style={{ paddingLeft: 28, width: 180 }} />
          </div>
        )}
      </div>
      {table.rows.length === 0 ? <div className="empty">Nothing affected — this metric is clear.</div> : (
        <div className="table-wrap">
          <table>
            <thead><tr>{table.columns.map((c: any) => <th key={c.key} className={c.type === 'num' ? 'num' : ''}>{c.label}</th>)}</tr></thead>
            <tbody>
              {rows.slice(0, shown).map((r: any, i: number) => (
                <tr key={i} className={r.asset_id ? 'clickable' : ''} onClick={r.asset_id ? () => openAsset(r.asset_id) : undefined}>
                  {table.columns.map((c: any) => <td key={c.key} className={c.type === 'num' ? 'num' : ''} style={c.key === 'title' || c.key === 'name' || c.key === 'detail' ? { maxWidth: 320 } : undefined}>{cell(c.type, r[c.key], r)}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length > shown && <div style={{ textAlign: 'center', marginTop: 10 }}><button className="btn btn-sm" onClick={() => setShown(shown + 100)}>Show more ({rows.length - shown} remaining)</button></div>}
        </div>
      )}
    </section>
  )
}
