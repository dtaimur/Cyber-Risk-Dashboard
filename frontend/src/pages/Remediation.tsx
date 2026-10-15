import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { useApi } from '../api'
import { useAuth } from '../auth'
import { fmtDate } from '../format'
import { Kpi } from '../components/Metric'
import { PRIORITIES, PRIORITY_COLOR, PriorityBadge, STATUS_COLOR, StatusBadge, TICKET_STATUSES, useTickets } from '../components/Tickets'
import { Card, ChartTooltip, ErrorBox, Legend, Loading, ModeBadge, PageHeader, axisProps } from '../components/ui'

export default function Remediation() {
  const { data: d, error, reload } = useApi<any>('/remediation/overview')
  const { can } = useAuth()
  if (error) return <ErrorBox error={error} onRetry={reload} />
  if (!d) return <Loading />
  const total = d.status_counts.reduce((a: number, s: any) => a + s.count, 0) || 1

  return (
    <>
      <PageHeader title="Jira Remediation"
        subtitle="Remediation tickets from detection to verified fix"
        actions={<>
          <ModeBadge mode={d.mode} />
          <Link to="/threats/active" className="btn btn-sm">Create from Active Threats</Link>
          {can('manage_integrations') && <Link to="/settings/integrations" className="btn btn-sm">Configure Jira</Link>}
        </>} />

      <div className="grid g-6">
        <Kpi label="Open vs closed vulnerabilities" metric="remediation_vulns" foot="Open, of those detected in the last 90 days" />
        <Kpi label="Open tickets" metric="tickets_open" foot="To Do · In Progress · In Review" />
        <Kpi label="Overdue tickets" metric="tickets_overdue" foot="Past due date" />
        <Kpi label="Ticket resolution time" metric="ticket_mttr" unit=" days" foot="Created to Done (90d)" />
        <Kpi label="Tracking coverage" metric="tracking_coverage" unit="%" foot="Critical/high with a ticket" />
        <Kpi label="Awaiting verification" metric="awaiting_verification" foot="Done in Jira, still detected" />
      </div>

      <div className="grid g-3 mt">
        <Card title="Workflow status" subtitle="All tickets">
          <div className="stackbar" role="img" aria-label="Tickets by status">
            {d.status_counts.filter((s: any) => s.count).map((s: any) => (
              <span key={s.status} title={`${s.status}: ${s.count}`} style={{ width: `${(100 * s.count) / total}%`, background: STATUS_COLOR[s.status] }} />
            ))}
          </div>
          <table style={{ marginTop: 12 }}>
            <tbody>
              {d.status_counts.map((s: any) => (
                <tr key={s.status}><td><StatusBadge status={s.status} /></td><td className="num">{s.count}</td>
                  <td className="num muted">{((100 * s.count) / total).toFixed(0)}%</td></tr>
              ))}
            </tbody>
          </table>
          {d.untracked_critical_high > 0 && (
            <div className="muted" style={{ fontSize: 12.5, marginTop: 10 }}>
              <b style={{ color: 'var(--bad-text)' }}>{d.untracked_critical_high}</b> open critical/high findings have no ticket yet.
            </div>
          )}
        </Card>
        <Card title="Created vs resolved" subtitle="Tickets per week">
          <div style={{ height: 240 }}>
            <ResponsiveContainer>
              <BarChart data={d.weekly} margin={{ top: 6, right: 8, left: -12, bottom: 0 }} barGap={2}>
                <CartesianGrid vertical={false} stroke="var(--grid)" />
                <XAxis dataKey="date" tickFormatter={(x) => fmtDate(x)} {...axisProps} minTickGap={24} />
                <YAxis {...axisProps} allowDecimals={false} />
                <Tooltip cursor={{ fill: 'var(--surface-2)' }} content={<ChartTooltip labelFormatter={(l: string) => `Week ending ${fmtDate(l)}`} />} />
                <Bar dataKey="created" name="Created" fill="var(--s2)" radius={[4, 4, 0, 0]} isAnimationActive={false} />
                <Bar dataKey="resolved" name="Resolved" fill="var(--s1)" radius={[4, 4, 0, 0]} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <Legend items={[{ label: 'Created', color: 'var(--s2)' }, { label: 'Resolved', color: 'var(--s1)' }]} />
        </Card>
        <Card title="Open backlog" subtitle="Open tickets at the end of each week">
          <div style={{ height: 240 }}>
            <ResponsiveContainer>
              <LineChart data={d.weekly} margin={{ top: 6, right: 10, left: -12, bottom: 0 }}>
                <CartesianGrid vertical={false} stroke="var(--grid)" />
                <XAxis dataKey="date" tickFormatter={(x) => fmtDate(x)} {...axisProps} minTickGap={24} />
                <YAxis {...axisProps} allowDecimals={false} />
                <Tooltip content={<ChartTooltip labelFormatter={(l: string) => `Week ending ${fmtDate(l)}`} />} />
                <Line dataKey="open" name="Open tickets" stroke="var(--s1)" strokeWidth={2} dot={{ r: 3, fill: 'var(--s1)' }} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <div className="grid g-2 mt">
        <Card title="By team" subtitle="Ticket status, overdue items, and average resolution time per owning team">
          <div className="table-wrap">
            <table>
              <thead><tr><th>Team</th>{TICKET_STATUSES.slice(0, 4).map((s) => <th key={s} className="num">{s}</th>)}<th className="num">Overdue</th><th className="num">Avg days</th></tr></thead>
              <tbody>
                {d.by_team.map((t: any) => (
                  <tr key={t.team}>
                    <td style={{ fontWeight: 500 }}>{t.team}</td>
                    {TICKET_STATUSES.slice(0, 4).map((s) => <td key={s} className="num">{t[s] || <span className="muted">0</span>}</td>)}
                    <td className="num" style={{ color: t.overdue ? 'var(--bad-text)' : undefined }}>{t.overdue}</td>
                    <td className="num">{t.mttr_days ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
        <Card title="Open ticket age" subtitle="How long open tickets have been waiting, by priority">
          <div style={{ height: 220 }}>
            <ResponsiveContainer>
              <BarChart data={d.aging} margin={{ top: 6, right: 8, left: -12, bottom: 0 }}>
                <CartesianGrid vertical={false} stroke="var(--grid)" />
                <XAxis dataKey="bucket" {...axisProps} />
                <YAxis {...axisProps} allowDecimals={false} />
                <Tooltip cursor={{ fill: 'var(--surface-2)' }} content={<ChartTooltip />} />
                {PRIORITIES.map((p, i) => <Bar key={p} dataKey={p} name={p} stackId="a" fill={PRIORITY_COLOR[p]} stroke="var(--surface)" radius={i === 3 ? [4, 4, 0, 0] : 0} isAnimationActive={false} />)}
              </BarChart>
            </ResponsiveContainer>
          </div>
          <Legend items={PRIORITIES.map((p) => ({ label: p, color: PRIORITY_COLOR[p] }))} />
        </Card>
      </div>

      <div className="grid g-3 mt">
        <Card title="Workload by assignee" subtitle="Open tickets">
          <table>
            <thead><tr><th>Assignee</th><th className="num">Open</th><th className="num">Overdue</th></tr></thead>
            <tbody>
              {d.workload.map((w: any) => (
                <tr key={w.assignee}><td>{w.assignee}</td><td className="num">{w.open}</td>
                  <td className="num" style={{ color: w.overdue ? 'var(--bad-text)' : undefined }}>{w.overdue}</td></tr>
              ))}
            </tbody>
          </table>
        </Card>
        <div className="span-2"><TicketTable teams={d.teams} /></div>
      </div>
    </>
  )
}

function TicketTable({ teams }: { teams: string[] }) {
  const [status, setStatus] = useState('open')
  const [team, setTeam] = useState('')
  const [priority, setPriority] = useState('')
  const [q, setQ] = useState('')
  const [page, setPage] = useState(0)
  const { openTicket } = useTickets()
  const p = new URLSearchParams({ limit: '15', offset: String(page * 15) })
  if (status) p.set('status', status)
  if (team) p.set('team', team)
  if (priority) p.set('priority', priority)
  if (q) p.set('q', q)
  const { data } = useApi<any>(`/remediation/tickets?${p}`)
  const today = new Date().toISOString().slice(0, 10)
  const reset = (fn: (v: string) => void) => (e: any) => { fn(e.target.value); setPage(0) }

  return (
    <Card title="Tickets" subtitle="Click a ticket to update status, priority, assignee, or due date">
      <div className="filters">
        <input className="input" placeholder="Search key, CVE, summary, assignee…" value={q} onChange={reset(setQ)} style={{ width: 230 }} />
        <select className="select" value={status} onChange={reset(setStatus)} aria-label="Status">
          <option value="open">Open</option><option value="overdue">Overdue</option><option value="closed">Closed</option><option value="">All</option>
          {TICKET_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="select" value={team} onChange={reset(setTeam)} aria-label="Team">
          <option value="">All teams</option>{teams.map((t) => <option key={t}>{t}</option>)}
        </select>
        <select className="select" value={priority} onChange={reset(setPriority)} aria-label="Priority">
          <option value="">All priorities</option>{PRIORITIES.map((x) => <option key={x}>{x}</option>)}
        </select>
        <span className="muted" style={{ marginLeft: 'auto', fontSize: 12 }}>{data?.total ?? '…'} tickets</span>
      </div>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Key</th><th>Summary</th><th>Status</th><th>Priority</th><th>Assignee</th><th>Due</th><th className="num">Findings</th></tr></thead>
          <tbody>
            {data?.items.map((t: any) => (
              <tr key={t.key} className="clickable" onClick={() => openTicket(t.key)}>
                <td className="mono" style={{ whiteSpace: 'nowrap' }}>{t.key}</td>
                <td style={{ maxWidth: 320 }}>{t.summary}<div className="muted" style={{ fontSize: 11.5 }}>{t.team}</div></td>
                <td><StatusBadge status={t.status} />{t.verification === 'awaiting_verification' && <div style={{ fontSize: 11, color: 'var(--medium-text)', marginTop: 3 }}>Awaiting rescan</div>}</td>
                <td><PriorityBadge priority={t.priority} /></td>
                <td className="text-2">{t.assignee || '—'}</td>
                <td className={t.due_date && t.due_date < today && !['Done', "Won't Fix"].includes(t.status) ? 'delta-bad' : ''} style={{ whiteSpace: 'nowrap' }}>{fmtDate(t.due_date)}</td>
                <td className="num">{t.still_open ? `${t.still_open}/${t.finding_count}` : t.finding_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {data?.items.length === 0 && <div className="empty">No tickets match</div>}
      </div>
      {data && data.total > 15 && (
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 10, alignItems: 'center' }}>
          <span className="muted" style={{ fontSize: 12 }}>Page {page + 1} of {Math.ceil(data.total / 15)}</span>
          <button className="btn btn-sm" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
          <button className="btn btn-sm" disabled={(page + 1) * 15 >= data.total} onClick={() => setPage(page + 1)}>Next</button>
        </div>
      )}
    </Card>
  )
}
