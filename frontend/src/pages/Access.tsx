import { useState } from 'react'
import { Check, Minus } from 'lucide-react'
import { useApi } from '../api'
import { timeAgo } from '../format'
import { Card, ErrorBox, Loading, PageHeader } from '../components/ui'

const ACTION_LABEL: Record<string, string> = {
  'auth.login': 'Signed in', 'auth.logout': 'Signed out', 'auth.login_failed': 'Failed sign-in', 'auth.login_blocked': 'Sign-in blocked (locked)',
  'access.denied': 'Access denied', 'integration.update': 'Integration changed', 'control.update': 'Control status changed',
  'roadmap.create': 'Roadmap item added', 'roadmap.update': 'Roadmap item edited', 'roadmap.delete': 'Roadmap item deleted',
  'goal.create': 'Goal added', 'goal.update': 'Goal edited', 'goal.delete': 'Goal deleted',
}
const TONE: Record<string, string> = { 'auth.login_failed': 'var(--medium)', 'auth.login_blocked': 'var(--critical)', 'access.denied': 'var(--critical)' }
const FILTERS = [['', 'All events'], ['auth', 'Authentication'], ['access.denied', 'Access denied'], ['integration', 'Integrations'], ['roadmap', 'Roadmap'], ['control', 'Controls']]

function detailText(d: string) {
  try {
    const o = JSON.parse(d)
    return Object.entries(o).filter(([, v]) => v !== null && v !== false && !(Array.isArray(v) && !v.length))
      .map(([k, v]) => `${k.replace('_', ' ')}: ${Array.isArray(v) ? v.join(', ') : v}`).join(' · ')
  } catch { return d }
}

export default function Access() {
  const roles = useApi<any>('/access/roles')
  const users = useApi<any[]>('/access/users')
  const [filter, setFilter] = useState('')
  const audit = useApi<any[]>(`/access/audit?limit=200${filter ? `&action=${encodeURIComponent(filter)}` : ''}`)
  if (roles.error) return <ErrorBox error={roles.error} />
  if (!roles.data || !users.data) return <Loading />
  const roleKeys = Object.keys(roles.data.roles)

  return (
    <>
      <PageHeader title="Access & Audit"
        subtitle="Roles, permissions, users, and the audit trail" />

      <div className="grid g-3">
        {roleKeys.map((k) => {
          const r = roles.data.roles[k]
          return (
            <Card key={k} title={r.label} subtitle={r.description}>
              <div className="muted" style={{ fontSize: 12 }}>{r.permissions.length} of {Object.keys(roles.data.permissions).length} permissions · {users.data!.filter((u) => u.role === k).length} user(s)</div>
            </Card>
          )
        })}
      </div>

      <Card className="mt" title="Permission matrix" subtitle="What each role can do">
        <div className="table-wrap">
          <table>
            <thead><tr><th>Permission</th>{roleKeys.map((k) => <th key={k} style={{ textAlign: 'center' }}>{roles.data.roles[k].label}</th>)}</tr></thead>
            <tbody>
              {Object.entries(roles.data.permissions).map(([p, label]) => (
                <tr key={p}>
                  <td>{label as string}<div className="mono muted" style={{ fontSize: 11 }}>{p}</div></td>
                  {roleKeys.map((k) => (
                    <td key={k} style={{ textAlign: 'center' }}>
                      {roles.data.roles[k].permissions.includes(p)
                        ? <Check size={16} className="perm-yes" aria-label="Allowed" />
                        : <Minus size={16} className="perm-no" aria-label="Not allowed" />}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card className="mt" title="Users">
        <table>
          <thead><tr><th>User</th><th>Username</th><th>Role</th><th>Last sign-in</th><th className="num">Active sessions</th><th>Status</th></tr></thead>
          <tbody>
            {users.data.map((u) => (
              <tr key={u.username}>
                <td style={{ fontWeight: 500 }}>{u.display_name}</td>
                <td className="mono">{u.username}</td>
                <td>{u.role_label}</td>
                <td className="text-2">{u.last_login ? timeAgo(u.last_login) : 'Never'}</td>
                <td className="num">{u.active_sessions}</td>
                <td>{u.locked_until && u.locked_until > new Date().toISOString() ? <span className="delta-bad">Locked</span> : <span className="delta-good">Active</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <Card className="mt" title="Audit log" subtitle="Most recent 200 events"
        action={<select className="select" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter events">
          {FILTERS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>}>
        <div className="table-wrap" style={{ maxHeight: 520, overflowY: 'auto' }}>
          <table>
            <thead><tr><th>When</th><th>User</th><th>Event</th><th>Details</th></tr></thead>
            <tbody>
              {audit.data?.map((e) => (
                <tr key={e.id}>
                  <td className="text-2" title={e.ts} style={{ whiteSpace: 'nowrap' }}>{timeAgo(e.ts)}</td>
                  <td className="mono">{e.actor || 'system'}</td>
                  <td><span className="badge"><span className="sw" style={{ background: TONE[e.action] || 'var(--s1)' }} />{ACTION_LABEL[e.action] || e.action}</span></td>
                  <td className="text-2" style={{ fontSize: 12.5 }}>{detailText(e.detail || '')}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {audit.data?.length === 0 && <div className="empty">No events</div>}
        </div>
      </Card>
    </>
  )
}
