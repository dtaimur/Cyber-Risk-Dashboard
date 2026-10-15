import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { CheckCircle2, ExternalLink, Globe, TicketPlus, X } from 'lucide-react'
import { api, patch, post } from '../api'
import { useAuth } from '../auth'
import { cap, fmtDate, timeAgo } from '../format'
import { useAssetDrawer } from './AssetDrawer'
import { Modal, SevBadge, Spinner, nextOverlayZ } from './ui'

export const TICKET_STATUSES = ['To Do', 'In Progress', 'In Review', 'Done', "Won't Fix"]
export const PRIORITIES = ['Highest', 'High', 'Medium', 'Low']
export const STATUS_COLOR: Record<string, string> = {
  'To Do': 'var(--low)', 'In Progress': 'var(--s1)', 'In Review': 'var(--s7)', Done: 'var(--good)', "Won't Fix": 'var(--axis)',
}
export const PRIORITY_COLOR: Record<string, string> = { Highest: 'var(--critical)', High: 'var(--high)', Medium: 'var(--medium)', Low: 'var(--low)' }

type Source = { source_type: 'threat'; cve: string } | { source_type: 'finding'; finding_id: number }
type Ctx = { openTicket: (key: string) => void; createTicket: (src: Source, onCreated?: (t: any) => void) => void }
type HostState = {
  open: { key: string; z: number } | null; setOpen: (o: { key: string; z: number } | null) => void
  creating: { src: Source; onCreated?: (t: any) => void } | null; setCreating: (c: HostState['creating']) => void
}
const TicketCtx = createContext<Ctx>({ openTicket: () => {}, createTicket: () => {} })
const HostCtx = createContext<HostState>(null as unknown as HostState)
export const useTickets = () => useContext(TicketCtx)

/** Ticket state; <TicketHost/> renders the drawer and create dialog. */
export function TicketProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState<HostState['open']>(null)
  const [creating, setCreating] = useState<HostState['creating']>(null)
  return (
    <TicketCtx.Provider value={{ openTicket: (key) => setOpen({ key, z: nextOverlayZ() }), createTicket: (src, onCreated) => setCreating({ src, onCreated }) }}>
      <HostCtx.Provider value={{ open, setOpen, creating, setCreating }}>{children}</HostCtx.Provider>
    </TicketCtx.Provider>
  )
}

export function TicketHost() {
  const { open, setOpen, creating, setCreating } = useContext(HostCtx)
  return (
    <>
      {creating && <CreateTicketModal src={creating.src} onClose={() => setCreating(null)}
        onCreated={(t) => { setCreating(null); creating.onCreated?.(t); window.dispatchEvent(new Event('dashboard:refresh')); setOpen({ key: t.key, z: nextOverlayZ() }) }} />}
      {open && <TicketDrawer ticketKey={open.key} z={open.z} onClose={() => setOpen(null)} />}
    </>
  )
}

export function StatusBadge({ status }: { status: string }) {
  return <span className="badge"><span className="sw" style={{ background: STATUS_COLOR[status] || 'var(--low)' }} />{status}</span>
}
export function PriorityBadge({ priority }: { priority: string }) {
  return <span className="badge"><span className="sw" style={{ background: PRIORITY_COLOR[priority] || 'var(--low)' }} />{priority}</span>
}

/** Small "Create ticket" / ticket-key control used on threats and findings. */
export function TicketButton({ ticket, src, compact }: { ticket?: { key: string; status: string } | null; src: Source; compact?: boolean }) {
  const { openTicket, createTicket } = useTickets()
  const { can } = useAuth()
  if (ticket) {
    return (
      <button className="btn btn-sm" onClick={(e) => { e.stopPropagation(); openTicket(ticket.key) }} title={`Open ${ticket.key}`}>
        <span className="sw" style={{ width: 8, height: 8, borderRadius: 2, background: STATUS_COLOR[ticket.status] }} />
        <span className="mono">{ticket.key}</span>{!compact && <span className="muted">· {ticket.status}</span>}
      </button>
    )
  }
  if (!can('manage_remediation')) return compact ? <span className="muted">—</span> : null
  return (
    <button className="btn btn-sm" onClick={(e) => { e.stopPropagation(); createTicket(src) }}>
      <TicketPlus size={13} /> {compact ? 'Create' : 'Create Jira ticket'}
    </button>
  )
}

function CreateTicketModal({ src, onClose, onCreated }: { src: Source; onClose: () => void; onCreated: (t: any) => void }) {
  const [draft, setDraft] = useState<any>(null)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    post('/remediation/draft', src).then(setDraft).catch((e) => setError(e.message))
  }, [src])

  const set = (k: string) => (e: any) => setDraft({ ...draft, [k]: e.target.value })

  async function submit() {
    setSaving(true); setError(null)
    try {
      onCreated(await post('/remediation/tickets', { ...src, ...Object.fromEntries(
        ['summary', 'description', 'priority', 'team', 'assignee', 'due_date'].map((k) => [k, draft[k] || null])) }))
    } catch (e: any) { setError(e.message) } finally { setSaving(false) }
  }

  return (
    <Modal title="Create remediation ticket" onClose={onClose}>
      {!draft && !error && <div className="skeleton" style={{ height: 240 }} />}
      {draft && (
        <div className="form-grid">
          <label className="field full">Summary<input className="input" value={draft.summary} onChange={set('summary')} /></label>
          <label className="field">Priority
            <select className="select" value={draft.priority} onChange={set('priority')}>{PRIORITIES.map((p) => <option key={p}>{p}</option>)}</select>
          </label>
          <label className="field">Due date<input className="input" type="date" value={draft.due_date || ''} onChange={set('due_date')} /></label>
          <label className="field">Team<input className="input" value={draft.team} onChange={set('team')} /></label>
          <label className="field">Assignee<input className="input" value={draft.assignee || ''} onChange={set('assignee')} /></label>
          <label className="field full">Description
            <textarea className="input mono" rows={10} value={draft.description} onChange={set('description')} style={{ fontSize: 12, lineHeight: 1.5 }} />
          </label>
          <div className="full muted" style={{ fontSize: 12 }}>
            Links {draft.finding_ids.length} finding{draft.finding_ids.length === 1 ? '' : 's'}. Due date defaults to the earliest remediation SLA.
            {draft.destination === 'jira' && <> The issue will be created in Jira.</>}
          </div>
        </div>
      )}
      {error && <div className="login-error">{error}</div>}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" onClick={submit} disabled={!draft || saving}>{saving ? <Spinner /> : <TicketPlus size={14} />} Create ticket</button>
      </div>
    </Modal>
  )
}

function TicketDrawer({ ticketKey, z, onClose }: { ticketKey: string; z: number; onClose: () => void }) {
  const [t, setT] = useState<any>(null)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const { can } = useAuth()
  const openAsset = useAssetDrawer()
  const editable = can('manage_remediation')

  useEffect(() => { api(`/remediation/tickets/${ticketKey}`).then(setT).catch((e) => setError(e.message)) }, [ticketKey])

  async function change(fields: Record<string, string>) {
    setSaving(true); setError(null)
    try {
      setT(await patch(`/remediation/tickets/${ticketKey}`, fields))
      window.dispatchEvent(new Event('dashboard:refresh'))
    } catch (e: any) { setError(e.message) } finally { setSaving(false) }
  }

  return (
    <div className="overlay" style={{ zIndex: z }} onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <aside className="drawer" role="dialog" aria-label="Ticket details">
        <div className="card-head" style={{ alignItems: 'flex-start' }}>
          <div>
            <div className="card-sub" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span className="mono">{ticketKey}</span>
              {t?.is_live ? <span className="badge badge-live"><span className="live-dot" />Jira</span> : null}
              {saving && <Spinner size={12} />}
            </div>
            <h2 style={{ fontSize: 18, marginTop: 4 }}>{t?.summary ?? '…'}</h2>
          </div>
          <button className="btn btn-ghost" onClick={onClose} aria-label="Close"><X size={18} /></button>
        </div>
        {error && <div className="login-error" style={{ marginBottom: 12 }}>{error}</div>}
        {!t && !error && <div className="skeleton" style={{ height: 300 }} />}
        {t && (
          <>
            {t.verification === 'awaiting_verification' && (
              <div className="card" style={{ borderColor: 'var(--medium)', marginBottom: 12, fontSize: 13 }}>
                Marked Done, but the scanner still detects {t.findings.filter((f: any) => f.status === 'open' || f.status === 'in_progress').length} of the linked findings. The fix needs verification.
              </div>
            )}
            {t.verification === 'verified' && (
              <div className="card" style={{ marginBottom: 12, fontSize: 13, display: 'flex', gap: 8, alignItems: 'center' }}>
                <CheckCircle2 size={16} color="var(--good)" /> Verified: none of the linked findings are detected anymore.
              </div>
            )}
            <div className="card" style={{ marginBottom: 12 }}>
              <div className="form-grid">
                <label className="field">Status
                  {editable ? (
                    <select className="select" value={t.status} onChange={(e) => change({ status: e.target.value })} style={{ borderLeft: `4px solid ${STATUS_COLOR[t.status]}` }}>
                      {TICKET_STATUSES.map((s) => <option key={s}>{s}</option>)}
                    </select>
                  ) : <StatusBadge status={t.status} />}
                </label>
                <label className="field">Priority
                  {editable ? (
                    <select className="select" value={t.priority} onChange={(e) => change({ priority: e.target.value })}>
                      {PRIORITIES.map((p) => <option key={p}>{p}</option>)}
                    </select>
                  ) : <PriorityBadge priority={t.priority} />}
                </label>
                <label className="field">Assignee
                  {editable ? <input className="input" defaultValue={t.assignee || ''} onBlur={(e) => e.target.value !== (t.assignee || '') && change({ assignee: e.target.value })} />
                    : <span>{t.assignee || '—'}</span>}
                </label>
                <label className="field">Due date
                  {editable ? <input className="input" type="date" defaultValue={t.due_date || ''} onBlur={(e) => e.target.value && e.target.value !== t.due_date && change({ due_date: e.target.value })} />
                    : <span>{fmtDate(t.due_date, { month: 'short', day: 'numeric', year: 'numeric' })}</span>}
                </label>
              </div>
              <div className="muted" style={{ fontSize: 12, marginTop: 10 }}>
                Team {t.team} · reported by {t.reporter} · created {fmtDate(t.created_at, { month: 'short', day: 'numeric', year: 'numeric' })}
                {t.resolved_at && <> · resolved {fmtDate(t.resolved_at, { month: 'short', day: 'numeric', year: 'numeric' })}</>}
              </div>
              {t.status === "Won't Fix" && <div className="muted" style={{ fontSize: 12, marginTop: 6 }}>Won't Fix records a formal risk acceptance; the linked findings leave the SLA backlog.</div>}
              {t.url && <a className="btn btn-sm" style={{ marginTop: 10 }} href={t.url} target="_blank" rel="noopener noreferrer"><ExternalLink size={13} /> Open in Jira</a>}
            </div>

            <div className="card" style={{ marginBottom: 12 }}>
              <div className="card-title" style={{ marginBottom: 8 }}>Linked findings ({t.findings.length})</div>
              <table>
                <thead><tr><th>Severity</th><th>Finding</th><th>Asset</th><th>Scanner status</th></tr></thead>
                <tbody>
                  {t.findings.map((f: any) => (
                    <tr key={f.id} className="clickable" onClick={() => openAsset(f.asset_id)}>
                      <td><SevBadge sev={f.severity} /></td>
                      <td>{f.title}{f.cve && <div className="mono muted" style={{ fontSize: 11.5 }}>{f.cve}</div>}</td>
                      <td>{f.hostname} {f.internet_facing ? <Globe size={11} color="var(--critical)" /> : null}</td>
                      <td className={f.status === 'remediated' ? 'delta-good' : ''}>{f.status === 'remediated' ? 'Fixed' : cap(f.status.replace('_', ' '))}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="card" style={{ marginBottom: 12 }}>
              <div className="card-title" style={{ marginBottom: 8 }}>Description</div>
              <div className="text-2" style={{ whiteSpace: 'pre-wrap', fontSize: 13 }}>{t.description}</div>
            </div>

            {t.history.length > 0 && (
              <div className="card">
                <div className="card-title" style={{ marginBottom: 8 }}>History</div>
                {t.history.map((h: any, i: number) => {
                  let d: any = {}
                  try { d = JSON.parse(h.detail) } catch { /* plain text */ }
                  const what = h.action === 'ticket.create' ? 'created the ticket'
                    : Object.entries(d).filter(([k]) => k !== 'key').map(([k, v]) => `set ${k.replace('_', ' ')} to ${v}`).join(', ')
                  return <div key={i} style={{ fontSize: 12.5, padding: '4px 0' }}><b>{h.actor}</b> {what} <span className="muted">· {timeAgo(h.ts)}</span></div>
                })}
              </div>
            )}
          </>
        )}
      </aside>
    </div>
  )
}
