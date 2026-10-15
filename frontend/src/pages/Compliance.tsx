import { useState } from 'react'
import { Pencil, Plus, Trash2, Zap } from 'lucide-react'
import { del, patch, post, put, useApi } from '../api'
import { useAuth } from '../auth'
import { cap, fmtDate } from '../format'
import { Card, ErrorBox, Loading, Meter, Modal, PageHeader } from '../components/ui'
import { MetricLink } from '../components/Metric'

const STATUS_COLOR: Record<string, string> = { implemented: 'var(--good)', partial: 'var(--medium)', not_implemented: 'var(--critical)' }
const ITEM_COLOR: Record<string, string> = {
  audit: 'var(--s1)', assessment: 'var(--s3)', pen_test: 'var(--s2)', certification: 'var(--s7)', policy_review: 'var(--s5)', milestone: 'var(--s4)',
}
const ROAD_STATUS: Record<string, string> = { planned: 'Planned', in_progress: 'In progress', at_risk: 'At risk', complete: 'Complete' }
const pctColor = (p: number) => (p >= 85 ? 'var(--good)' : p >= 65 ? 'var(--medium)' : 'var(--critical)')

export default function Compliance() {
  const { data: d, error, reload } = useApi<any>('/compliance')
  const [fw, setFw] = useState<string | null>(null)
  if (error) return <ErrorBox error={error} onRetry={reload} />
  if (!d) return <Loading />
  const selected = fw ?? d.frameworks[0]?.framework
  const framework = d.frameworks.find((f: any) => f.framework === selected)

  return (
    <>
      <PageHeader title="Compliance & Security Goals"
        subtitle="NIST CSF 2.0, ISO 27001:2022, and GDPR readiness, security goals, and the audit roadmap" />

      <div className="grid g-3">
        {d.frameworks.map((f: any) => (
          <button key={f.framework} className="card" onClick={() => setFw(f.framework)}
            style={{ textAlign: 'left', cursor: 'pointer', outline: f.framework === selected ? '2px solid var(--accent)' : 'none' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
              <div className="card-title">{f.framework}</div>
              <div style={{ fontSize: 26, fontWeight: 650, color: pctColor(f.pct) }}>{f.pct}%</div>
            </div>
            <div style={{ margin: '8px 0' }}><Meter value={f.pct} color={pctColor(f.pct)} /></div>
            <div className="muted" style={{ fontSize: 12 }}>
              {f.implemented} implemented · {f.partial} partial · {f.not_implemented} gaps · {f.total} controls
            </div>
          </button>
        ))}
      </div>

      {framework && (
        <div className="grid g-3 mt">
          <Card title={`${framework.framework} by area`}>
            {framework.families.map((f: any) => (
              <div className="comp-row" key={f.family} style={{ gridTemplateColumns: '150px 1fr 48px' }}>
                <div className="lbl">{f.family}<small>{f.total} controls</small></div>
                <Meter value={f.pct} color={pctColor(f.pct)} />
                <div className="val">{Math.round(f.pct)}%</div>
              </div>
            ))}
          </Card>
          <Card className="span-2" title={`${framework.framework} controls`} subtitle="Update manual attestation status inline"
            action={<MetricLink metric="compliance" params={{ framework: framework.framework }} className="btn btn-sm">How is {framework.pct}% calculated?</MetricLink>}>
            <ControlsTable controls={d.controls.filter((c: any) => c.framework === selected)} onChange={reload} />
          </Card>
        </div>
      )}

      <Goals goals={d.goals} metrics={d.goal_metrics} onChange={reload} />
      <Roadmap items={d.roadmap} onChange={reload} />
    </>
  )
}

function ControlsTable({ controls, onChange }: { controls: any[]; onChange: () => void }) {
  const { can } = useAuth()
  async function setStatus(id: number, status: string) {
    await patch(`/compliance/controls/${id}`, { status })
    onChange()
  }
  return (
    <div className="table-wrap" style={{ maxHeight: 420, overflowY: 'auto' }}>
      <table>
        <thead><tr><th>ID</th><th>Control</th><th>Owner</th><th>Status</th></tr></thead>
        <tbody>
          {controls.map((c) => (
            <tr key={c.id}>
              <td className="mono">{c.control_id}</td>
              <td>{c.name}{c.auto_rule && <div className="muted" style={{ fontSize: 11.5 }}><Zap size={11} color="var(--accent)" /> Auto-evaluated: {c.evidence}</div>}</td>
              <td className="text-2">{c.owner}</td>
              <td>
                {c.auto_rule || !can('edit_compliance') ? (
                  <span className="badge"><span className="sw" style={{ background: STATUS_COLOR[c.status] }} />{cap(c.status.replace('_', ' '))}</span>
                ) : (
                  <select className="select" value={c.status} onChange={(e) => setStatus(c.id, e.target.value)} aria-label={`Status of ${c.control_id}`}
                    style={{ borderLeft: `4px solid ${STATUS_COLOR[c.status]}`, padding: '4px 8px' }}>
                    <option value="implemented">Implemented</option>
                    <option value="partial">Partial</option>
                    <option value="not_implemented">Not implemented</option>
                  </select>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Goals({ goals, metrics, onChange }: { goals: any[]; metrics: Record<string, any>; onChange: () => void }) {
  const [editing, setEditing] = useState<any>(null)
  const edit = useAuth().can('edit_compliance')
  return (
    <Card className="mt" title="Security goals" subtitle="Progress is measured from live dashboard metrics, not self-reported"
      action={edit ? <button className="btn btn-sm" onClick={() => setEditing({})}><Plus size={14} /> Add goal</button> : undefined}>
      <div className="grid g-3">
        {goals.map((g) => (
          <div key={g.id} style={{ background: 'var(--surface-2)', borderRadius: 4, padding: '12px 14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
              <div style={{ fontWeight: 600, fontSize: 13.5 }}>{g.title}</div>
              {edit && <button className="btn btn-ghost btn-sm" onClick={() => setEditing(g)} aria-label="Edit goal"><Pencil size={13} /></button>}
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, margin: '6px 0' }}>
              <span style={{ fontSize: 22, fontWeight: 650 }}>{g.current ?? '—'}</span>
              <span className="muted" style={{ fontSize: 12 }}>{g.unit} now · target {g.direction === 'lower' ? '≤' : '≥'} {g.target}</span>
            </div>
            <Meter value={g.progress} color={g.met ? 'var(--good)' : 'var(--s1)'} />
            <div className="muted" style={{ fontSize: 11.5, marginTop: 6 }}>
              {g.met ? <span className="delta-good">Target met</span> : `${g.progress}% of the way from baseline ${g.baseline}`} · {g.owner} · due {fmtDate(g.due_date)}
            </div>
          </div>
        ))}
      </div>
      {editing && <GoalForm goal={editing} metrics={metrics} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); onChange() }} />}
    </Card>
  )
}

function GoalForm({ goal, metrics, onClose, onSaved }: any) {
  const [f, setF] = useState({
    title: goal.title ?? '', metric_key: goal.metric_key ?? Object.keys(metrics)[0], baseline: goal.baseline ?? 0, target: goal.target ?? 0,
    direction: goal.direction ?? 'lower', due_date: goal.due_date ?? new Date().toISOString().slice(0, 10), owner: goal.owner ?? '',
  })
  const [err, setErr] = useState<string | null>(null)
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.value })
  async function save() {
    try {
      const body = { ...f, baseline: Number(f.baseline), target: Number(f.target) }
      goal.id ? await put(`/compliance/goals/${goal.id}`, body) : await post('/compliance/goals', body)
      onSaved()
    } catch (e: any) { setErr(e.message) }
  }
  async function remove() { await del(`/compliance/goals/${goal.id}`); onSaved() }
  return (
    <Modal title={goal.id ? 'Edit goal' : 'New security goal'} onClose={onClose}>
      <div className="form-grid">
        <label className="field full">Goal<input className="input" value={f.title} onChange={set('title')} /></label>
        <label className="field full">Measured by
          <select className="select" value={f.metric_key} onChange={set('metric_key')}>
            {Object.entries(metrics).map(([k, m]: any) => <option key={k} value={k}>{m.label} ({m.unit})</option>)}
          </select>
        </label>
        <label className="field">Baseline<input className="input" type="number" value={f.baseline} onChange={set('baseline')} /></label>
        <label className="field">Target<input className="input" type="number" value={f.target} onChange={set('target')} /></label>
        <label className="field">Better when
          <select className="select" value={f.direction} onChange={set('direction')}><option value="lower">Lower</option><option value="higher">Higher</option></select>
        </label>
        <label className="field">Due date<input className="input" type="date" value={f.due_date} onChange={set('due_date')} /></label>
        <label className="field full">Owner<input className="input" value={f.owner} onChange={set('owner')} /></label>
      </div>
      {err && <div className="delta-bad" style={{ marginTop: 10, fontSize: 13 }}>{err}</div>}
      <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
        {goal.id && <button className="btn btn-danger" onClick={remove}><Trash2 size={14} /> Delete</button>}
        <div style={{ flex: 1 }} />
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" onClick={save}>Save</button>
      </div>
    </Modal>
  )
}

function Roadmap({ items, onChange }: { items: any[]; onChange: () => void }) {
  const [editing, setEditing] = useState<any>(null)
  const edit = useAuth().can('edit_compliance')
  const today = new Date()
  const start = new Date(today.getFullYear(), today.getMonth() - 1, 1)
  const end = new Date(today.getFullYear(), today.getMonth() + 5, 1)
  const span = end.getTime() - start.getTime()
  const pos = (s: string) => Math.max(0, Math.min(100, ((new Date(s + 'T00:00:00').getTime() - start.getTime()) / span) * 100))
  const months = Array.from({ length: 6 }, (_, i) => new Date(start.getFullYear(), start.getMonth() + i, 1))

  return (
    <Card className="mt" title="Audit & assessment roadmap" subtitle="Editable plan of upcoming audits, assessments, tests, and milestones"
      action={edit ? <button className="btn btn-sm btn-primary" onClick={() => setEditing({})}><Plus size={14} /> Add item</button> : undefined}>
      <div className="timeline">
        <div className="tl-row" style={{ paddingBottom: 0 }}>
          <div />
          <div className="tl-scale" style={{ gridTemplateColumns: 'repeat(6, 1fr)' }}>
            {months.map((m) => <span key={m.toISOString()}>{m.toLocaleDateString(undefined, { month: 'short', year: '2-digit' })}</span>)}
          </div>
        </div>
        {items.map((it) => (
          <div className="tl-row" key={it.id}>
            <div style={{ fontSize: 12.5, cursor: edit ? 'pointer' : 'default' }} onClick={edit ? () => setEditing(it) : undefined}>
              <div style={{ fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{it.title}</div>
              <div className="muted" style={{ fontSize: 11 }}>{ROAD_STATUS[it.status]} · {it.owner}</div>
            </div>
            <div className="tl-track">
              <div className="tl-today" style={{ left: `${pos(today.toISOString().slice(0, 10))}%` }} />
              <div className="tl-bar" title={`${it.title}: ${fmtDate(it.start_date)} – ${fmtDate(it.due_date)}`}
                style={{
                  left: `${pos(it.start_date)}%`, width: `${Math.max(1, pos(it.due_date) - pos(it.start_date))}%`,
                  background: ITEM_COLOR[it.item_type], opacity: it.status === 'complete' ? 0.4 : 1,
                  outline: it.status === 'at_risk' ? '2px solid var(--critical)' : 'none',
                }} />
            </div>
          </div>
        ))}
      </div>
      <div className="legend" style={{ marginTop: 10 }}>
        {Object.entries(ITEM_COLOR).map(([k, c]) => <span key={k}><i style={{ background: c }} />{cap(k.replace('_', ' '))}</span>)}
        <span><i style={{ background: 'transparent', outline: '2px solid var(--critical)' }} />At risk</span>
        <span><i style={{ background: 'var(--critical)', width: 2 }} />Today</span>
      </div>

      <div className="table-wrap mt">
        <table>
          <thead><tr><th>Item</th><th>Type</th><th>Framework</th><th>Dates</th><th>Owner</th><th>Status</th><th /></tr></thead>
          <tbody>
            {items.map((it) => (
              <tr key={it.id}>
                <td>{it.title}{it.notes && <div className="muted" style={{ fontSize: 11.5 }}>{it.notes}</div>}</td>
                <td><span className="badge"><span className="sw" style={{ background: ITEM_COLOR[it.item_type] }} />{cap(it.item_type.replace('_', ' '))}</span></td>
                <td className="text-2">{it.framework || '—'}</td>
                <td style={{ whiteSpace: 'nowrap' }}>{fmtDate(it.start_date)} – {fmtDate(it.due_date)}</td>
                <td className="text-2">{it.owner}</td>
                <td className={it.status === 'at_risk' ? 'delta-bad' : it.status === 'complete' ? 'delta-good' : ''}>{ROAD_STATUS[it.status]}</td>
                <td>{edit && <button className="btn btn-ghost btn-sm" onClick={() => setEditing(it)} aria-label="Edit"><Pencil size={13} /></button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {editing && <RoadmapForm item={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); onChange() }} />}
    </Card>
  )
}

function RoadmapForm({ item, onClose, onSaved }: any) {
  const iso = (d: Date) => d.toISOString().slice(0, 10)
  const [f, setF] = useState({
    title: item.title ?? '', item_type: item.item_type ?? 'audit', framework: item.framework ?? '',
    start_date: item.start_date ?? iso(new Date()), due_date: item.due_date ?? iso(new Date(Date.now() + 14 * 864e5)),
    owner: item.owner ?? '', status: item.status ?? 'planned', notes: item.notes ?? '',
  })
  const [err, setErr] = useState<string | null>(null)
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.value })
  async function save() {
    try {
      const body = { ...f, framework: f.framework || null, notes: f.notes || null }
      item.id ? await put(`/compliance/roadmap/${item.id}`, body) : await post('/compliance/roadmap', body)
      onSaved()
    } catch (e: any) { setErr(e.message) }
  }
  async function remove() {
    if (!confirm(`Delete "${item.title}"?`)) return
    await del(`/compliance/roadmap/${item.id}`)
    onSaved()
  }
  return (
    <Modal title={item.id ? 'Edit roadmap item' : 'New roadmap item'} onClose={onClose}>
      <div className="form-grid">
        <label className="field full">Title<input className="input" value={f.title} onChange={set('title')} /></label>
        <label className="field">Type
          <select className="select" value={f.item_type} onChange={set('item_type')}>
            {Object.keys(ITEM_COLOR).map((k) => <option key={k} value={k}>{cap(k.replace('_', ' '))}</option>)}
          </select>
        </label>
        <label className="field">Framework<input className="input" value={f.framework} onChange={set('framework')} placeholder="e.g. SOC 2" /></label>
        <label className="field">Start<input className="input" type="date" value={f.start_date} onChange={set('start_date')} /></label>
        <label className="field">Due<input className="input" type="date" value={f.due_date} onChange={set('due_date')} /></label>
        <label className="field">Owner<input className="input" value={f.owner} onChange={set('owner')} /></label>
        <label className="field">Status
          <select className="select" value={f.status} onChange={set('status')}>
            {Object.entries(ROAD_STATUS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </label>
        <label className="field full">Notes<textarea className="input" rows={3} value={f.notes} onChange={set('notes')} /></label>
      </div>
      {err && <div className="delta-bad" style={{ marginTop: 10, fontSize: 13 }}>{err}</div>}
      <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
        {item.id && <button className="btn btn-danger" onClick={remove}><Trash2 size={14} /> Delete</button>}
        <div style={{ flex: 1 }} />
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" onClick={save}>Save</button>
      </div>
    </Modal>
  )
}
