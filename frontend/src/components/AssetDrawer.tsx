import { createContext, useContext, useState, type ReactNode } from 'react'
import { Globe, X } from 'lucide-react'
import { useApi } from '../api'
import { TOOL_NAME, cap, fmtDate } from '../format'
import { TicketButton } from './Tickets'
import { ErrorBox, Loading, SevBadge, nextOverlayZ } from './ui'

const Ctx = createContext<(id: number) => void>(() => {})
const StateCtx = createContext<{ open: { id: number; z: number } | null; close: () => void }>({ open: null, close: () => {} })
export const useAssetDrawer = () => useContext(Ctx)

/** Drill-down from any metric to the affected asset and its findings/alerts.
 *  State lives here; <AssetDrawerHost/> renders it (inside the other providers it depends on). */
export function AssetDrawerProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState<{ id: number; z: number } | null>(null)
  return (
    <Ctx.Provider value={(id) => setOpen({ id, z: nextOverlayZ() })}>
      <StateCtx.Provider value={{ open, close: () => setOpen(null) }}>{children}</StateCtx.Provider>
    </Ctx.Provider>
  )
}

export function AssetDrawerHost() {
  const { open, close } = useContext(StateCtx)
  return open ? <AssetDrawer id={open.id} z={open.z} onClose={close} /> : null
}

function AssetDrawer({ id, z, onClose }: { id: number; z: number; onClose: () => void }) {
  const { data: a, error } = useApi<any>(`/assets/${id}`)
  const open = a?.findings.filter((f: any) => f.status === 'open' || f.status === 'in_progress') ?? []
  return (
    <div className="overlay" style={{ zIndex: z }} onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <aside className="drawer" role="dialog" aria-label="Asset details">
        <div className="card-head">
          <div>
            <div className="card-sub">Asset</div>
            <h2 style={{ fontSize: 20 }}>{a?.hostname ?? '…'}</h2>
          </div>
          <button className="btn btn-ghost" onClick={onClose} aria-label="Close"><X size={18} /></button>
        </div>
        {error && <ErrorBox error={error} />}
        {!a && !error && <Loading />}
        {a && (
          <>
            <div className="grid g-3" style={{ marginBottom: 16 }}>
              <div className="card"><div className="kpi-label">Criticality</div><div className="kpi-value">{a.criticality}<small>/5</small></div></div>
              <div className="card"><div className="kpi-label">Open findings</div><div className="kpi-value">{open.length}</div></div>
              <div className="card"><div className="kpi-label">EDR sensor</div><div className="kpi-value" style={{ fontSize: 18, paddingTop: 6 }}>{a.edr_status === 'missing' ? 'Not installed' : a.edr_status === 'rfm' ? 'Degraded' : a.edr_status === 'n/a' ? 'N/A' : 'Healthy'}</div></div>
            </div>
            <div className="card" style={{ marginBottom: 16 }}>
              <table>
                <tbody>
                  <tr><td className="muted">OS</td><td>{a.os}</td><td className="muted">IP</td><td className="mono">{a.ip}</td></tr>
                  <tr><td className="muted">Business unit</td><td>{a.business_unit}</td><td className="muted">Owner</td><td>{a.owner}</td></tr>
                  <tr><td className="muted">Environment</td><td>{a.environment?.toUpperCase()}</td><td className="muted">Exposure</td>
                    <td>{a.internet_facing ? <span className="badge badge-kev"><Globe size={11} /> Internet-facing</span> : 'Internal'}</td></tr>
                  <tr><td className="muted">Software</td><td colSpan={3}><div className="chips">{a.software.map((s: string) => <span key={s} className="badge">{s}</span>)}</div></td></tr>
                </tbody>
              </table>
            </div>
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title" style={{ marginBottom: 8 }}>Vulnerabilities</div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Severity</th><th>Finding</th><th>Source</th><th>Status</th><th>Due</th><th>Ticket</th></tr></thead>
                  <tbody>
                    {a.findings.map((f: any) => (
                      <tr key={f.id}>
                        <td><SevBadge sev={f.severity} /></td>
                        <td>
                          <div>{f.title}</div>
                          <div className="chips" style={{ marginTop: 4 }}>
                            {f.cve && <span className="mono muted">{f.cve}</span>}
                            {f.in_kev && <span className="badge badge-kev">KEV</span>}
                          </div>
                        </td>
                        <td>{TOOL_NAME[f.source]}</td>
                        <td>{cap(f.status.replace('_', ' '))}</td>
                        <td className={f.status !== 'remediated' && f.due_date < new Date().toISOString().slice(0, 10) ? 'delta-bad' : ''}>{fmtDate(f.due_date)}</td>
                        <td>{(f.ticket || f.status === 'open' || f.status === 'in_progress')
                          ? <TicketButton compact ticket={f.ticket} src={{ source_type: 'finding', finding_id: f.id }} /> : <span className="muted">—</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 8 }}>Recent alerts</div>
              {a.alerts.length === 0 ? <div className="empty">No alerts on this asset</div> : (
                <table>
                  <tbody>
                    {a.alerts.map((al: any) => (
                      <tr key={al.id}><td><SevBadge sev={al.severity} /></td><td>{al.title}<div className="muted" style={{ fontSize: 12 }}>{al.technique}</div></td>
                        <td>{TOOL_NAME[al.source]}</td><td className="muted">{fmtDate(al.detected_at)}</td></tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </>
        )}
      </aside>
    </div>
  )
}
