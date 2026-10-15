import { useState } from 'react'
import { CheckCircle2, ExternalLink, KeyRound, Lock, RefreshCw, XCircle } from 'lucide-react'
import { post, put, useApi } from '../api'
import { timeAgo } from '../format'
import { Card, ErrorBox, Loading, ModeBadge, Modal, PageHeader, Spinner } from '../components/ui'

export default function Integrations() {
  const { data, error, reload } = useApi<any[]>('/integrations')
  const [configuring, setConfiguring] = useState<any>(null)
  if (error) return <ErrorBox error={error} onRetry={reload} />
  if (!data) return <Loading />
  const tools = data.filter((i) => i.kind === 'security_tool')
  const ticketing = data.filter((i) => i.kind === 'ticketing')
  const feeds = data.filter((i) => i.kind === 'threat_feed')

  return (
    <>
      <PageHeader title="API Integrations"
        subtitle="Vendor API connections. Credentials are encrypted at rest and never returned to the browser." />

      <h3 style={{ fontSize: 14, margin: '0 0 10px' }}>Security tools</h3>
      <div className="grid g-2">
        {tools.map((i) => <IntegrationCard key={i.id} i={i} onConfigure={() => setConfiguring(i)} onChange={reload} />)}
      </div>

      <h3 style={{ fontSize: 14, margin: '24px 0 10px' }}>Ticketing <span className="muted" style={{ fontWeight: 400 }}>— remediation workflow</span></h3>
      <div className="grid g-2">
        {ticketing.map((i) => <IntegrationCard key={i.id} i={i} onConfigure={() => setConfiguring(i)} onChange={reload} />)}
      </div>

      <h3 style={{ fontSize: 14, margin: '24px 0 10px' }}>Threat intelligence feeds <span className="muted" style={{ fontWeight: 400 }}>— public sources, no credentials required</span></h3>
      <div className="grid g-3">
        {feeds.map((i) => <IntegrationCard key={i.id} i={i} onChange={reload} />)}
      </div>
      {configuring && <ConfigureModal i={configuring} onClose={() => setConfiguring(null)} onSaved={() => { setConfiguring(null); reload() }} />}
    </>
  )
}

function IntegrationCard({ i, onConfigure, onChange }: { i: any; onConfigure?: () => void; onChange: () => void }) {
  const [busy, setBusy] = useState<string | null>(null)
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null)

  async function run(action: 'test' | 'sync') {
    setBusy(action); setResult(null)
    try {
      const r = await post(`/integrations/${i.id}/${action}`)
      setResult({ ok: r.ok, message: r.message || r.error || (r.ok ? `Synced ${r.count ?? ''} records` : 'Failed') })
      onChange()
    } catch (e: any) { setResult({ ok: false, message: e.message }) }
    finally { setBusy(null) }
  }
  async function toggle() {
    await put(`/integrations/${i.id}`, { enabled: !i.enabled })
    onChange()
  }

  return (
    <Card title={i.name} subtitle={i.description}
      action={i.kind !== 'threat_feed' ? <ModeBadge mode={i.data_mode} /> : (i.enabled ? <span className="badge badge-live"><span className="live-dot" />Live</span> : <span className="badge">Disabled</span>)}>
      <div className="muted" style={{ fontSize: 12, marginBottom: 10 }}>
        {i.last_sync ? <>Last sync {timeAgo(i.last_sync)} · {i.last_status === 'ok' ? <span className="delta-good">{i.last_message}</span> : <span className="delta-bad">{i.last_message}</span>}</>
          : 'Never synced'}
        {i.kind !== 'threat_feed' && <> · {i.has_secret ? <><Lock size={11} /> Credential stored</> : 'No credential'}</>}
      </div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        {onConfigure && <button className="btn btn-sm btn-primary" onClick={onConfigure}><KeyRound size={13} /> Configure</button>}
        {(i.kind === 'threat_feed' || i.has_secret) && (
          <>
            {i.kind !== 'threat_feed' && <button className="btn btn-sm" onClick={() => run('test')} disabled={!!busy}>{busy === 'test' ? <Spinner /> : null} Test connection</button>}
            <button className="btn btn-sm" onClick={() => run('sync')} disabled={!!busy || !i.enabled}>{busy === 'sync' ? <Spinner /> : <RefreshCw size={13} />} Sync now</button>
          </>
        )}
        <label style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 12.5, marginLeft: 'auto' }}>
          <input type="checkbox" checked={i.enabled} onChange={toggle} /> Enabled
        </label>
        <a href={i.docs_url} target="_blank" rel="noopener noreferrer" className="btn btn-sm btn-ghost" aria-label="API documentation"><ExternalLink size={13} /></a>
      </div>
      {result && (
        <div style={{ marginTop: 10, fontSize: 12.5, display: 'flex', gap: 6, alignItems: 'center' }} className={result.ok ? 'delta-good' : 'delta-bad'}>
          {result.ok ? <CheckCircle2 size={14} /> : <XCircle size={14} />} {result.message}
        </div>
      )}
    </Card>
  )
}

function ConfigureModal({ i, onClose, onSaved }: { i: any; onClose: () => void; onSaved: () => void }) {
  const [config, setConfig] = useState<Record<string, string>>(i.config || {})
  const [secret, setSecret] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  async function save() {
    setSaving(true); setErr(null)
    try {
      await put(`/integrations/${i.id}`, { enabled: true, config, ...(secret ? { secret } : {}) })
      onSaved()
    } catch (e: any) { setErr(e.message) }
    finally { setSaving(false) }
  }

  return (
    <Modal title={`Connect ${i.name}`} onClose={onClose}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {i.fields.map((f: any) => f.secret ? (
          <label key={f.key} className="field">{f.label}
            <input className="input" type="password" autoComplete="new-password" value={secret} onChange={(e) => setSecret(e.target.value)}
              placeholder={i.has_secret ? '•••••••• (stored — leave blank to keep)' : f.placeholder} />
          </label>
        ) : (
          <label key={f.key} className="field">{f.label}
            <input className="input" value={config[f.key] || ''} placeholder={f.placeholder} onChange={(e) => setConfig({ ...config, [f.key]: e.target.value })} />
          </label>
        ))}
        <div className="muted" style={{ fontSize: 12, display: 'flex', gap: 6 }}>
          <Lock size={13} style={{ flexShrink: 0, marginTop: 2 }} />
          The secret is encrypted before it is written to the database and is only decrypted server-side when calling {i.name}. Only HTTPS endpoints are accepted.
        </div>
        {err && <div className="delta-bad" style={{ fontSize: 13 }}>{err}</div>}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={save} disabled={saving}>{saving && <Spinner />} Save &amp; enable</button>
        </div>
      </div>
    </Modal>
  )
}
