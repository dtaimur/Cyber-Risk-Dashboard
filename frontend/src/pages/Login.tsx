import { useState } from 'react'
import { Lock } from 'lucide-react'
import { useAuth } from '../auth'
import { Spinner } from '../components/ui'

export default function Login() {
  const { login } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true); setError(null)
    try { await login(username, password) }
    catch (err: any) { setError(err.message || 'Sign-in failed') }
    finally { setBusy(false) }
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 22 }}>
          <div className="brand-mark" aria-hidden>CR</div>
          <div style={{ fontWeight: 600, fontSize: 15 }}>Cyber Risk</div>
        </div>
        <h1 style={{ fontSize: 17, fontWeight: 600, marginBottom: 4 }}>Sign in</h1>
        <p className="muted" style={{ margin: '0 0 18px', fontSize: 12.5 }}>Authorized users only. Sign-in activity is logged.</p>
        <label className="field">Username
          <input className="input" autoComplete="username" autoFocus value={username} onChange={(e) => setUsername(e.target.value)} required />
        </label>
        <label className="field" style={{ marginTop: 12 }}>Password
          <input className="input" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </label>
        {error && <div className="login-error" role="alert">{error}</div>}
        <button className="btn btn-primary" type="submit" disabled={busy} style={{ width: '100%', justifyContent: 'center', marginTop: 18, padding: '9px 12px' }}>
          {busy ? <Spinner /> : <Lock size={14} />} Sign in
        </button>
      </form>
    </div>
  )
}
