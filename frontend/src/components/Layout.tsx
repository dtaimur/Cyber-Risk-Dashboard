import { useEffect, useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import {
  Bell, Bot, Bug, ClipboardCheck, FileText, Gauge, KanbanSquare, LogOut, Moon, Newspaper, Plug, Radar, RefreshCw, Sun, Users,
} from 'lucide-react'
import { post, useApi } from '../api'
import { useAuth } from '../auth'
import { TOOL_NAME } from '../format'
import { Spinner } from './ui'

const TOOLS = ['qualys', 'crowdstrike', 'expel', 'wiz']

function getTheme() {
  try { return localStorage.getItem('dashboard-theme-v2') || 'light' } catch { return 'light' }
}

export default function Layout() {
  const [theme, setTheme] = useState(getTheme)
  const [refreshing, setRefreshing] = useState(false)
  const [refreshedAt, setRefreshedAt] = useState<Date | null>(null)
  const { user, can, logout } = useAuth()
  const { data: status } = useApi<{ modes: Record<string, string> }>('/status')
  const modes = status?.modes || {}
  const initials = (user?.display_name || '').split(' ').map((w) => w[0]).join('').slice(0, 2)

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try { localStorage.setItem('dashboard-theme-v2', theme) } catch { /* storage unavailable */ }
  }, [theme])

  async function refreshFeeds() {
    setRefreshing(true)
    try {
      await post('/threats/refresh')
      setRefreshedAt(new Date())
      window.dispatchEvent(new Event('dashboard:refresh'))
    } finally {
      setRefreshing(false)
    }
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark" aria-hidden>CR</div>
          <div className="brand-name">Cyber Risk</div>
        </div>

        <NavLink to="/" end className="nav-link"><Gauge size={17} />Executive Summary</NavLink>
        {can('use_assistant') && <NavLink to="/assistant" className="nav-link"><Bot size={17} />AI Analyst</NavLink>}

        {can('view_details') && <div className="nav-group">
          <div className="nav-label">Vulnerabilities</div>
          <NavLink to="/vulnerabilities" end className="nav-link"><Bug size={17} />Overview</NavLink>
          {TOOLS.map((t) => (
            <NavLink key={t} to={`/vulnerabilities/${t}`} className="nav-link nav-sub">
              {TOOL_NAME[t]}
              {modes[t] === 'live' && <span className="dot" title="Live API connection" style={{ background: 'var(--good)' }} />}
            </NavLink>
          ))}
          <NavLink to="/vulnerabilities/jira" className="nav-link"><KanbanSquare size={17} />Jira Remediation
            {modes.jira === 'live' && <span className="dot" title="Live API connection" style={{ background: 'var(--good)', marginLeft: 'auto' }} />}
          </NavLink>
        </div>}

        <div className="nav-group">
          <div className="nav-label">Threats</div>
          <NavLink to="/threats/news" className="nav-link"><Newspaper size={17} />Threat News</NavLink>
          {can('view_details') && <NavLink to="/threats/active" className="nav-link"><Radar size={17} />Active Threats</NavLink>}
        </div>

        <div className="nav-group">
          <div className="nav-label">Operations</div>
          {can('view_details') && <NavLink to="/alerts" className="nav-link"><Bell size={17} />Alerts &amp; Forensics</NavLink>}
          <NavLink to="/report" className="nav-link"><FileText size={17} />Executive Report</NavLink>
          <NavLink to="/compliance" className="nav-link"><ClipboardCheck size={17} />Compliance &amp; Goals</NavLink>
        </div>

        {(can('manage_integrations') || can('view_audit')) && <div className="nav-group">
          <div className="nav-label">Settings</div>
          {can('manage_integrations') && <NavLink to="/settings/integrations" className="nav-link"><Plug size={17} />API Integrations</NavLink>}
          {can('view_audit') && <NavLink to="/settings/access" className="nav-link"><Users size={17} />Access &amp; Audit</NavLink>}
        </div>}

        <div className="sidebar-foot">
          <span className="live-dot" /> Live data connection
        </div>
      </aside>

      <div className="main">
        <header className="topbar no-print">
          <span className="muted" style={{ fontSize: 13 }}>
            {new Date().toLocaleDateString(undefined, { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' })}
          </span>
          <div className="spacer" />
          {refreshedAt && <span className="muted" style={{ fontSize: 12 }}>Feeds refreshed {refreshedAt.toLocaleTimeString()}</span>}
          {can('refresh_feeds') && (
            <button className="btn btn-sm" onClick={refreshFeeds} disabled={refreshing}>
              {refreshing ? <Spinner /> : <RefreshCw size={14} />} Refresh threat intel
            </button>
          )}
          <button className="btn btn-sm" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            aria-label="Toggle color theme">
            {theme === 'dark' ? <Sun size={14} /> : <Moon size={14} />}
          </button>
          <div className="user-chip">
            <div className="avatar" aria-hidden>{initials}</div>
            <div style={{ lineHeight: 1.2 }}>
              <div style={{ fontSize: 13, fontWeight: 600 }}>{user?.display_name}</div>
              <div className="muted" style={{ fontSize: 11.5 }}>{user?.role_label}</div>
            </div>
            <button className="btn btn-sm btn-ghost" onClick={logout} aria-label="Sign out" title="Sign out"><LogOut size={15} /></button>
          </div>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
