import type { ReactNode } from 'react'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { ShieldOff } from 'lucide-react'
import { AuthProvider, useAuth } from './auth'
import { AssetDrawerHost, AssetDrawerProvider } from './components/AssetDrawer'
import Layout from './components/Layout'
import { MetricDrawerProvider } from './components/Metric'
import { TicketHost, TicketProvider } from './components/Tickets'
import { Spinner } from './components/ui'
import Access from './pages/Access'
import Assistant from './pages/Assistant'
import ActiveThreats from './pages/ActiveThreats'
import Alerts from './pages/Alerts'
import Compliance from './pages/Compliance'
import ExecutiveReport from './pages/ExecutiveReport'
import ExecutiveSummary from './pages/ExecutiveSummary'
import Integrations from './pages/Integrations'
import Login from './pages/Login'
import Remediation from './pages/Remediation'
import ThreatNews from './pages/ThreatNews'
import ToolPage from './pages/ToolPage'
import VulnOverview from './pages/VulnOverview'

/** Client-side guard for a better experience; the API enforces the same rule. */
function Guard({ perm, children }: { perm: string; children: ReactNode }) {
  const { can, user } = useAuth()
  if (can(perm)) return <>{children}</>
  return (
    <div className="restricted card">
      <ShieldOff size={28} color="var(--muted)" />
      <h2 style={{ fontSize: 18, margin: '10px 0 6px' }}>Access restricted</h2>
      <p className="text-2" style={{ margin: 0 }}>
        Your role ({user?.role_label}) does not include this view. Contact an administrator if you need access.
      </p>
    </div>
  )
}

function Shell() {
  const { user, loading } = useAuth()
  if (loading) return <div className="login-wrap"><Spinner size={20} /></div>
  if (!user) return <Login />
  return (
    <AssetDrawerProvider>
      <TicketProvider>
      <MetricDrawerProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<Guard perm="view_summary"><ExecutiveSummary /></Guard>} />
            <Route path="assistant" element={<Guard perm="use_assistant"><Assistant /></Guard>} />
            <Route path="vulnerabilities" element={<Guard perm="view_details"><VulnOverview /></Guard>} />
            <Route path="vulnerabilities/jira" element={<Guard perm="view_details"><Remediation /></Guard>} />
            <Route path="vulnerabilities/:tool" element={<Guard perm="view_details"><ToolPage /></Guard>} />
            <Route path="threats/news" element={<Guard perm="view_threat_intel"><ThreatNews /></Guard>} />
            <Route path="threats/active" element={<Guard perm="view_details"><ActiveThreats /></Guard>} />
            <Route path="alerts" element={<Guard perm="view_details"><Alerts /></Guard>} />
            <Route path="report" element={<Guard perm="generate_report"><ExecutiveReport /></Guard>} />
            <Route path="compliance" element={<Guard perm="view_compliance"><Compliance /></Guard>} />
            <Route path="settings/integrations" element={<Guard perm="manage_integrations"><Integrations /></Guard>} />
            <Route path="settings/access" element={<Guard perm="view_audit"><Access /></Guard>} />
            <Route path="*" element={<div className="empty">Page not found</div>} />
          </Route>
        </Routes>
      </MetricDrawerProvider>
      <AssetDrawerHost />
      <TicketHost />
      </TicketProvider>
    </AssetDrawerProvider>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Shell />
      </AuthProvider>
    </BrowserRouter>
  )
}
