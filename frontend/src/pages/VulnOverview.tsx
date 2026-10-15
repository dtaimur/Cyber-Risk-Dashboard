import { Link } from 'react-router-dom'
import { useApi } from '../api'
import { SEVS, TOOL_NAME, cap } from '../format'
import { AgingChart, FindingsTable, NewVsRemediated, SeverityTrend, TopAssets } from '../components/charts'
import { Card, ErrorBox, Loading, ModeBadge, PageHeader } from '../components/ui'
import { Kpi } from '../components/Metric'

export default function VulnOverview() {
  const { data: d, error, reload } = useApi<any>('/vulnerabilities/overview')
  if (error) return <ErrorBox error={error} onRetry={reload} />
  if (!d) return <Loading />
  const m = d.metrics

  return (
    <>
      <PageHeader title="Vulnerability Management"
        subtitle="Open findings across Qualys, CrowdStrike Spotlight, and Wiz" />

      <div className="grid g-6">
        <Kpi label="Open findings" metric="open_findings" value={m.open_total} foot={`${m.affected_assets} affected assets`} />
        <Kpi label="Critical" metric="open_critical" value={m.by_severity.critical} tone={m.by_severity.critical ? 'bad' : 'good'} foot={`${m.by_severity.high} high`} />
        <Kpi label="Actively exploited (KEV)" metric="kev_open" value={m.kev_open} tone={m.kev_open ? 'bad' : 'good'} foot="Distinct CVEs on CISA KEV" />
        <Kpi label="Critical/high within SLA" metric="sla_compliance" value={m.sla_compliance} unit="%" foot={`${m.crit_high_overdue} past due`} />
        <Kpi label="Critical MTTR" metric="crit_mttr_days" value={m.mttr_days.critical} unit=" days" foot="Target ≤ 15 days" tone={m.mttr_days.critical > 15 ? 'bad' : 'good'} />
        <Kpi label="Fixed on time (90d)" metric="fixed_on_time" value={m.remediated_on_time_pct} unit="%" foot={`${m.remediated_90d} remediated`} />
      </div>

      <div className="grid g-3 mt">
        {d.by_source.map((s: any) => (
          <Card key={s.source} title={<Link to={`/vulnerabilities/${s.source}`}>{TOOL_NAME[s.source]}</Link>} action={<ModeBadge mode={d.modes[s.source]} />}>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px 16px', alignItems: 'flex-end' }}>
              <div><div className="kpi-value">{s.total}</div><div className="muted" style={{ fontSize: 12 }}>open</div></div>
              {SEVS.slice(0, 3).map((sev) => (
                <div key={sev}><div style={{ fontSize: 18, fontWeight: 600, paddingTop: 6 }}>{s[sev]}</div><div className="muted" style={{ fontSize: 12 }}>{cap(sev)}</div></div>
              ))}
              <div style={{ marginLeft: 'auto', textAlign: 'right', whiteSpace: 'nowrap' }}>
                <div style={{ fontSize: 18, fontWeight: 600, paddingTop: 6, color: s.overdue ? 'var(--bad-text)' : undefined }}>{s.overdue}</div>
                <div className="muted" style={{ fontSize: 12 }}>past SLA</div>
              </div>
            </div>
          </Card>
        ))}
      </div>

      <div className="grid g-3 mt">
        <SeverityTrend data={d.trend} />
        <NewVsRemediated data={d.trend} />
        <AgingChart data={d.aging} />
      </div>

      <div className="mt"><TopAssets data={d.top_assets} /></div>
      <div className="mt"><FindingsTable /></div>
    </>
  )
}
