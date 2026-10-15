import { Link, useParams } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, Cell, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Globe } from 'lucide-react'
import { useApi } from '../api'
import { SEVS, SEV_COLOR, TOOL_NAME, cap, fmtCategory, fmtDate } from '../format'
import { useAssetDrawer } from '../components/AssetDrawer'
import { AgingChart, FindingsTable, HBarList, NewVsRemediated, SeverityTrend, TopAssets } from '../components/charts'
import { Card, ChartTooltip, ErrorBox, Legend, Loading, ModeBadge, PageHeader, SevBadge, axisProps } from '../components/ui'
import { Kpi } from '../components/Metric'

const DESCRIPTIONS: Record<string, string> = {
  qualys: 'Qualys VMDR · host vulnerability scanning and coverage',
  crowdstrike: 'CrowdStrike Falcon · sensor health, Spotlight vulnerabilities, detections',
  expel: 'Expel MDR · alert triage, investigations, incidents',
  wiz: 'Wiz · cloud posture across AWS, Azure, and GCP',
}

export default function ToolPage() {
  const { tool = 'qualys' } = useParams()
  const { data: d, error, reload } = useApi<any>(`/tools/${tool}`)
  return (
    <>
      <PageHeader title={TOOL_NAME[tool] ?? tool} subtitle={DESCRIPTIONS[tool]}
        actions={<>{d && <ModeBadge mode={d.mode} />}<Link to="/settings/integrations" className="btn btn-sm">Configure API</Link></>} />
      {error && <ErrorBox error={error} onRetry={reload} />}
      {!d || d.tool !== tool ? (!error && <Loading />) : (
        tool === 'qualys' ? <Qualys d={d} /> : tool === 'crowdstrike' ? <CrowdStrike d={d} /> : tool === 'expel' ? <Expel d={d} /> : <Wiz d={d} />
      )}
    </>
  )
}

function TopVulns({ data }: { data: any[] }) {
  return (
    <Card title="Most widespread vulnerabilities" subtitle="Open findings grouped by vulnerability">
      <table>
        <thead><tr><th>Severity</th><th>Vulnerability</th><th className="num">Hosts</th></tr></thead>
        <tbody>
          {data.map((v) => (
            <tr key={v.title}>
              <td><SevBadge sev={v.severity} /></td>
              <td>{v.title}<div className="chips" style={{ marginTop: 3 }}>{v.cve && <span className="mono muted">{v.cve}</span>}{v.in_kev && <span className="badge badge-kev">KEV</span>}</div></td>
              <td className="num">{v.count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  )
}

function Qualys({ d }: { d: any }) {
  const k = d.kpis
  return (
    <>
      <div className="grid g-6">
        <Kpi label="Open detections" metric="open_findings" params={{ source: "qualys" }} value={k.open} foot={`${k.affected_hosts} hosts affected`} />
        <Kpi label="Severity 5 (Urgent)" metric="open_critical" params={{ source: "qualys" }} value={k.urgent} tone={k.urgent ? 'bad' : 'good'} foot={`${k.kev_open} on CISA KEV`} />
        <Kpi label="Scan coverage (30d)" metric="scan_coverage" value={k.scan_coverage} unit="%" foot={`${k.hosts_scanned_30d} hosts scanned`} />
        <Kpi label="Avg. QDS" metric="avg_qds" value={k.avg_qds} foot="Qualys Detection Score 1–100" />
        <Kpi label="Patch available" metric="patchable_pct" params={{ source: "qualys" }} value={k.patchable_pct} unit="%" foot="Of open detections" />
        <Kpi label="Critical/high within SLA" metric="sla_compliance" params={{ source: "qualys" }} value={k.sla_compliance} unit="%" foot={`Critical MTTR ${k.mttr_critical ?? '—'}d`} />
      </div>
      <div className="grid g-3 mt">
        <Card title="Detections by Qualys severity">
          <div style={{ height: 230 }}>
            <ResponsiveContainer>
              <BarChart data={d.severity} margin={{ top: 6, right: 8, left: -12, bottom: 0 }}>
                <CartesianGrid vertical={false} stroke="var(--grid)" />
                <XAxis dataKey="label" {...axisProps} />
                <YAxis {...axisProps} />
                <Tooltip cursor={{ fill: 'var(--surface-2)' }} content={<ChartTooltip />} />
                <Bar dataKey="count" name="Detections" radius={[4, 4, 0, 0]} isAnimationActive={false}>
                  {d.severity.map((s: any) => <Cell key={s.severity} fill={SEV_COLOR[s.severity]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title="Scan freshness" subtitle="Days since each host was last scanned">
          <div style={{ height: 230 }}>
            <ResponsiveContainer>
              <BarChart data={d.scan_age} margin={{ top: 6, right: 8, left: -12, bottom: 0 }}>
                <CartesianGrid vertical={false} stroke="var(--grid)" />
                <XAxis dataKey="bucket" {...axisProps} />
                <YAxis {...axisProps} />
                <Tooltip cursor={{ fill: 'var(--surface-2)' }} content={<ChartTooltip />} />
                <Bar dataKey="hosts" name="Hosts" radius={[4, 4, 0, 0]} isAnimationActive={false}>
                  {d.scan_age.map((s: any, i: number) => <Cell key={s.bucket} fill={i >= 3 ? 'var(--high)' : 'var(--s1)'} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="muted" style={{ fontSize: 12 }}>Hosts not scanned in 30+ days are coverage gaps (orange).</div>
        </Card>
        <AgingChart data={d.aging} />
      </div>
      <div className="grid g-2 mt">
        <SeverityTrend data={d.trend} />
        <NewVsRemediated data={d.trend} />
      </div>
      <div className="grid g-2 mt">
        <TopVulns data={d.top_vulns} />
        <TopAssets data={d.top_assets} title="Most vulnerable hosts" />
      </div>
      <div className="mt"><FindingsTable source="qualys" /></div>
    </>
  )
}

function CrowdStrike({ d }: { d: any }) {
  const k = d.kpis
  const open = useAssetDrawer()
  const statusColor: Record<string, string> = { normal: 'var(--good)', rfm: 'var(--medium)', missing: 'var(--critical)' }
  return (
    <>
      <div className="grid g-6">
        <Kpi label="Sensor coverage" metric="edr_coverage" value={k.edr_coverage} unit="%" foot={`${k.sensors_healthy} of ${k.managed_hosts} hosts healthy`} tone={k.edr_coverage < 95 ? 'bad' : 'good'} />
        <Kpi label="Hosts without sensor" metric="edr_missing" value={k.missing} tone={k.missing ? 'bad' : 'good'} foot={`${k.rfm} in reduced functionality`} />
        <Kpi label="Detections (30d)" metric="alerts" params={{ source: "crowdstrike", days: 30 }} value={k.detections_30d} foot={`${k.open_detections} open · ${k.prevented} auto-prevented`} />
        <Kpi label="Critical detection MTTR" metric="mttr_critical_alerts" params={{ source: "crowdstrike", days: 30 }} value={k.mttr_critical_hours} unit="h" foot="Detection to resolution" />
        <Kpi label="Spotlight vulnerabilities" metric="open_findings" params={{ source: "crowdstrike" }} value={k.spotlight_open} foot={`${k.spotlight_critical} critical`} />
        <Kpi label="Hosts in containment" metric="contained_hosts" value={k.contained} foot="Network-isolated by Falcon" />
      </div>
      <div className="grid g-3 mt">
        <Card title="Sensor health" subtitle="Managed hosts (excludes network devices)">
          {d.sensor_status.map((s: any) => (
            <div key={s.key} className="comp-row" style={{ gridTemplateColumns: '150px 1fr 50px' }}>
              <div className="lbl">{s.status}</div>
              <div className="meter" style={{ height: 10 }}><span style={{ width: `${(100 * s.count) / k.managed_hosts}%`, background: statusColor[s.key] }} /></div>
              <div className="val">{s.count}</div>
            </div>
          ))}
          <div className="card-sub" style={{ marginTop: 14, marginBottom: 6 }}>Unprotected hosts by environment</div>
          <HBarList data={d.missing_by_env} labelKey="environment" color="var(--critical)" format={(s) => s.toUpperCase()} />
          <div className="card-sub" style={{ marginTop: 14, marginBottom: 6 }}>Sensor versions</div>
          {d.sensor_versions.map((v: any) => (
            <div key={v.version} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12.5, padding: '2px 0' }}>
              <span className="mono">{v.version} {v.current && <span className="badge badge-live">current</span>}</span><span className="num">{v.count}</span>
            </div>
          ))}
        </Card>
        <Card title="Detections by MITRE ATT&CK tactic" subtitle="Last 30 days">
          <HBarList data={d.tactics} labelKey="tactic" color="var(--s1)" />
        </Card>
        <Card title="Most-detected hosts" subtitle="Last 30 days · click to drill down">
          <table>
            <tbody>
              {d.top_hosts.map((h: any) => (
                <tr key={h.asset_id} className="clickable" onClick={() => open(h.asset_id)}><td>{h.hostname}</td><td className="num">{h.count}</td></tr>
              ))}
            </tbody>
          </table>
          <div className="card-sub" style={{ marginTop: 14, marginBottom: 6 }}>Detections by severity</div>
          <HBarList data={d.detections_by_severity.map((s: any) => ({ ...s, severity: cap(s.severity) }))} labelKey="severity" color="var(--high)" />
        </Card>
      </div>
      <div className="grid g-2 mt">
        <SeverityTrend data={d.spotlight_trend} title="Spotlight vulnerabilities over time" />
        <TopVulns data={d.top_vulns} />
      </div>
      <div className="mt"><FindingsTable source="crowdstrike" /></div>
    </>
  )
}

function Expel({ d }: { d: any }) {
  const k = d.kpis
  const max = d.funnel[0].count || 1
  return (
    <>
      <div className="grid g-6">
        <Kpi label="Alerts triaged (30d)" metric="alerts" params={{ source: "expel", days: 30 }} value={k.alerts_30d} foot={`${k.open} still open`} />
        <Kpi label="Under investigation" metric="alerts_investigating" params={{ source: "expel", days: 30 }} value={k.investigating} />
        <Kpi label="Confirmed incidents (30d)" metric="incidents" params={{ source: "expel", days: 30 }} value={k.incidents_30d} tone={k.incidents_30d ? 'bad' : 'good'} />
        <Kpi label="Median time to detect" metric="mttd" params={{ source: "expel", days: 30 }} value={k.mttd_minutes} unit="min" foot="Event to alert" />
        <Kpi label="Critical MTTR" metric="mttr_critical_alerts" params={{ source: "expel", days: 30 }} value={k.mttr_critical} unit="h" foot={`High: ${k.mttr_high ?? '—'}h`} />
        <Kpi label="False positive rate" metric="false_positive_rate" params={{ source: "expel", days: 30 }} value={k.false_positive_rate} unit="%" foot="Of closed alerts" />
      </div>
      <div className="grid g-3 mt">
        <Card title="Triage funnel" subtitle="How MDR filters noise into real incidents (30d)">
          {d.funnel.map((f: any, i: number) => (
            <div key={f.stage} style={{ marginBottom: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 4 }}><span>{f.stage}</span><b>{f.count}</b></div>
              <div className="meter" style={{ height: 14 }}><span style={{ width: `${(100 * f.count) / max}%`, background: ['var(--s1)', 'var(--s2)', 'var(--critical)'][i] }} /></div>
            </div>
          ))}
        </Card>
        <Card title="Alert categories" subtitle="Last 30 days"><HBarList data={d.categories} labelKey="category" format={fmtCategory} /></Card>
        <Card title="Response time trend" subtitle="Mean hours to resolve, weekly">
          <div style={{ height: 200 }}>
            <ResponsiveContainer>
              <LineChart data={d.weekly} margin={{ top: 6, right: 8, left: -12, bottom: 0 }}>
                <CartesianGrid vertical={false} stroke="var(--grid)" />
                <XAxis dataKey="date" tickFormatter={(x) => fmtDate(x)} {...axisProps} minTickGap={24} />
                <YAxis {...axisProps} />
                <Tooltip content={<ChartTooltip unit="h" labelFormatter={(l: string) => `Week ending ${fmtDate(l)}`} />} />
                <Line dataKey="mttr_hours" name="MTTR" stroke="var(--s1)" strokeWidth={2} dot={{ r: 3 }} connectNulls isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>
      <div className="grid g-2 mt">
        <Card title="Weekly alerts and incidents">
          <div style={{ height: 230 }}>
            <ResponsiveContainer>
              <BarChart data={d.weekly} margin={{ top: 6, right: 8, left: -12, bottom: 0 }}>
                <CartesianGrid vertical={false} stroke="var(--grid)" />
                <XAxis dataKey="date" tickFormatter={(x) => fmtDate(x)} {...axisProps} minTickGap={24} />
                <YAxis {...axisProps} />
                <Tooltip cursor={{ fill: 'var(--surface-2)' }} content={<ChartTooltip labelFormatter={(l: string) => `Week ending ${fmtDate(l)}`} />} />
                <Bar dataKey="alerts" name="Alerts" fill="var(--s1)" radius={[4, 4, 0, 0]} isAnimationActive={false} />
                <Bar dataKey="incidents" name="Incidents" fill="var(--s2)" radius={[4, 4, 0, 0]} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <Legend items={[{ label: 'Alerts', color: 'var(--s1)' }, { label: 'Incidents', color: 'var(--s2)' }]} />
        </Card>
        <Card title="Recent incidents">
          <table>
            <thead><tr><th>Severity</th><th>Incident</th><th>Status</th><th>Detected</th></tr></thead>
            <tbody>
              {d.incidents.map((i: any) => (
                <tr key={i.id}><td><SevBadge sev={i.severity} /></td><td>{i.title}<div className="muted" style={{ fontSize: 11.5 }}>{i.user_name || i.hostname}</div></td>
                  <td>{cap(i.status.replace('_', ' '))}</td><td className="muted">{fmtDate(i.detected_at)}</td></tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
    </>
  )
}

function Wiz({ d }: { d: any }) {
  const k = d.kpis
  return (
    <>
      <div className="grid g-6">
        <Kpi label="Cloud resources" metric="cloud_resources" value={k.cloud_resources} foot="AWS · Azure · GCP" />
        <Kpi label="Open issues" metric="cloud_open_issues" value={k.open_issues} foot={`${k.critical_issues} critical`} />
        <Kpi label="Toxic combinations" metric="toxic_combinations" value={k.toxic_combinations} tone={k.toxic_combinations ? 'bad' : 'good'} foot="Exposure + vuln + privilege" />
        <Kpi label="Internet-exposed issues" metric="internet_exposed_issues" value={k.internet_exposed} />
        <Kpi label="Exposed secrets" metric="exposed_secrets" value={k.secrets} tone={k.secrets ? 'bad' : 'good'} />
        <Kpi label="Workload vulnerabilities" metric="open_findings" params={{ source: "wiz" }} value={k.workload_vulns} foot={`${k.workload_critical} critical`} />
      </div>
      <div className="grid g-3 mt">
        <Card title="Open issues by cloud" subtitle="By severity">
          <div style={{ height: 220 }}>
            <ResponsiveContainer>
              <BarChart data={d.by_cloud} margin={{ top: 6, right: 8, left: -12, bottom: 0 }}>
                <CartesianGrid vertical={false} stroke="var(--grid)" />
                <XAxis dataKey="cloud" {...axisProps} />
                <YAxis {...axisProps} />
                <Tooltip cursor={{ fill: 'var(--surface-2)' }} content={<ChartTooltip />} />
                {SEVS.map((s, i) => <Bar key={s} dataKey={s} name={cap(s)} stackId="a" fill={SEV_COLOR[s]} stroke="var(--surface)" radius={i === 3 ? [4, 4, 0, 0] : 0} isAnimationActive={false} />)}
              </BarChart>
            </ResponsiveContainer>
          </div>
          <Legend items={SEVS.map((s) => ({ label: cap(s), color: SEV_COLOR[s] }))} />
        </Card>
        <Card title="Issues by category"><HBarList data={d.by_category} labelKey="category" format={fmtCategory} color="var(--s3)" /></Card>
        <Card title="Top failing rules">
          <table><tbody>
            {d.top_rules.map((r: any) => <tr key={r.rule}><td><SevBadge sev={r.severity} /></td><td style={{ fontSize: 12.5 }}>{r.rule}</td><td className="num">{r.count}</td></tr>)}
          </tbody></table>
        </Card>
      </div>
      <div className="grid g-2 mt">
        <SeverityTrend data={d.trend} title="Open cloud issues over time" />
        <Card title="Toxic combinations" subtitle="Highest-risk attack paths — fix within 7 days">
          <table>
            <thead><tr><th>Resource</th><th>Issue</th><th>Cloud</th><th>Opened</th></tr></thead>
            <tbody>
              {d.toxic.map((t: any) => (
                <tr key={t.id}><td className="mono">{t.resource}</td><td style={{ fontSize: 12.5 }}>{t.rule} {t.internet_exposed ? <Globe size={12} color="var(--critical)" /> : null}</td>
                  <td>{t.cloud.toUpperCase()}</td><td className="muted">{fmtDate(t.created_at)}</td></tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
      <div className="grid g-2 mt">
        <TopVulns data={d.top_vulns} />
        <FindingsTable source="wiz" />
      </div>
    </>
  )
}
