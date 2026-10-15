export const SEVS = ['critical', 'high', 'medium', 'low'] as const
export type Severity = (typeof SEVS)[number]

export const SEV_COLOR: Record<string, string> = {
  critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)',
}

// Categorical identity colors for tools, in fixed validated order.
export const TOOL_COLOR: Record<string, string> = {
  crowdstrike: 'var(--s1)', expel: 'var(--s2)', wiz: 'var(--s3)', qualys: 'var(--s4)',
}
export const TOOL_NAME: Record<string, string> = {
  qualys: 'Qualys', crowdstrike: 'CrowdStrike', expel: 'Expel', wiz: 'Wiz', jira: 'Jira',
}

export const cap = (s: string) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s)
export const fmtNum = (n: number | null | undefined, digits = 0) =>
  n === null || n === undefined ? '—' : n.toLocaleString(undefined, { maximumFractionDigits: digits })

export function fmtDate(s?: string | null, opts: Intl.DateTimeFormatOptions = { month: 'short', day: 'numeric' }) {
  if (!s) return '—'
  const d = new Date(s.length === 10 ? s + 'T00:00:00' : s)
  return d.toLocaleDateString(undefined, opts)
}

export function timeAgo(s?: string | null) {
  if (!s) return '—'
  const mins = (Date.now() - new Date(s).getTime()) / 60000
  if (mins < 60) return `${Math.max(1, Math.round(mins))}m ago`
  if (mins < 60 * 24) return `${Math.round(mins / 60)}h ago`
  return `${Math.round(mins / 1440)}d ago`
}

/** Text-safe variants (readable on both white and dark surfaces). */
export function riskTextColor(score: number) {
  return score >= 75 ? 'var(--critical-text)' : score >= 55 ? 'var(--high-text)' : score >= 35 ? 'var(--medium-text)' : 'var(--good-text)'
}

export function riskColor(score: number) {
  return score >= 75 ? 'var(--critical)' : score >= 55 ? 'var(--high)' : score >= 35 ? 'var(--medium)' : 'var(--good)'
}

const ACRONYMS: Record<string, string> = { bec: 'BEC (business email compromise)', c2: 'Command & control', pup: 'Unwanted software' }
export const fmtCategory = (s: string) => ACRONYMS[s] ?? cap(s)
