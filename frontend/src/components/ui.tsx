import type { ReactNode } from 'react'
import { AlertTriangle, ArrowDownRight, ArrowUpRight, Loader2, X } from 'lucide-react'
import { SEV_COLOR, cap } from '../format'

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {subtitle && <p>{subtitle}</p>}
      </div>
      {actions && <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>{actions}</div>}
    </div>
  )
}

export function Card({ title, subtitle, action, children, className = '', style }: {
  title?: ReactNode; subtitle?: ReactNode; action?: ReactNode; children: ReactNode; className?: string; style?: React.CSSProperties
}) {
  return (
    <section className={`card ${className}`} style={style}>
      {(title || action) && (
        <div className="card-head">
          <div>
            {title && <div className="card-title">{title}</div>}
            {subtitle && <div className="card-sub">{subtitle}</div>}
          </div>
          {action}
        </div>
      )}
      {children}
    </section>
  )
}

export function Delta({ value, unit = '', better = 'lower' }: { value: number | null | undefined; unit?: string; better?: 'lower' | 'higher' }) {
  if (value === null || value === undefined || value === 0) return <span className="muted">no change</span>
  const good = better === 'lower' ? value < 0 : value > 0
  return (
    <span className={good ? 'delta-good' : 'delta-bad'} style={{ display: 'inline-flex', alignItems: 'center', gap: 2 }}>
      {value > 0 ? <ArrowUpRight size={13} /> : <ArrowDownRight size={13} />}{Math.abs(value)}{unit}
    </span>
  )
}

export function SevBadge({ sev }: { sev: string }) {
  return (
    <span className="badge">
      <span className="sw" style={{ background: SEV_COLOR[sev] || 'var(--low)' }} />
      {cap(sev)}
    </span>
  )
}

/** Only live connections are labeled; nothing is shown otherwise. */
export function ModeBadge({ mode }: { mode?: string }) {
  if (mode !== 'live') return null
  return <span className="badge badge-live" title="Data synced from the vendor API"><span className="live-dot" />Live API</span>
}

export function Meter({ value, color, max = 100 }: { value: number; color: string; max?: number }) {
  return <div className="meter"><span style={{ width: `${Math.min(100, (100 * value) / max)}%`, background: color }} /></div>
}

export function Legend({ items }: { items: { label: string; color: string }[] }) {
  return (
    <div className="legend">
      {items.map((i) => <span key={i.label}><i style={{ background: i.color }} />{i.label}</span>)}
    </div>
  )
}

export function Loading() {
  return (
    <div className="grid g-3">
      {[0, 1, 2].map((i) => <div key={i} className="skeleton" />)}
    </div>
  )
}

export function ErrorBox({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return (
    <div className="card" style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
      <AlertTriangle size={18} color="var(--critical)" />
      <div style={{ flex: 1 }}>Could not load data: <span className="text-2">{error}</span></div>
      {onRetry && <button className="btn btn-sm" onClick={onRetry}>Retry</button>}
    </div>
  )
}

export function Spinner({ size = 14 }: { size?: number }) {
  return <Loader2 size={size} className="spin" />
}

export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  return (
    <div className="modal-wrap" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title}>
        <div className="card-head">
          <h3>{title}</h3>
          <button className="btn btn-ghost btn-sm" onClick={onClose} aria-label="Close"><X size={16} /></button>
        </div>
        {children}
      </div>
    </div>
  )
}

/** Shared hover tooltip for Recharts. Values in text ink; color swatch carries identity. */
export function ChartTooltip({ active, payload, label, labelFormatter, unit = '' }: any) {
  if (!active || !payload?.length) return null
  return (
    <div className="tt">
      <div className="tt-title">{labelFormatter ? labelFormatter(label) : label}</div>
      {payload.filter((p: any) => p.value !== null && p.value !== undefined).map((p: any) => (
        <div className="tt-row" key={p.dataKey}>
          <span><i style={{ background: p.color || p.fill || p.stroke }} />{p.name}</span>
          <b>{typeof p.value === 'number' ? p.value.toLocaleString() : p.value}{unit}</b>
        </div>
      ))}
    </div>
  )
}

/** Overlays stack in the order they were opened (a ticket opened from an asset sits above it, and vice versa). */
let overlayZ = 60
export const nextOverlayZ = () => ++overlayZ

export const axisProps = {
  stroke: 'var(--axis)', tick: { fill: 'var(--muted)', fontSize: 11 }, tickLine: false,
} as const
