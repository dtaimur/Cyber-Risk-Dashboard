import { useEffect, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { ArrowUp, Check, Database, RotateCcw, ShieldCheck, Square, TicketPlus, TriangleAlert } from 'lucide-react'
import { useApi } from '../api'
import { useAuth } from '../auth'
import { PriorityBadge, useTickets } from '../components/Tickets'
import { Card, PageHeader, Spinner } from '../components/ui'

type ToolCall = { name: string; summary?: string; error?: boolean; done: boolean }
type Draft = { draft: any; source: any; created?: string }
type Turn = { role: 'user' | 'assistant'; text: string; tools: ToolCall[]; drafts: Draft[]; error?: string; streaming?: boolean }

const TOOL_LABEL: Record<string, string> = {
  get_security_overview: 'Read security overview', get_metric_detail: 'Looked up metric', search_findings: 'Searched findings',
  get_active_threats: 'Checked active threats', get_asset: 'Looked up asset', search_alerts: 'Searched alerts',
  search_threat_news: 'Searched threat news', get_vendor_risk: 'Reviewed vendor risk', get_compliance: 'Reviewed compliance',
  search_tickets: 'Searched Jira tickets', draft_remediation_ticket: 'Drafted ticket',
}

/** Turn CVE IDs and ticket keys into links (only for roles that can open them). */
function linkify(md: string, allowed: boolean) {
  if (!allowed) return md
  return md
    .replace(/(?<![[\w/#-])(CVE-\d{4}-\d{4,7})(?![\w\]])/g, '[$1](/threats/active#$1)')
    .replace(/(?<![[\w/#-])(SEC-\d+)(?![\w\]])/g, '[$1](#ticket:$1)')
}

export default function Assistant() {
  const { data: status } = useApi<any>('/assistant/status')
  const { can } = useAuth()
  const { openTicket, createTicket } = useTickets()
  const [params, setParams] = useSearchParams()
  const [turns, setTurns] = useState<Turn[]>([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const convId = useRef<string | null>(null)
  const abort = useRef<AbortController | null>(null)
  const bottom = useRef<HTMLDivElement>(null)

  useEffect(() => { bottom.current?.scrollIntoView({ behavior: 'smooth', block: 'end' }) }, [turns])

  // Deep link from a metric: /assistant?q=...
  useEffect(() => {
    const q = params.get('q')
    if (q && status?.configured && !busy && turns.length === 0) {
      setParams({}, { replace: true })
      send(q)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status])

  function update(fn: (t: Turn) => Turn) {
    setTurns((ts) => [...ts.slice(0, -1), fn(ts[ts.length - 1])])
  }

  async function send(text: string) {
    const message = text.trim()
    if (!message || busy) return
    setInput('')
    setBusy(true)
    setTurns((ts) => [...ts, { role: 'user', text: message, tools: [], drafts: [] },
      { role: 'assistant', text: '', tools: [], drafts: [], streaming: true }])
    const ctrl = new AbortController()
    abort.current = ctrl
    try {
      const res = await fetch('/api/assistant/chat', {
        method: 'POST', signal: ctrl.signal, credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
        body: JSON.stringify({ message, conversation_id: convId.current }),
      })
      if (!res.ok || !res.body) {
        const body = await res.json().catch(() => ({}))
        if (res.status === 401) window.dispatchEvent(new Event('auth:expired'))
        throw new Error(body.detail || res.statusText)
      }
      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      for (;;) {
        const { value, done } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        const chunks = buffer.split('\n\n')
        buffer = chunks.pop() || ''
        for (const chunk of chunks) {
          if (!chunk.startsWith('data: ')) continue
          const ev = JSON.parse(chunk.slice(6))
          if (ev.type === 'conversation') convId.current = ev.id
          else if (ev.type === 'text') update((t) => ({ ...t, text: t.text + ev.text }))
          else if (ev.type === 'tool_start') update((t) => ({ ...t, tools: [...t.tools, { name: ev.name, done: false }] }))
          else if (ev.type === 'tool_done') update((t) => {
            const i = t.tools.findIndex((c) => c.name === ev.name && !c.done)
            const call = { name: ev.name, summary: ev.summary, error: ev.error, done: true }
            return { ...t, tools: i >= 0 ? t.tools.map((c, j) => (j === i ? call : c)) : [...t.tools, call] }
          })
          else if (ev.type === 'ticket_draft') update((t) => ({ ...t, drafts: [...t.drafts, { draft: ev.draft, source: ev.source }] }))
          else if (ev.type === 'error') update((t) => ({ ...t, error: ev.message }))
        }
      }
    } catch (e: any) {
      if (e.name !== 'AbortError') update((t) => ({ ...t, error: e.message }))
    } finally {
      update((t) => ({ ...t, streaming: false }))
      setBusy(false)
      abort.current = null
    }
  }

  function reset() {
    abort.current?.abort()
    convId.current = null
    setTurns([])
  }

  const markdownComponents = {
    a: ({ href, children }: any) => {
      if (href?.startsWith('#ticket:')) return <button className="md-link mono" onClick={() => openTicket(href.slice(8))}>{children}</button>
      if (href?.startsWith('/')) return <Link to={href}>{children}</Link>
      return <a href={href} target="_blank" rel="noopener noreferrer">{children}</a>
    },
  }

  return (
    <div className="assistant">
      <PageHeader title="AI Analyst"
        subtitle="Questions answered from dashboard data, limited to what your role can see"
        actions={turns.length > 0 ? <button className="btn btn-sm" onClick={reset}><RotateCcw size={13} /> New conversation</button> : undefined} />

      {status && !status.configured && (
        <Card>
          <div style={{ display: 'flex', gap: 10 }}>
            <TriangleAlert size={18} color="var(--medium-text)" style={{ flexShrink: 0, marginTop: 2 }} />
            <div>
              <b>The AI analyst is not configured.</b>
              <p className="text-2" style={{ margin: '4px 0 0', fontSize: 13.5 }}>
                An administrator needs to provide a Claude API key to the server (environment variable <span className="mono">ANTHROPIC_API_KEY</span>) and restart it.
                The key stays on the server and is never sent to the browser.
              </p>
            </div>
          </div>
        </Card>
      )}

      <div className="chat">
        {turns.length === 0 && status?.configured && (
          <div className="chat-empty">
            <div className="kpi-label" style={{ marginBottom: 8 }}>Suggested questions</div>
            <div className="suggestions">
              {status.suggestions.map((s: string) => <button key={s} className="suggestion" onClick={() => send(s)}>{s}</button>)}
            </div>
          </div>
        )}

        {turns.map((t, i) => t.role === 'user' ? (
          <div key={i} className="msg msg-user"><div className="bubble">{t.text}</div></div>
        ) : (
          <div key={i} className="msg msg-assistant">
            <div className="avatar-bot" aria-hidden>AI</div>
            <div className="msg-body">
              {t.tools.length > 0 && (
                <div className="tool-trail">
                  {t.tools.map((c, j) => (
                    <span key={j} className={`tool-chip ${c.error ? 'err' : ''}`}>
                      {c.done ? (c.error ? <TriangleAlert size={11} /> : <Check size={11} />) : <Spinner size={11} />}
                      <Database size={11} className="muted" />
                      {TOOL_LABEL[c.name] || c.name}{c.summary && c.done && !c.error && <span className="muted"> · {c.summary}</span>}
                    </span>
                  ))}
                </div>
              )}
              {t.text ? (
                <div className="md"><ReactMarkdown remarkPlugins={[remarkGfm]} components={markdownComponents}>{linkify(t.text, can('view_details'))}</ReactMarkdown></div>
              ) : t.streaming && !t.error && <div className="muted" style={{ fontSize: 13 }}><Spinner size={12} /> {t.tools.length ? 'Analyzing…' : 'Thinking…'}</div>}
              {t.drafts.map((d, j) => (
                <div key={j} className="draft-card">
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                    <TicketPlus size={15} color="var(--accent)" /><b style={{ fontSize: 13 }}>Draft remediation ticket</b>
                    <PriorityBadge priority={d.draft.priority} />
                  </div>
                  <div style={{ fontSize: 13 }}>{d.draft.summary}</div>
                  <div className="muted" style={{ fontSize: 12, margin: '2px 0 8px' }}>
                    {d.draft.team} · due {d.draft.due_date} · {d.draft.linked_findings} finding{d.draft.linked_findings === 1 ? '' : 's'} · not created yet
                  </div>
                  {d.created ? <button className="btn btn-sm mono" onClick={() => openTicket(d.created!)}>{d.created}</button> : (
                    <button className="btn btn-sm btn-primary" onClick={() => createTicket(d.source, (tk) =>
                      setTurns((ts) => ts.map((x, xi) => xi === i ? { ...x, drafts: x.drafts.map((y, yi) => yi === j ? { ...y, created: tk.key } : y) } : x)))}>
                      Review &amp; create
                    </button>
                  )}
                </div>
              ))}
              {t.error && <div className="login-error" style={{ marginTop: 8 }}>{t.error}</div>}
            </div>
          </div>
        ))}
        <div ref={bottom} />
      </div>

      <form className="composer" onSubmit={(e) => { e.preventDefault(); send(input) }}>
        <textarea className="input" rows={1} placeholder={status?.configured ? 'Ask about vulnerabilities, threats, alerts, vendors, compliance…' : 'The AI analyst is not configured'}
          value={input} disabled={!status?.configured} maxLength={4000}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(input) } }} />
        {busy
          ? <button type="button" className="btn btn-primary" onClick={() => abort.current?.abort()} aria-label="Stop"><Square size={14} /></button>
          : <button type="submit" className="btn btn-primary" disabled={!input.trim() || !status?.configured} aria-label="Send"><ArrowUp size={16} /></button>}
      </form>
      <div className="muted composer-note">
        <ShieldCheck size={12} /> Read-only: the analyst can look up data and draft tickets, but cannot change anything. Answers can contain mistakes; verify important figures in the dashboard. Powered by Claude.
      </div>
    </div>
  )
}
