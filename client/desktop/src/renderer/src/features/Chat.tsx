import { useEffect, useMemo, useRef, useState } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import type { ChatMessage } from '../../../shared/ipc'
import { invoke, usePoll } from '../hooks'
import EmptyState from '../ui/EmptyState'
import IconButton from '../ui/IconButton'
import { Toolbar, ToolbarSpacer, ToolbarTitle } from '../ui/Toolbar'

type History = {
  messages: ChatMessage[]
  topic?: { text?: string; set_by?: string; set_at?: number }
}

type Row =
  | { kind: 'day'; key: string; label: string }
  | { kind: 'msg'; key: string; m: ChatMessage; grouped: boolean; own: boolean }

function dayLabel(ts: number): string {
  const d = new Date(ts * 1000)
  const today = new Date()
  const yesterday = new Date(Date.now() - 86_400_000)
  if (d.toDateString() === today.toDateString()) return 'Today'
  if (d.toDateString() === yesterday.toDateString()) return 'Yesterday'
  return d.toLocaleDateString(undefined, {
    weekday: 'short', month: 'short', day: 'numeric'
  })
}

function initials(name: string): string {
  return name.split(/[\s._-]+/).filter(Boolean).slice(0, 2)
    .map((x) => x[0]!.toUpperCase()).join('')
}

export default function Chat(props: {
  enabled?: boolean
  me?: string
}): JSX.Element {
  const [line, setLine] = useState('')
  const [fail, setFail] = useState<{ text: string; error: string } | null>(null)
  const [sending, setSending] = useState(false)
  const [follow, setFollow] = useState(true)
  const { data, error, reload } = usePoll<History>(
    'chat.history', { limit: 300 }, 5_000, props.enabled ?? true)
  const rowsRef = useRef<HTMLDivElement>(null)
  const input = useRef<HTMLTextAreaElement>(null)

  const messages = useMemo(() => data?.messages ?? [], [data])

  const rows = useMemo(() => {
    const out: Row[] = []
    let lastDay = ''
    let lastOp = ''
    let lastTs = 0
    for (const m of messages) {
      const ts = m.ts ?? 0
      const day = new Date(ts * 1000).toDateString()
      if (day !== lastDay) {
        out.push({ kind: 'day', key: `d:${day}:${m.id ?? ts}`, label: dayLabel(ts) })
        lastDay = day
        lastOp = ''
      }
      const grouped = m.operator === lastOp && ts - lastTs < 300 &&
        m.kind !== 'action'
      out.push({
        kind: 'msg', key: `m:${m.id ?? `${ts}:${out.length}`}`, m,
        grouped, own: m.operator === props.me
      })
      lastOp = m.operator ?? ''
      lastTs = ts
    }
    return out
  }, [messages, props.me])

  const virt = useVirtualizer({
    count: rows.length,
    getScrollElement: () => rowsRef.current,
    estimateSize: () => 30,
    getItemKey: (i) => rows[i]?.key ?? i,
    overscan: 20,
    anchorTo: 'end',
    followOnAppend: follow
  })

  const send = async (textOverride?: string): Promise<void> => {
    const text = (textOverride ?? line).trim()
    if (!text || sending) return
    setSending(true)
    setFail(null)
    try {
      await invoke('chat.send', { text })
      setLine('')
      setFail(null)
      reload()
      input.current?.focus()
    } catch (e) {
      setLine(text)
      setFail({ text, error: (e as Error).message })
      input.current?.focus()
    } finally {
      setSending(false)
    }
  }

  useEffect(() => {
    if (follow && rows.length) virt.scrollToIndex(rows.length - 1, { align: 'end' })
  }, [rows.length, follow]) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="view chat">
      <Toolbar label="Operator chat">
        <ToolbarTitle>Chat</ToolbarTitle>
        <span className="pill">{messages.length}</span>
        {data?.topic?.text && (
          <span className="chat-topic" title={`Topic set by ${data.topic.set_by ?? '?'}`}>
            # {data.topic.text}
          </span>
        )}
        <ToolbarSpacer />
        <IconButton label={follow ? 'Pause follow' : 'Follow messages'}
          on={follow} onClick={() => setFollow((f) => !f)}>
          {follow ? '❚❚' : '▶'}
        </IconButton>
        <IconButton label="Refresh chat" onClick={reload}>↻</IconButton>
      </Toolbar>

      {error && <div className="banner err" role="alert">{error}</div>}
      {fail && (
        <div className="banner err chat-fail" role="alert">
          send failed: {fail.error}
          <button className="btn tiny" onClick={() => void send(fail.text)}>
            Retry
          </button>
          <button className="btn tiny" onClick={() => setFail(null)}>Dismiss</button>
        </div>
      )}

      <div className="chat-scroll" ref={rowsRef} role="log"
        aria-live="polite" aria-label="Operator chat">
        {rows.length === 0 && (
          <EmptyState glyph="✦" title="No messages"
            hint="coordinate with other operators here" />
        )}
        <div style={{ height: virt.getTotalSize(), position: 'relative' }}>
          {virt.getVirtualItems().map((v) => {
            const row = rows[v.index]
            if (!row) return null
            if (row.kind === 'day') {
              return (
                <div key={row.key} className="chat-day"
                  style={{ position: 'absolute', left: 0, right: 0, transform: `translateY(${v.start}px)` }}>
                  <span>{row.label}</span>
                </div>
              )
            }
            const m = row.m
            return (
              <div key={row.key} data-index={v.index}
                ref={virt.measureElement}
                className={`chat-msg${row.own ? ' own' : ''}${row.grouped ? ' grouped' : ''}${m.kind === 'action' ? ' action' : ''}`}
                style={{ position: 'absolute', left: 0, right: 0, transform: `translateY(${v.start}px)` }}>
                <span className="chat-avatar" aria-hidden="true">
                  {row.grouped ? '' : initials(m.operator ?? '?')}
                </span>
                <div className="chat-body">
                  {!row.grouped && (
                    <div className="chat-meta">
                      <b>{m.operator ?? '?'}</b>
                      <time className="mono" dateTime={new Date((m.ts ?? 0) * 1000).toISOString()}>
                        {m.ts ? new Date(m.ts * 1000).toLocaleTimeString([], { hour12: false }) : ''}
                      </time>
                      {row.own && <span className="chat-you">you</span>}
                    </div>
                  )}
                  <p>{m.kind === 'action' ? `* ${m.text}` : m.text}</p>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      <form className="chat-compose" onSubmit={(e) => { e.preventDefault(); void send() }}>
        <textarea ref={input} className="ui-input chat-input" rows={2}
          value={line} maxLength={2000}
          placeholder="message · Enter sends · Shift+Enter newline"
          aria-label="Chat message"
          onChange={(e) => setLine(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault()
              void send()
            }
          }} />
        <div className="chat-send">
          <span className="muted small">{line.length}/2000</span>
          <button className="btn primary" disabled={sending || !line.trim()}>
            {sending ? 'Sending…' : 'Send'}
          </button>
        </div>
      </form>
    </div>
  )
}
