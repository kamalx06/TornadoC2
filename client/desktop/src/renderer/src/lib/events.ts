// Capped event ring shared by the log pane. Bridge, task and audit
// producers all write here; the pane only filters and renders.

export type Level = 'info' | 'warn' | 'err' | 'task'
export type Source = 'bridge' | 'task' | 'audit' | 'operator' | 'system'

export type Event = {
  id: number
  ts: number
  level: Level
  source: Source
  text: string
  key?: string
}

const MAX = 2000
const seenAudit = new Set<string>()
let seq = 1
let ring: Event[] = []
const listeners = new Set<() => void>()

function emit(): void {
  for (const fn of listeners) fn()
}

export function push(
  level: Level, source: Source, text: string, key?: string
): Event {
  const event: Event = {
    id: seq++, ts: Date.now(), level, source,
    text: text.replace(/\n$/, '').slice(0, 2000), key
  }
  ring = [...ring.slice(-(MAX - 1)), event]
  emit()
  return event
}

export function classify(line: string): Level {
  if (/\b(error|failed|failure|denied|refused|traceback)\b/i.test(line)) return 'err'
  if (/\b(warn|warning|degraded|timeout|retry)\b/i.test(line)) return 'warn'
  if (/^\[task\]/i.test(line)) return 'task'
  return 'info'
}

export function pushBridge(line: string): void {
  const clean = line.replace(/\n$/, '')
  if (!clean) return
  push(classify(clean), 'bridge', clean)
}

export function pushTask(text: string, level: Level = 'task'): void {
  push(level, 'task', text)
}

export function pushAudit(rows: Array<{
  id?: string; ts?: string; operator?: string; action?: string;
  target?: string; outcome?: string; detail?: string
}>): void {
  for (const row of rows.slice().reverse()) {
    const key = row.id ?? `${row.ts}:${row.action}`
    if (seenAudit.has(key)) continue
    seenAudit.add(key)
    if (seenAudit.size > 5000) seenAudit.clear()
    const text = [
      row.operator ?? '?', row.action ?? '?', row.target ?? '',
      row.outcome ?? '', row.detail ?? ''
    ].filter(Boolean).join(' · ')
    push(row.outcome === 'denied' || row.outcome === 'error' ? 'err' : 'info',
      'audit', text, key)
  }
}

export function snapshot(): Event[] {
  return ring
}

export function subscribe(fn: () => void): () => void {
  listeners.add(fn)
  return () => { listeners.delete(fn) }
}

export function clear(): void {
  ring = []
  emit()
}

export function exportText(rows: Event[]): string {
  return rows.map((e) =>
    `${new Date(e.ts).toISOString()} ${e.level.toUpperCase()} ${e.source} ${e.text}`
  ).join('\n')
}
