// Per-target terminal transcript, kept outside React so a tab move,
// maximise or remount never loses output. sessionStorage survives a
// window reload but stays on this workstation.

export type Line = {
  id: number
  ts: number
  kind: 'in' | 'out' | 'err' | 'sys'
  text: string
  raw?: string
}

const MAX = 300
const MAX_TARGETS = 40
const store = new Map<number, Line[]>()
let seq = 1
const listeners = new Map<number, Set<() => void>>()

function key(id: number): string {
  return `t2:term:${id}`
}

function load(id: number): Line[] {
  const existing = store.get(id)
  if (existing) return existing
  try {
    const raw = sessionStorage.getItem(key(id))
    if (raw) {
      const parsed = JSON.parse(raw) as Line[]
      if (Array.isArray(parsed)) {
        store.set(id, parsed.slice(-MAX))
        return parsed.slice(-MAX)
      }
    }
  } catch {
    /* ignore */
  }
  store.set(id, [])
  return []
}

function notify(id: number): void {
  for (const fn of listeners.get(id) ?? []) fn()
}

export function subscribe(id: number, fn: () => void): () => void {
  const set = listeners.get(id) ?? new Set()
  set.add(fn)
  listeners.set(id, set)
  return () => {
    set.delete(fn)
    if (!set.size) listeners.delete(id)
  }
}

function persist(id: number, lines: Line[]): void {
  try {
    sessionStorage.setItem(key(id), JSON.stringify(lines.slice(-MAX)))
  } catch {
    // Storage full: drop the oldest target rather than fail output.
    const oldest = store.keys().next().value
    if (oldest !== undefined && oldest !== id) {
      store.delete(oldest)
      try { sessionStorage.removeItem(key(oldest)) } catch { /* ignore */ }
    }
  }
}

export function getTranscript(id: number): Line[] {
  return load(id).slice()
}

export function append(id: number, line: Omit<Line, 'id' | 'ts'> & { ts?: number }): Line {
  const lines = load(id)
  const next: Line = {
    id: seq++,
    ts: line.ts ?? Date.now(),
    kind: line.kind,
    text: line.text,
    raw: line.raw
  }
  lines.push(next)
  while (lines.length > MAX) lines.shift()
  persist(id, lines)
  notify(id)
  if (store.size > MAX_TARGETS) {
    const oldest = store.keys().next().value
    if (oldest !== undefined && oldest !== id) store.delete(oldest)
  }
  return next
}

export function clearTranscript(id: number): void {
  store.set(id, [])
  try { sessionStorage.removeItem(key(id)) } catch { /* ignore */ }
  notify(id)
}

export function transcriptText(id: number): string {
  return load(id).map((l) => {
    const t = new Date(l.ts).toISOString().slice(11, 19)
    return `${t} ${l.kind === 'in' ? '$' : l.kind === 'err' ? '!' : ' '} ${l.text}`
  }).join('\n')
}
