import type { Beacon } from '../../../shared/ipc'

export type Severity = 'high' | 'medium' | 'low'
export type SortKey = 'last' | 'pri' | 'host' | 'id'
export type SortDir = 'asc' | 'desc'

const ELEVATED = new Set(['root', 'system', 'admin', 'administrator'])

export function severity(b: Beacon): Severity {
  const priv = (b.privilege ?? 'user').toLowerCase()
  if (b.elevated && ELEVATED.has(priv)) return 'high'
  if (b.elevated || ELEVATED.has(priv)) return 'medium'
  return 'low'
}

export function severityLabel(s: Severity): string {
  return s === 'high' ? 'HIGH' : s === 'medium' ? 'MED' : 'LOW'
}

export function sortRows(rows: Beacon[], key: SortKey, dir: SortDir): Beacon[] {
  const sign = dir === 'asc' ? 1 : -1
  const rank: Record<Severity, number> = { high: 3, medium: 2, low: 1 }
  const sorted = rows.slice().sort((a, b) => {
    switch (key) {
      case 'pri':
        return (rank[severity(a)] - rank[severity(b)]) * sign ||
          a.id - b.id
      case 'host':
        return (a.display_name ?? '').localeCompare(b.display_name ?? '') * sign
      case 'id':
        return (a.id - b.id) * sign
      case 'last':
        return ((a.last_seen_age ?? 0) - (b.last_seen_age ?? 0)) * sign
    }
  })
  return sorted
}

export function rangeSelection(
  rows: Beacon[], from: number, to: number
): Set<number> {
  const a = rows.findIndex((r) => r.id === from)
  const b = rows.findIndex((r) => r.id === to)
  if (a < 0 || b < 0) return new Set(to ? [to] : [])
  const [lo, hi] = a <= b ? [a, b] : [b, a]
  return new Set(rows.slice(lo, hi + 1).map((r) => r.id))
}

export function nextIndex(
  length: number, current: number, delta: number
): number {
  if (length === 0) return -1
  if (current < 0) return delta > 0 ? 0 : length - 1
  return Math.max(0, Math.min(length - 1, current + delta))
}
