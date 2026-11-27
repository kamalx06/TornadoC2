import { describe, expect, it } from 'vitest'
import type { Beacon } from '../src/shared/ipc'
import {
  nextIndex, rangeSelection, severity, severityLabel, sortRows
} from '../src/renderer/src/lib/targets'

const b = (id: number, over: Partial<Beacon> = {}): Beacon =>
  ({ id, display_name: `host${id}`, last_seen_age: id, ...over })

describe('target severity', () => {
  it('ranks elevated privileged sessions highest', () => {
    expect(severity(b(1, { elevated: true, privilege: 'system' }))).toBe('high')
    expect(severity(b(2, { elevated: true, privilege: 'user' }))).toBe('medium')
    expect(severity(b(3, { privilege: 'root' }))).toBe('medium')
    expect(severity(b(4))).toBe('low')
    expect(severityLabel('high')).toBe('HIGH')
  })

  it('sorts by priority then id, both directions', () => {
    const rows = [b(1), b(2, { elevated: true, privilege: 'system' }), b(3)]
    expect(sortRows(rows, 'pri', 'desc').map((r) => r.id)).toEqual([2, 1, 3])
    expect(sortRows(rows, 'pri', 'asc').map((r) => r.id)).toEqual([1, 3, 2])
  })

  it('builds inclusive ranges regardless of direction', () => {
    const rows = [b(10), b(11), b(12), b(13)]
    expect([...rangeSelection(rows, 13, 11)]).toEqual([11, 12, 13])
    expect([...rangeSelection(rows, 10, 10)]).toEqual([10])
  })

  it('clamps index movement', () => {
    expect(nextIndex(5, 0, -1)).toBe(0)
    expect(nextIndex(5, 4, 1)).toBe(4)
    expect(nextIndex(5, -1, 1)).toBe(0)
    expect(nextIndex(0, -1, 1)).toBe(-1)
  })
})
