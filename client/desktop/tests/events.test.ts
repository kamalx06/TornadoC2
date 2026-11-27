import { beforeEach, describe, expect, it } from 'vitest'
import {
  clear, pushBridge, snapshot, subscribe
} from '../src/renderer/src/lib/events'

describe('event sources', () => {
  beforeEach(() => clear())

  it('parses server levels into a server source', () => {
    pushBridge('[srv:err] POST /api/v1/beacons 500 12ms alice\n')
    const event = snapshot().at(-1)!
    expect(event.level).toBe('err')
    expect(event.source).toBe('server')
    expect(event.text).toBe('POST /api/v1/beacons 500 12ms alice')
  })

  it('keeps ordinary bridge output as bridge', () => {
    pushBridge('[bridge] connected\n')
    expect(snapshot().at(-1)!.source).toBe('bridge')
  })

  it('classifies unlevelled server lines as info only if malformed', () => {
    pushBridge('[srv:bogus] hello\n')
    expect(snapshot().at(-1)!.source).toBe('bridge')
  })

  it('notifies subscribers and trims the newline', () => {
    let calls = 0
    const off = subscribe(() => { calls += 1 })
    pushBridge('[srv:info] ok\n')
    off()
    expect(calls).toBe(1)
    expect(snapshot().at(-1)!.text).toBe('ok')
  })
})
