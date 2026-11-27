import { describe, expect, it } from 'vitest'
import { requestSchema, responseSchema, methodSchema } from '../src/shared/ipc'

describe('ipc schema', () => {
  it('accepts a known method', () => {
    expect(methodSchema.parse('beacons')).toBe('beacons')
  })
  it('rejects unknown methods', () => {
    expect(() => methodSchema.parse('exec')).toThrow()
  })
  it('defaults params', () => {
    expect(requestSchema.parse({ method: 'ping' }).params).toEqual({})
  })
  it('caps timeouts', () => {
    expect(() =>
      requestSchema.parse({ method: 'ping', timeoutMs: 20 * 60_000 })
    ).toThrow()
  })
  it('narrows responses', () => {
    expect(responseSchema.parse({ ok: true, result: 1 }).ok).toBe(true)
    expect(
      responseSchema.parse({ ok: false, error: 'x', code: 'down' }).ok
    ).toBe(false)
  })
})

import {
  healthRowSchema, modelSchema, auditRowSchema, chatMessageSchema,
  graphSchema, listenerSchema
} from '../src/shared/ipc'

describe('read payloads', () => {
  it('accepts a health row', () => {
    const r = healthRowSchema.parse({
      id: 'lst_a', health: 'ok', cert_days_left: 12,
      history: [{ ts: 1, state: 'ok' }]
    })
    expect(r.health).toBe('ok')
  })
  it('rejects unknown health states', () => {
    expect(() =>
      listenerSchema.parse({ id: 'x', health: 'flapping' })
    ).toThrow()
  })
  it('accepts a model snapshot', () => {
    const m = modelSchema.parse({
      dataset: 'abc', hosts: [{ hostname: 'h' }],
      timeline: [{ ts: 1, kind: 'jump', text: 't', by: 'a' }],
      mitre: [{ tactic: 'x', technique: 'T1', kind: 'jump' }]
    })
    expect(m.hosts?.length).toBe(1)
  })
  it('accepts audit/chat/graph rows', () => {
    auditRowSchema.parse({ id: '1', action: 'x', outcome: 'ok' })
    chatMessageSchema.parse({ id: 1, operator: 'a', text: 'hi' })
    graphSchema.parse({
      nodes: [{ id: 1, privilege: 'root' }],
      edges: [{ from: 1, to: 1, shared: ['user=a'] }]
    })
  })
})
