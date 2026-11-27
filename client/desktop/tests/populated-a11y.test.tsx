// @vitest-environment jsdom
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import axe from 'axe-core'
import App from '../src/renderer/src/App'

const beacons = [
  { id: 1, display_name: 'alice@dc01', os: 'windows', arch: 'amd64',
    alive: true, last_seen_age: 2, privilege: 'system', elevated: true },
  { id: 2, display_name: 'bob@web01', os: 'linux', arch: 'amd64',
    alive: false, last_seen_age: 900, privilege: 'user' }
]
const health = [{ id: 'l1', name: 'edge', type: 'http', host: '0.0.0.0',
  port: 443, status: 'running', health: 'degraded', tls: 'mtls',
  cert_days_left: 12, history: [{ ts: 1, state: 'ok' }, { ts: 2, state: 'degraded' }] }]

const invoke = vi.fn(async (method: string) => {
  let result: unknown = {}
  if (method === 'connect') {
    result = { name: 'op', role: 'admin', caps: ['beacon.list', 'beacon.use', 'listener.view'] }
  } else if (method === 'beacons') result = beacons
  else if (method === 'listeners.health') result = { listeners: health }
  else if (method === 'graph') result = { nodes: [], edges: [] }
  else if (method === 'audit') result = []
  else if (method === 'chat.history') result = { messages: [] }
  else if (method === 'job.list') result = { jobs: [] }
  else if (method === 'armory.list') result = { catalogue: [] }
  else if (method === 'creds.list') result = { creds: [] }
  return { ok: true, result }
})

beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, 'clientHeight', {
    configurable: true, get: () => 500
  })
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({
    width: 1200, height: 500, top: 0, left: 0, bottom: 500, right: 1200,
    x: 0, y: 0, toJSON: () => ({})
  } as DOMRect)
  window.t2 = {
    invoke,
    status: vi.fn(async () => ({ connected: false, config: '' })),
    pickConfig: vi.fn(async () => ''),
    clipboard: vi.fn(async () => true),
    saveFile: vi.fn(async () => ''),
    detach: vi.fn(async () => true),
    onLog: () => () => undefined,
    onUpdate: () => () => undefined,
    onConn: () => () => undefined,
    windowControl: vi.fn(async () => true)
  } as unknown as typeof window.t2
})

afterEach(() => { cleanup(); invoke.mockClear() })

async function connect() {
  render(<App />)
  fireEvent.change(screen.getByLabelText('Operator config path'), {
    target: { value: '/tmp/op.cfg' }
  })
  fireEvent.click(screen.getByRole('button', { name: /connect/i }))
  await waitFor(() => expect(document.querySelectorAll('[data-row-id]').length).toBe(2))
}

describe('populated workspace accessibility', () => {
  it('axe passes with rows, inspector and listeners', async () => {
    await connect()
    fireEvent.click(document.querySelector('[data-row-id="1"]')!)
    await waitFor(() => expect(screen.getByText('Fingerprint')).toBeTruthy())
    fireEvent.click(document.querySelector('[data-tab-id="listeners"]')!)
    await waitFor(() => expect(screen.getByText('0.0.0.0:443')).toBeTruthy())
    const res = await axe.run(document.body, {
      rules: { 'color-contrast': { enabled: false } }
    })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })
})
