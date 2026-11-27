// @vitest-environment jsdom
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import App from '../src/renderer/src/App'

let pingFails = false
const invoke = vi.fn(async (method: string) => {
  if (method === 'ping' && pingFails) throw new Error('offline')
  let result: unknown = {}
  if (method === 'beacons') result = []
  else if (method === 'listeners.health') result = { listeners: [] }
  else if (method === 'graph') result = { nodes: [], edges: [] }
  else if (method === 'audit') result = []
  else if (method === 'chat.history') result = { messages: [] }
  else if (method === 'job.list') result = { jobs: [] }
  else if (method === 'armory.list') result = { catalogue: [] }
  else if (method === 'creds.list') result = { creds: [] }
  return { ok: true, result }
})

beforeAll(() => {
  window.t2 = {
    invoke,
    status: vi.fn(async () => ({ connected: false, config: '' })),
    pickConfig: vi.fn(async () => ''),
    pathForFile: vi.fn((f: File) => `/tmp/${f.name}`),
    clipboard: vi.fn(async () => true),
    saveFile: vi.fn(async () => ''),
    detach: vi.fn(async () => true),
    onLog: () => () => undefined,
    onUpdate: () => () => undefined,
    onConn: () => () => undefined,
    windowControl: vi.fn(async () => true)
  } as unknown as typeof window.t2
})

beforeEach(() => { pingFails = false; localStorage.clear() })
afterEach(() => { cleanup(); invoke.mockClear() })

const file = (name: string) => new File(['x'], name, { type: 'text/plain' })

describe('connect gate', () => {
  it('accepts a dropped config', async () => {
    render(<App />)
    const drop = document.querySelector('.gate-drop')!
    fireEvent.drop(drop, { dataTransfer: { files: [file('operator.cfg')] } })
    const input = screen.getByLabelText('Operator config path') as HTMLInputElement
    expect(input.value).toBe('/tmp/operator.cfg')
    expect(screen.getByText('operator.cfg')).toBeTruthy()
    await waitFor(() => expect(
      (screen.getByRole('button', { name: /^connect$/i }) as HTMLButtonElement).disabled)
      .toBe(false))
  })

  it('rejects a non-config drop with a readable error', () => {
    render(<App />)
    fireEvent.drop(document.querySelector('.gate-drop')!, {
      dataTransfer: { files: [file('notes.txt')] }
    })
    expect(screen.getByRole('alert').textContent).toContain('.cfg')
    expect((screen.getByLabelText('Operator config path') as HTMLInputElement).value)
      .toBe('')
  })

  it('shows the last session and readiness rows', () => {
    localStorage.setItem('t2:last-session', JSON.stringify({
      operator: 'alice', role: 'operator', at: Date.now()
    }))
    render(<App />)
    expect(screen.getByText('last session')).toBeTruthy()
    expect(screen.getByText('alice')).toBeTruthy()
    expect(screen.getByText('Transport')).toBeTruthy()
    expect(screen.getByText('local only')).toBeTruthy()
  })

  it('blocks connect when the bridge is offline', async () => {
    pingFails = true
    render(<App />)
    await waitFor(() => expect(
      screen.getByRole('button', { name: /bridge offline/i })).toBeTruthy())
    expect((screen.getByRole('button', { name: /bridge offline/i }) as HTMLButtonElement)
      .disabled).toBe(true)
  })

  it('remembers the last session after connecting and disconnecting', async () => {
    const original = invoke.getMockImplementation()!
    invoke.mockImplementation(async (method: string) => {
      if (method === 'connect') {
        return { ok: true, result: { name: 'alice', role: 'operator', caps: ['beacon.list'] } }
      }
      return original(method)
    })
    render(<App />)
    fireEvent.change(screen.getByLabelText('Operator config path'), {
      target: { value: '/tmp/op.cfg' }
    })
    fireEvent.click(screen.getByRole('button', { name: /^connect$/i }))
    await waitFor(() => expect(
      document.querySelectorAll('[data-tab]').length).toBeGreaterThan(0))
    fireEvent.click(screen.getByRole('button', { name: 'Disconnect' }))
    await waitFor(() => expect(screen.getByText('last session')).toBeTruthy())
    expect(screen.getByText('alice')).toBeTruthy()
    invoke.mockImplementation(original)
  })

  it('focuses the password after a connect failure', async () => {
    const original = invoke.getMockImplementation()!
    invoke.mockImplementation(async (method: string) => {
      if (method === 'connect') throw new Error('bad password')
      return original(method)
    })
    render(<App />)
    fireEvent.change(screen.getByLabelText('Operator config path'), {
      target: { value: '/tmp/op.cfg' }
    })
    expect((screen.getByLabelText('Operator config path') as HTMLInputElement).value)
      .toBe('/tmp/op.cfg')
    fireEvent.click(screen.getByRole('button', { name: /^connect$/i }))
    await waitFor(() => expect(screen.getByRole('alert')).toBeTruthy())
    await waitFor(() => expect(document.activeElement?.getAttribute('type'))
      .toBe('password'), { timeout: 600 })
    invoke.mockImplementation(original)
  })
})
