// @vitest-environment jsdom
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import axe from 'axe-core'
import type { HealthRow } from '../src/shared/ipc'
import Listeners from '../src/renderer/src/features/Listeners'

let rows: HealthRow[] = []
let data: { listeners: HealthRow[] } = { listeners: [] }
const reload = vi.fn()
const toast = vi.fn()
const invoke = vi.fn(async (method: string, params: Record<string, unknown>) => {
  if (method === 'listener.probe') {
    return { ok: true, state: params.id === 'a' ? 'down' : 'ok' }
  }
  if (method === 'listener.create') return { listener: { id: 'c' } }
  if (method === 'listeners.certs') return { certs: [], keys: [], cas: [] }
  if (method === 'listeners.profiles') return { profiles: [] }
  return {}
})

vi.mock('../src/renderer/src/hooks', () => ({
  invoke: (m: string, p: Record<string, unknown>) => invoke(m, p),
  usePoll: () => ({ data, error: '', reload })
}))

beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, 'clientHeight', {
    configurable: true, get: () => 400
  })
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({
    width: 1000, height: 400, top: 0, left: 0, bottom: 400, right: 1000,
    x: 0, y: 0, toJSON: () => ({})
  } as DOMRect)
  window.t2 = { clipboard: vi.fn(async () => true) } as unknown as typeof window.t2
})

beforeEach(() => {
  data = { listeners: [] }
  rows = [
    { id: 'a', name: 'edge', type: 'http', host: '0.0.0.0', port: 443,
      status: 'running', health: 'ok', tls: 'mtls', cert_days_left: 4,
      history: [{ ts: 1, state: 'ok' }, { ts: 2, state: 'degraded' }] },
    { id: 'b', name: 'dns', type: 'dns', host: '0.0.0.0', port: 53,
      status: 'stopped', health: 'down', tls: '', cert_days_left: -1,
      history: [{ ts: 3, state: 'down', error: 'refused' }] }
  ]
  data = { listeners: rows }
})

afterEach(() => { cleanup(); invoke.mockClear(); reload.mockClear(); toast.mockClear() })

function ui(caps = ['listener.view', 'listener.manage', 'listener.delete']) {
  return render(<Listeners caps={caps} onToast={toast} />)
}

describe('listener pane', () => {
  it('renders bind, TLS, health text and sparklines', () => {
    ui()
    expect(screen.getByText('0.0.0.0:443')).toBeTruthy()
    expect(screen.getByText('mTLS')).toBeTruthy()
    expect(screen.getByText(/■ down/)).toBeTruthy()
    expect(screen.getByText(/● ok/)).toBeTruthy()
    expect(screen.getByRole('img', { name: /Last 2 probes/ })).toBeTruthy()
  })

  it('probes in place without a reload', async () => {
    ui()
    fireEvent.click(screen.getAllByRole('button', { name: 'Probe' })[0]!)
    await waitFor(() => expect(toast).toHaveBeenCalled())
    expect(screen.getAllByText(/■ down/).length).toBe(2)
    expect(reload).not.toHaveBeenCalled()
  })

  it('creates from the side sheet', async () => {
    ui()
    fireEvent.click(screen.getByRole('button', { name: 'New listener' }))
    const sheet = await screen.findByRole('region', { name: 'Create listener' })
    expect(sheet).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'new' } })
    fireEvent.change(screen.getByLabelText('Port'), { target: { value: '8443' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('listener.create',
      expect.objectContaining({ spec: expect.objectContaining({ name: 'new' }) })))
    await waitFor(() => expect(reload).toHaveBeenCalled())
  })

  it('opens edit with delete in the sheet', async () => {
    ui()
    fireEvent.click(screen.getAllByRole('button', { name: 'Edit' })[0]!)
    expect(await screen.findByRole('region', { name: 'Edit listener' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Delete' })).toBeTruthy()
  })

  it('hides management actions without the capability', () => {
    ui(['listener.view'])
    expect(screen.queryByRole('button', { name: 'New listener' })).toBeNull()
    expect(screen.getAllByRole('button', { name: 'Probe' })[0]
      ?.hasAttribute('disabled')).toBe(true)
  })

  it('has no axe violations', async () => {
    const { container } = ui()
    const res = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } }
    })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })
})
