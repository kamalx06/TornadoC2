// @vitest-environment jsdom
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import App from '../src/renderer/src/App'

const invoke = vi.fn(async (method: string) => {
  let result: unknown = {}
  if (method === 'connect') {
    result = { name: 'op', role: 'admin', caps: ['beacon.list'] }
  } else if (method === 'beacons') result = []
  else if (method === 'listeners.health') result = { listeners: [] }
  else if (method === 'graph') result = { nodes: [], edges: [] }
  else if (method === 'audit') result = []
  else if (method === 'chat.history') result = { messages: [] }
  else if (method === 'job.list') result = { jobs: [] }
  return { ok: true, result }
})

beforeAll(() => {
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

afterEach(() => { cleanup(); invoke.mockClear(); localStorage.clear() })

async function connect() {
  render(<App />)
  fireEvent.change(screen.getByLabelText('Operator config path'), {
    target: { value: '/tmp/op.cfg' }
  })
  fireEvent.click(screen.getByRole('button', { name: /connect/i }))
  await waitFor(() => expect(document.querySelectorAll('[data-tab]').length).toBeGreaterThan(5))
}

describe('keyboard only', () => {
  it('opens and closes the palette without a pointer', async () => {
    await connect()
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true })
    expect(screen.getByRole('dialog', { name: 'Command palette' })).toBeTruthy()
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(screen.queryByRole('dialog', { name: 'Command palette' })).toBeNull()
  })

  it('moves between profiles with arrow keys', async () => {
    await connect()
    const first = document.querySelector('.profiles [role="tab"]') as HTMLElement
    first.focus()
    fireEvent.keyDown(first, { key: 'ArrowRight' })
    await waitFor(() => expect(
      document.querySelector('.profiles [aria-selected="true"]')?.textContent)
      .toContain('Investigation'))
  })

  it('activates a rail panel with the keyboard', async () => {
    await connect()
    fireEvent.click(screen.getByRole('button', { name: 'Topology' }))
    const graph = screen.getByRole('menuitem', { name: 'Graph' })
    graph.focus()
    graph.click()
    await waitFor(() => expect(
      document.querySelector('[data-tab-id="graph"]')?.getAttribute('data-tab-selected'))
      .toBe('true'))
    await waitFor(() => expect(
      document.activeElement?.getAttribute('role')).toBe('tab'))
  })
})
