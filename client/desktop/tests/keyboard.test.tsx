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

  it('opens the View menu with Alt+P and closes with Escape', async () => {
    await connect()
    fireEvent.keyDown(window, { key: 'p', altKey: true })
    const view = await screen.findByRole('menuitem', { name: 'View' })
    expect(view.getAttribute('aria-expanded')).toBe('true')
    fireEvent.keyDown(document.activeElement ?? window, { key: 'Escape' })
    await waitFor(() => expect(view.getAttribute('aria-expanded')).toBe('false'))
    expect(document.activeElement).toBe(view)
  })

  it('moves between menus with arrow keys', async () => {
    await connect()
    const file = screen.getByRole('menuitem', { name: 'File' })
    file.focus()
    fireEvent.keyDown(file, { key: 'ArrowRight' })
    await waitFor(() => expect(document.activeElement?.textContent).toBe('View'))
  })

  it('moves between workspaces with the keyboard', async () => {
    await connect()
    const trigger = screen.getByRole('button', { name: /Workspace:/ })
    trigger.focus()
    fireEvent.keyDown(trigger, { key: 'ArrowDown' })
    const list = await screen.findByRole('listbox', { name: 'Workspace' })
    fireEvent.keyDown(list, { key: 'ArrowDown' })
    await waitFor(() => expect(document.activeElement?.textContent)
      .toContain('Workspace 2'))
    fireEvent.keyDown(document.activeElement!, { key: 'Enter' })
    await waitFor(() => expect(localStorage.getItem('t2.workspace.active')).toBe('w2'))
  })

  it('opens the View menu and activates a panel with the keyboard', async () => {
    await connect()
    fireEvent.keyDown(window, { key: 'p', altKey: true })
    const graph = await screen.findByRole('menuitem', { name: 'Graph' })
    graph.focus()
    fireEvent.keyDown(graph, { key: 'Enter' })
    await waitFor(() => expect(
      document.querySelector('[data-tab-id="graph"]')?.getAttribute('data-tab-selected'))
      .toBe('true'))
    await waitFor(() => expect(
      document.activeElement?.getAttribute('role')).toBe('tab'))
  })
})
