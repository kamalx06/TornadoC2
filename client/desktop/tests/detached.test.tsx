// @vitest-environment jsdom
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import axe from 'axe-core'

const invoke = vi.fn(async (method: string) => {
  let result: unknown = {}
  if (method === 'graph') result = { nodes: [], edges: [] }
  else if (method === 'beacons') result = []
  else if (method === 'listeners.health') result = { listeners: [] }
  return { ok: true, result }
})

let App: typeof import('../src/renderer/src/App').default

beforeAll(async () => {
  history.replaceState(null, '', '#detach/graph')
  window.t2 = {
    invoke,
    status: vi.fn(async () => ({
      connected: true, config: '/tmp/op.cfg', operator: 'op', role: 'admin',
      caps: ['beacon.list'], platform: 'linux'
    })),
    pickConfig: vi.fn(async () => ''),
    clipboard: vi.fn(async () => true),
    saveFile: vi.fn(async () => ''),
    detach: vi.fn(async () => true),
    onLog: () => () => undefined,
    onUpdate: () => () => undefined,
    onConn: () => () => undefined,
    windowControl: vi.fn(async () => true)
  } as unknown as typeof window.t2
  App = (await import('../src/renderer/src/App')).default
})

afterEach(() => { cleanup(); localStorage.clear(); invoke.mockClear() })

describe('detached window', () => {
  it('opens the same dock with one slot', async () => {
    render(<App />)
    await waitFor(() => expect(
      document.querySelector('[data-tab-id="graph"]')).toBeTruthy())
    expect(document.querySelector('nav.rail')).toBeNull()
    expect(document.querySelector('.profiles')).toBeNull()
    expect(document.title).toContain('Graph')
  })

  it('keeps a separate layout key from the main window', async () => {
    render(<App />)
    await waitFor(() => expect(screen.getByRole('button', { name: 'Panels' })).toBeTruthy())
    fireEvent.click(screen.getByRole('button', { name: 'Panels' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Targets' }))
    await waitFor(() => expect(
      localStorage.getItem('t2.dock.detach.graph') ?? '').toContain('targets'))
    expect(localStorage.getItem('t2.dock.v1')).toBeNull()
  })

  it('has no axe violations', async () => {
    const { container } = render(<App />)
    await waitFor(() => expect(
      document.querySelector('[data-tab-id="graph"]')).toBeTruthy())
    const res = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } }
    })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })

  it('resets back to the detached panel', async () => {
    render(<App />)
    await waitFor(() => expect(
      document.querySelector('[data-tab-id="graph"]')).toBeTruthy())
    fireEvent.click(screen.getByRole('button', { name: 'Panels' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Events' }))
    await waitFor(() => expect(
      document.querySelector('[data-tab-id="events"]')).toBeTruthy())
    fireEvent.click(screen.getByRole('button', { name: 'Reset layout' }))
    await waitFor(() => expect(
      document.querySelectorAll('[role="tab"][data-tab]')).toHaveLength(1))
    expect(document.querySelector('[data-tab-id="graph"]')).toBeTruthy()
  })
})
