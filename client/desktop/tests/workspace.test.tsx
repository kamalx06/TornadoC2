// @vitest-environment jsdom
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import axe from 'axe-core'
import App from '../src/renderer/src/App'

const invoke = vi.fn(async (method: string) => {
  let result: unknown = {}
  if (method === 'connect') {
    result = { name: 'operator', role: 'admin', caps: ['beacon.list', 'listener.view', 'beacon.build', 'beacon.use'] }
  } else if (method === 'beacons') result = []
  else if (method === 'listeners.health') result = { listeners: [] }
  else if (method === 'listeners') result = { listeners: [] }
  else if (method === 'graph') result = { nodes: [], edges: [] }
  else if (method === 'armory.list') result = { catalogue: [] }
  else if (method === 'chat.history') result = []
  else if (method === 'job.list') result = { jobs: [] }
  else if (method === 'creds.list') result = { creds: [] }
  else if (method === 'audit') result = { rows: [] }
  else if (method === 'build.profiles') result = { profiles: [] }
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
  await waitFor(() => expect(screen.getAllByRole('tab').length).toBeGreaterThan(5))
}

describe('workspace', () => {
  it('replaces the view switcher with a dock', async () => {
    await connect()
    expect(document.querySelector('[data-workspace]')).toBeTruthy()
    expect(screen.queryByRole('navigation', { name: 'Sections' })).toBeNull()
    expect(document.querySelectorAll('[role="tab"][data-tab]')).toHaveLength(7)
    expect(screen.getByLabelText('Filter targets')).toBeTruthy()
  })

  it('filters group menus by capability', async () => {
    await connect()
    fireEvent.click(screen.getByRole('button', { name: 'Assets' }))
    expect(screen.getByRole('menuitem', { name: 'Listeners' })).toBeTruthy()
    expect(screen.queryByRole('menuitem', { name: 'Armory' })).toBeNull()
    fireEvent.keyDown(document, { key: 'Escape' })
  })

  it('opens a panel from the rail', async () => {
    await connect()
    fireEvent.click(screen.getByRole('button', { name: 'Assets' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Listeners' }))
    await waitFor(() => expect(
      document.querySelector('[data-tab-id="listeners"]')
        ?.getAttribute('data-tab-selected')).toBe('true'))
  })

  it('moves the active tab with alt+digit', async () => {
    await connect()
    const targets = screen.getByRole('tab', { name: /Targets/ })
    fireEvent.click(targets)
    fireEvent.keyDown(targets, { key: '3', altKey: true })
    expect(document.querySelector('[data-tabset-id="dock-right"]')
      ?.textContent).toContain('Targets')
  })

  it('detaches the active panel', async () => {
    await connect()
    fireEvent.click(document.querySelector('[data-tab-id="graph"]')!)
    fireEvent.click(screen.getByRole('button', { name: 'Detach active panel' }))
    expect(window.t2.detach).toHaveBeenCalledWith('graph')
  })

  it('auto-attaches to an existing bridge session', async () => {
    vi.mocked(window.t2.status).mockResolvedValueOnce({
      connected: true, config: '/tmp/op.cfg', operator: 'op', role: 'admin',
      caps: ['beacon.list'], platform: 'linux'
    })
    render(<App />)
    await waitFor(() => expect(
      document.querySelectorAll('[role="tab"][data-tab]')).toHaveLength(7))
    expect(screen.queryByRole('button', { name: /^connect$/i })).toBeNull()
    expect(screen.getByText('op')).toBeTruthy()
  })

  it('applies and persists a profile, then marks custom', async () => {
    await connect()
    fireEvent.click(screen.getByRole('tab', { name: /Investigation/ }))
    await waitFor(() => expect(
      document.querySelector('[data-tabset-id="dock-center"] [data-tab-id="audit"]')
        ?.getAttribute('data-tab-selected')).toBe('true'))
    expect(localStorage.getItem('t2.dock.profile')).toBe('investigation')
    fireEvent.click(document.querySelector('[data-tabset-id="dock-center"] [data-tab-id="audit"]')!)
    fireEvent.keyDown(document.querySelector('.dock')!, { key: 'Delete' })
    await waitFor(() => expect(screen.getByText('custom')).toBeTruthy())
  })

  it('opens build and jump from the titlebar', async () => {
    await connect()
    fireEvent.click(screen.getByRole('button', { name: 'Build agent' }))
    expect(await screen.findByRole('dialog')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    fireEvent.click(screen.getByRole('button', { name: 'Jump to host' }))
    expect(await screen.findByRole('dialog')).toBeTruthy()
  })

  it('maximises from the titlebar double click', async () => {
    await connect()
    fireEvent.doubleClick(document.querySelector('.titlebar')!)
    expect(window.t2.windowControl).toHaveBeenCalledWith('max')
  })

  it('tracks live counts and the clock in the status bar', async () => {
    await connect()
    expect(screen.getByText('0 dead')).toBeTruthy()
    await waitFor(() => expect(
      document.querySelector('.clock')?.textContent).toMatch(/^\d{2}:\d{2}:\d{2}Z$/))
  })

  it('remembers the last config path', async () => {
    await connect()
    expect(localStorage.getItem('t2:recent-cfg')).toContain('/tmp/op.cfg')
  })

  it('has no axe violations with the dock mounted', async () => {
    await connect()
    const res = await axe.run(document.body, {
      rules: { 'color-contrast': { enabled: false } }
    })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })
})
