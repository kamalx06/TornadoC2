// @vitest-environment jsdom
import { readFileSync } from 'node:fs'
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import axe from 'axe-core'
import type { Beacon } from '../src/shared/ipc'
import Network from '../src/renderer/src/features/Network'

const net = readFileSync('tests/fixtures/data/netstat-windows.txt', 'utf8')
const ps = readFileSync('tests/fixtures/data/ps-windows.txt', 'utf8')
const queue = new Map<string, string>()
let seq = 0

const invoke = vi.fn(async (method: string, params: Record<string, unknown>) => {
  if (method === 'task') {
    const id = `t${++seq}`
    const verb = String(params.verb)
    queue.set(id, verb === 'netstat' ? net : ps)
    return { task_id: id }
  }
  if (method === 'task.result') {
    return { ready: true, output: btoa(queue.get(String(params.taskId)) ?? '') }
  }
  return {}
})

vi.mock('../src/renderer/src/hooks', () => ({
  invoke: (m: string, p: Record<string, unknown>) => invoke(m, p)
}))

const beacon: Beacon = { id: 5, display_name: 'w@h', os: 'windows', arch: 'amd64', alive: true }

beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, 'clientHeight', {
    configurable: true, get: () => 400
  })
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({
    width: 900, height: 400, top: 0, left: 0, bottom: 400, right: 900,
    x: 0, y: 0, toJSON: () => ({})
  } as DOMRect)
  window.t2 = { clipboard: vi.fn(async () => true) } as unknown as typeof window.t2
})

afterEach(() => { cleanup(); invoke.mockClear(); queue.clear() })

function ui(caps = ['beacon.list', 'beacon.use']) {
  return render(<Network beacon={beacon} caps={caps} onToast={() => undefined} />)
}

describe('network grid', () => {
  it('lists connections and correlates the owning process', async () => {
    ui()
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }))
    await waitFor(() => expect(screen.getByText('10.0.0.1:443')).toBeTruthy())
    expect(screen.getAllByText('explorer.exe').length).toBeGreaterThan(0)
    expect(screen.getByText('ESTABLISHED')).toBeTruthy()
  })

  it('kills the owning pid after confirmation', async () => {
    ui()
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }))
    await waitFor(() => expect(screen.getByText('10.0.0.1:443')).toBeTruthy())
    fireEvent.click(screen.getAllByRole('button', { name: 'Kill' })[1]!)
    const buttons = screen.getAllByRole('button', { name: 'Kill' })
    fireEvent.click(buttons.at(-1)!)
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('task',
      expect.objectContaining({
        verb: 'exec', args: ['taskkill', '/PID', '4412', '/F']
      })))
  })

  it('shows raw output', async () => {
    ui()
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }))
    await waitFor(() => expect(screen.getByText('10.0.0.1:443')).toBeTruthy())
    fireEvent.click(screen.getByRole('button', { name: 'Show raw output' }))
    expect(screen.getByText(/Proto/)).toBeTruthy()
  })

  it('has no axe violations', async () => {
    const { container } = ui()
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }))
    await waitFor(() => expect(screen.getByText('10.0.0.1:443')).toBeTruthy())
    const res = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })
})
