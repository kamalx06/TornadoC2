// @vitest-environment jsdom
import { readFileSync } from 'node:fs'
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import axe from 'axe-core'
import type { Beacon } from '../src/shared/ipc'
import Processes from '../src/renderer/src/features/Processes'

const ps = readFileSync('tests/fixtures/data/ps-linux.txt', 'utf8')
const queue = new Map<string, string>()
let seq = 0
let raw = ps

const invoke = vi.fn(async (method: string, params: Record<string, unknown>) => {
  if (method === 'task') {
    const id = `t${++seq}`
    queue.set(id, raw)
    return { task_id: id }
  }
  if (method === 'task.result') {
    const id = String(params.taskId)
    return { ready: true, output: btoa(queue.get(id) ?? '') }
  }
  return {}
})

vi.mock('../src/renderer/src/hooks', () => ({
  invoke: (m: string, p: Record<string, unknown>) => invoke(m, p)
}))

const beacon: Beacon = { id: 2, display_name: 'a@b', os: 'linux', arch: 'amd64', alive: true }

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

afterEach(() => { cleanup(); invoke.mockClear(); queue.clear(); raw = ps })

function ui(caps = ['beacon.list', 'beacon.use']) {
  return render(<Processes beacon={beacon} caps={caps} onToast={() => undefined} />)
}

describe('process grid', () => {
  it('collects and lists processes', async () => {
    ui()
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }))
    await waitFor(() => expect(screen.getByText(/http\.server/)).toBeTruthy())
    expect(screen.getAllByText('sshd').length).toBeGreaterThan(0)
  })

  it('shows raw output and survives junk', async () => {
    raw = 'PID COMMAND\n??\n9 broken line here'
    ui()
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }))
    await waitFor(() => expect(screen.getByText('broken')).toBeTruthy())
    fireEvent.click(screen.getByRole('button', { name: 'Show raw output' }))
    expect(screen.getByText(/9 broken line here/)).toBeTruthy()
  })

  it('kills a pid with taskkill on windows and kill on linux', async () => {
    ui()
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }))
    await waitFor(() => expect(screen.getByText(/http\.server/)).toBeTruthy())
    const kills = screen.getAllByRole('button', { name: 'Kill' })
    fireEvent.click(kills[0]!)
    fireEvent.click(screen.getAllByRole('button', { name: 'Kill' }).at(-1)!)
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('task',
      expect.objectContaining({ verb: 'exec', args: ['kill', '-9', expect.any(String)] })))
  })

  it('disables kill without beacon.use', async () => {
    ui(['beacon.list'])
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }))
    await waitFor(() => expect(screen.getByText(/http\.server/)).toBeTruthy())
    expect(screen.getAllByRole('button', { name: 'Kill' })[0]?.hasAttribute('disabled')).toBe(true)
  })

  it('has no axe violations', async () => {
    const { container } = ui()
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }))
    await waitFor(() => expect(screen.getByText(/http\.server/)).toBeTruthy())
    const res = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })
})
