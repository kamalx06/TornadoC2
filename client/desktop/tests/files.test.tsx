// @vitest-environment jsdom
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import axe from 'axe-core'
import type { Beacon } from '../src/shared/ipc'
import Files from '../src/renderer/src/features/Files'

const queue = new Map<string, string>()
let seq = 0

const invoke = vi.fn(async (method: string, params: Record<string, unknown>) => {
  if (method === 'task') {
    const id = `t${++seq}`
    const verb = String(params.verb)
    const args = (params.args ?? []) as string[]
    let out = ''
    if (verb === 'pwd') out = '/var/www\n'
    else if (verb === 'find') {
      const base = args[0]
      const dir = args.includes('d')
      if (base === '/var/www') out = dir ? '/var/www/site\n' : '/var/www/robots.txt\n'
      else if (base === '/var/www/site') {
        out = dir ? '/var/www/site/assets\n' : '/var/www/site/index.html\n'
      }
    }
    queue.set(id, out)
    return { task_id: id }
  }
  if (method === 'task.result') {
    return { ready: true, output: btoa(queue.get(String(params.taskId)) ?? '') }
  }
  if (method === 'download.start') return {}
  return {}
})

vi.mock('../src/renderer/src/hooks', () => ({
  invoke: (m: string, p: Record<string, unknown>) => invoke(m, p)
}))

const beacon: Beacon = { id: 8, display_name: 'x@y', os: 'linux', arch: 'amd64', alive: true }

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
  return render(<Files beacon={beacon} caps={caps} onToast={() => undefined} />)
}

describe('file grid', () => {
  it('starts in pwd and separates dirs from files', async () => {
    ui()
    await waitFor(() => expect(
      document.querySelectorAll('.dg-row').length).toBeGreaterThan(1))
    expect(document.querySelectorAll('.datagrid').length).toBe(1)
    expect(screen.getAllByText(/robots\.txt/).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/site/).length).toBeGreaterThan(0)
    expect(screen.getAllByText('dir').length).toBeGreaterThan(0)
    expect(screen.getAllByText('file').length).toBeGreaterThan(0)
    const crumbs = screen.getByRole('navigation', { name: 'Path' })
    expect(crumbs.textContent).toContain('var')
  })

  it('navigates into a directory and back up', async () => {
    ui()
    await waitFor(() => expect(screen.getByRole('button', { name: /site/ })).toBeTruthy())
    fireEvent.click(screen.getByRole('button', { name: /site/ }))
    await waitFor(() => expect(
      screen.getAllByText(/index\.html/).length).toBeGreaterThan(0))
    fireEvent.click(screen.getByRole('button', { name: 'Parent directory' }))
    await waitFor(() => expect(
      screen.getAllByText(/robots\.txt/).length).toBeGreaterThan(0))
  })

  it('queues a download for a file', async () => {
    ui()
    await waitFor(() => expect(
      screen.getAllByText(/robots\.txt/).length).toBeGreaterThan(0))
    const row = screen.getAllByText(/robots\.txt/)[0]!
      .closest('[role="row"]') as HTMLElement
    fireEvent.click(row.querySelector('[role="cell"]:last-child button:nth-child(2)')!)
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('download.start', {
      id: 8, remote: '/var/www/robots.txt'
    }))
  })

  it('keeps raw output available', async () => {
    ui()
    await waitFor(() => expect(
      screen.getAllByText(/robots\.txt/).length).toBeGreaterThan(0))
    fireEvent.click(screen.getByRole('button', { name: 'Show raw output' }))
    expect(screen.getAllByText(/\/var\/www\/site/).length).toBeGreaterThan(0)
  })

  it('has no axe violations', async () => {
    const { container } = ui()
    await waitFor(() => expect(
      screen.getAllByText(/robots\.txt/).length).toBeGreaterThan(0))
    const res = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })
})
