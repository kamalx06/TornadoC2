// @vitest-environment jsdom
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import axe from 'axe-core'
import type { Beacon } from '../src/shared/ipc'
import Screen from '../src/renderer/src/features/Screen'

const PNG = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAFgwJ/lK3qWQAAAABJRU5ErkJggg=='
let mode: 'ok' | 'error' = 'ok'

const invoke = vi.fn(async (method: string) => {
  if (method === 'task') return { task_id: 's1' }
  if (method === 'task.result') {
    return mode === 'ok'
      ? { ready: true, output: PNG }
      : { ready: true, error: 'screenshot: GetDC failed' }
  }
  return {}
})

vi.mock('../src/renderer/src/hooks', () => ({
  invoke: (m: string, p: Record<string, unknown>, t?: number) =>
    t === undefined ? invoke(m, p) : invoke(m, p, t)
}))

const beacon: Beacon = { id: 4, display_name: 'bob@win', os: 'windows', arch: 'amd64', alive: true }

beforeAll(() => {
  window.t2 = {
    saveBinary: vi.fn(async () => '/tmp/screen.png'),
    clipboard: vi.fn(async () => true)
  } as unknown as typeof window.t2
})

afterEach(() => { cleanup(); invoke.mockClear(); mode = 'ok' })

function ui() {
  return render(<Screen beacon={beacon} onToast={() => undefined} />)
}

describe('screen viewer', () => {
  it('captures and renders a png', async () => {
    ui()
    fireEvent.click(screen.getByRole('button', { name: 'Capture' }))
    const img = await screen.findByRole('img', { name: /Screen of bob@win/ })
    expect(img.getAttribute('src')).toBe(`data:image/png;base64,${PNG}`)
    expect(screen.getByText(/last capture/)).toBeTruthy()
  })

  it('downloads the last capture', async () => {
    ui()
    fireEvent.click(screen.getByRole('button', { name: 'Capture' }))
    await screen.findByRole('img')
    fireEvent.click(screen.getByRole('button', { name: 'Download capture' }))
    await waitFor(() => expect(window.t2.saveBinary).toHaveBeenCalled())
    const args = vi.mocked(window.t2.saveBinary).mock.calls[0]!
    expect(args[1]).toBe(PNG)
  })

  it('surfaces capture errors inline', async () => {
    mode = 'error'
    ui()
    fireEvent.click(screen.getByRole('button', { name: 'Capture' }))
    expect((await screen.findByRole('alert')).textContent).toContain('GetDC failed')
    await waitFor(() => expect(screen.getByText('No capture yet')).toBeTruthy())
  })

  it('zooms and resets', () => {
    ui()
    fireEvent.click(screen.getByRole('button', { name: 'Zoom in' }))
    expect(screen.getByText('120%')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Reset view' }))
    expect(screen.getByText('100%')).toBeTruthy()
  })

  it('has no axe violations', async () => {
    const { container } = ui()
    fireEvent.click(screen.getByRole('button', { name: 'Capture' }))
    await screen.findByRole('img')
    const res = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } }
    })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })
})
