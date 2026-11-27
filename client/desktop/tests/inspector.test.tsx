// @vitest-environment jsdom
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import axe from 'axe-core'
import type { Beacon } from '../src/shared/ipc'
import TargetActions from '../src/renderer/src/features/TargetActions'

const invoke = vi.fn(async (method: string) => {
  if (method === 'task') return { task_id: 't1' }
  if (method === 'task.result') return { ready: true, output: btoa('ok\n') }
  if (method === 'beacon.note') return { notes: [{ text: 'domain admin' }] }
  return {}
})

vi.mock('../src/renderer/src/hooks', () => ({
  invoke: (m: string, p: Record<string, unknown>) => invoke(m, p)
}))

const beacon: Beacon = {
  id: 7, display_name: 'alice@dc01', alias: 'pivot', os: 'windows',
  arch: 'amd64', alive: true, last_seen_age: 4, privilege: 'system',
  elevated: true, integrity: 'system', parent_name: 'explorer.exe',
  fingerprint: 'abc123', checkins: 9, last_addr: '10.0.0.7',
  sleep_interval: 60, viewers: [{ name: 'op' }]
}

beforeAll(() => {
  window.t2 = {
    clipboard: vi.fn(async () => true),
    pickOpen: vi.fn(async () => ''),
    pickConfig: vi.fn(async () => '')
  } as unknown as typeof window.t2
})

afterEach(() => { cleanup(); invoke.mockClear(); onConsole.mockClear() })

const onConsole = vi.fn()

function ui() {
  return render(<TargetActions beacon={beacon} caps={['beacon.socks']}
    onConsole={onConsole}
    onToast={() => undefined} onChanged={() => undefined} />)
}

describe('target inspector', () => {
  it('shows identity, session and network sections', () => {
    ui()
    expect(screen.getByText('Identity')).toBeTruthy()
    expect(screen.getByText('Session')).toBeTruthy()
    expect(screen.getAllByText('alice@dc01').length).toBeGreaterThan(0)
    expect(screen.getByText('10.0.0.7')).toBeTruthy()
    expect(screen.getByText('abc123')).toBeTruthy()
  })

  it('copies facts with auto-clear', () => {
    ui()
    fireEvent.click(screen.getByRole('button', { name: 'Copy beacon id' }))
    expect(window.t2.clipboard).toHaveBeenCalledWith('7', 30_000)
  })

  it('sets an alias through the prompt', async () => {
    ui()
    fireEvent.click(screen.getByRole('button', { name: 'Alias…' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'alias' }), {
      target: { value: 'edge' }
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('beacon.alias', {
      id: 7, alias: 'edge'
    }))
  })

  it('hands execution to the console', () => {
    ui()
    fireEvent.click(screen.getByRole('button', { name: 'whoami' }))
    expect(onConsole).toHaveBeenCalledWith('whoami')
    fireEvent.click(screen.getByRole('button', { name: 'Open console' }))
    expect(onConsole).toHaveBeenCalledWith()
    expect(invoke).not.toHaveBeenCalledWith('task', expect.anything())
  })

  it('loads notes', async () => {
    ui()
    fireEvent.click(screen.getByText('Notes (0)'))
    fireEvent.click(screen.getByRole('button', { name: 'Load notes' }))
    await waitFor(() => expect(screen.getByText('domain admin')).toBeTruthy())
  })

  it('has no axe violations', async () => {
    const { container } = ui()
    const res = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } }
    })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })
})
