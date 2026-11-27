// @vitest-environment jsdom
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { act } from 'react'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import axe from 'axe-core'
import type { Beacon } from '../src/shared/ipc'
import Terminal from '../src/renderer/src/features/Terminal'
import { append, clearTranscript } from '../src/renderer/src/lib/transcripts'

const invoke = vi.fn(async (method: string) => {
  if (method === 'commands') return { beacon: ['whoami', 'ps', 'screenshot'] }
  if (method === 'task') return { task_id: 't1' }
  if (method === 'task.result') return { ready: true, output: btoa('alice\n') }
  if (method === 'shell') return { output: btoa('shell-out\n') }
  return {}
})

vi.mock('../src/renderer/src/hooks', () => ({
  invoke: (m: string, p: Record<string, unknown>, t?: number) =>
    t === undefined ? invoke(m, p) : invoke(m, p, t)
}))

const beacon: Beacon = {
  id: 3, display_name: 'alice@host', os: 'linux', arch: 'amd64', alive: true
}

beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, 'clientHeight', {
    configurable: true, get: () => 400
  })
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({
    width: 800, height: 400, top: 0, left: 0, bottom: 400, right: 800,
    x: 0, y: 0, toJSON: () => ({})
  } as DOMRect)
  window.t2 = {
    saveFile: vi.fn(async () => '/tmp/transcript.txt'),
    clipboard: vi.fn(async () => true)
  } as unknown as typeof window.t2
})

afterEach(() => { cleanup(); invoke.mockClear(); clearTranscript(3) })

function ui() {
  return render(<Terminal beacon={beacon} onToast={() => undefined} />)
}

describe('terminal', () => {
  it('suggests verbs and completes with the keyboard', async () => {
    ui()
    const input = screen.getByLabelText('Command') as HTMLInputElement
    fireEvent.change(input, { target: { value: 'wh' } })
    const options = await screen.findAllByRole('option')
    expect(options[0]?.textContent).toBe('whoami')
    fireEvent.keyDown(input, { key: 'Tab' })
    expect(input.value).toBe('whoami ')
  })

  it('runs a task and prints decoded output with a timestamp', async () => {
    ui()
    const input = screen.getByLabelText('Command')
    fireEvent.change(input, { target: { value: 'whoami' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    await waitFor(() => expect(screen.getByText('alice')).toBeTruthy())
    expect(document.querySelector('.term-line.out .term-time')).toBeTruthy()
    expect(invoke).toHaveBeenCalledWith('task', { id: 3, verb: 'whoami', args: [] })
  })

  it('recalls history with arrow up', async () => {
    ui()
    const input = screen.getByLabelText('Command') as HTMLInputElement
    fireEvent.change(input, { target: { value: 'ps' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('task',
      { id: 3, verb: 'ps', args: [] }))
    fireEvent.keyDown(input, { key: 'ArrowUp' })
    expect(input.value).toBe('ps')
  })

  it('toggles raw base64 output', async () => {
    ui()
    const input = screen.getByLabelText('Command')
    fireEvent.change(input, { target: { value: 'whoami' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    await waitFor(() => expect(screen.getByText('alice')).toBeTruthy())
    fireEvent.click(screen.getByRole('button', { name: 'Show raw base64' }))
    expect(screen.getByText(btoa('alice\n'))).toBeTruthy()
  })

  it('saves and clears the transcript', async () => {
    const { unmount } = ui()
    const input = screen.getByLabelText('Command')
    fireEvent.change(input, { target: { value: 'whoami' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    await waitFor(() => expect(screen.getByText('alice')).toBeTruthy())
    fireEvent.click(screen.getByRole('button', { name: 'Save transcript' }))
    await waitFor(() => expect(window.t2.saveFile).toHaveBeenCalled())
    unmount()
    render(<Terminal beacon={beacon} onToast={() => undefined} />)
    await waitFor(() => expect(screen.getByText('alice')).toBeTruthy())
    fireEvent.click(screen.getByRole('button', { name: 'Clear transcript' }))
    expect(screen.queryByText('alice')).toBeNull()
  })

  it('starts a shell and sends through it', async () => {
    ui()
    fireEvent.click(screen.getByRole('button', { name: 'Start shell' }))
    await waitFor(() => expect(screen.getByText('shell started')).toBeTruthy())
    fireEvent.change(screen.getByLabelText('Command'), { target: { value: 'id' } })
    fireEvent.keyDown(screen.getByLabelText('Command'), { key: 'Enter' })
    await waitFor(() => expect(screen.getByText('shell-out')).toBeTruthy())
    expect(invoke).toHaveBeenCalledWith('shell', expect.objectContaining({
      id: 3, action: 'exec', command: 'id'
    }), 90_000)
  })

  it('accepts a console prefill and external transcript writes', async () => {
    const used = vi.fn()
    render(<Terminal beacon={beacon} onToast={() => undefined}
      prefill={{ text: 'whoami', n: 1 }} onPrefillUsed={used} />)
    await waitFor(() => expect(
      (screen.getByLabelText('Command') as HTMLInputElement).value).toBe('whoami'))
    expect(used).toHaveBeenCalled()
    act(() => append(3, { kind: 'out', text: 'injected output' }))
    expect(await screen.findByText('injected output')).toBeTruthy()
  })

  it('has no axe violations', async () => {
    const { container } = ui()
    const res = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } }
    })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })
})
