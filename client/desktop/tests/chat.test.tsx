// @vitest-environment jsdom
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import axe from 'axe-core'
import type { ChatMessage } from '../src/shared/ipc'
import Chat from '../src/renderer/src/features/Chat'

let messages: ChatMessage[] = []
let fail = false
const reload = vi.fn()
const invoke = vi.fn(async (method: string) => {
  if (method === 'chat.send') {
    if (fail) throw new Error('rate limited')
    return {}
  }
  return {}
})

vi.mock('../src/renderer/src/hooks', () => ({
  invoke: (m: string, p: Record<string, unknown>) => invoke(m, p),
  usePoll: () => ({ data: { messages, topic: { text: 'dc01' } }, error: '', reload })
}))

beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, 'clientHeight', {
    configurable: true, get: () => 400
  })
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({
    width: 900, height: 400, top: 0, left: 0, bottom: 400, right: 900,
    x: 0, y: 0, toJSON: () => ({})
  } as DOMRect)
})

beforeEach(() => {
  fail = false
  messages = [
    { id: 1, ts: Date.now() / 1000 - 120, operator: 'alice', text: 'holding dc01' },
    { id: 2, ts: Date.now() / 1000 - 60, operator: 'alice', text: 'second line' },
    { id: 3, ts: Date.now() / 1000 - 30, operator: 'bob', text: 'copy that', kind: 'action' }
  ]
  window.t2 = { clipboard: vi.fn(async () => true) } as unknown as typeof window.t2
})

afterEach(() => { cleanup(); invoke.mockClear(); reload.mockClear() })

describe('chat', () => {
  it('separates days and groups consecutive operators', () => {
    render(<Chat me="bob" />)
    expect(screen.getByText('Today')).toBeTruthy()
    expect(screen.getByText('holding dc01')).toBeTruthy()
    // alice's second message is grouped: only one author header for her.
    expect(screen.getAllByText('alice')).toHaveLength(1)
    expect(screen.getByText('you')).toBeTruthy()
  })

  it('sends on Enter and clears the box', async () => {
    render(<Chat me="bob" />)
    const input = screen.getByLabelText('Chat message')
    fireEvent.change(input, { target: { value: 'moving' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('chat.send', { text: 'moving' }))
    expect((input as HTMLTextAreaElement).value).toBe('')
  })

  it('keeps the text and offers retry after failure', async () => {
    fail = true
    render(<Chat me="bob" />)
    const input = screen.getByLabelText('Chat message') as HTMLTextAreaElement
    fireEvent.change(input, { target: { value: 'important' } })
    fireEvent.click(screen.getByRole('button', { name: 'Send' }))
    await waitFor(() => expect(screen.getByText(/send failed/)).toBeTruthy())
    expect(input.value).toBe('important')
    fail = false
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(input.value).toBe(''))
    expect(invoke).toHaveBeenCalledTimes(2)
  })

  it('has no axe violations', async () => {
    const { container } = render(<Chat me="bob" />)
    const res = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } }
    })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })
})
