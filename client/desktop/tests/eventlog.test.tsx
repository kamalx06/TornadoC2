// @vitest-environment jsdom
import { act } from 'react'
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import axe from 'axe-core'
import EventLog from '../src/renderer/src/features/EventLog'
import { clear, push } from '../src/renderer/src/lib/events'

const auditRows = [{ id: 'a1', operator: 'op', action: 'beacon.task', outcome: 'ok' }]
vi.mock('../src/renderer/src/hooks', () => ({
  usePoll: () => ({ data: auditRows, error: '', reload: () => undefined })
}))

beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, 'clientHeight', {
    configurable: true, get: () => 300
  })
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({
    width: 900, height: 300, top: 0, left: 0, bottom: 300, right: 900,
    x: 0, y: 0, toJSON: () => ({})
  } as DOMRect)
})

beforeEach(() => {
  clear()
  window.t2 = { saveFile: vi.fn(async () => '/tmp/events.log') } as unknown as typeof window.t2
})

afterEach(cleanup)

const seed = () => {
  act(() => {
    push('info', 'bridge', 'connected')
    push('err', 'bridge', 'bridge lost')
    push('warn', 'system', 'certificate expires soon')
    push('task', 'task', '→ whoami on #1')
  })
}

describe('event log', () => {
  it('merges audit rows and renders sources', async () => {
    render(<EventLog onToast={() => undefined} />)
    await waitFor(() => expect(screen.getByText(/beacon\.task/)).toBeTruthy())
  })

  it('filters by level, source and text', () => {
    seed()
    render(<EventLog onToast={() => undefined} />)
    expect(screen.getByText('bridge lost')).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Level filter'), { target: { value: 'err' } })
    expect(screen.queryByText('connected')).toBeNull()
    expect(screen.getByText('bridge lost')).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Level filter'), { target: { value: 'all' } })
    fireEvent.change(screen.getByLabelText('Source filter'), { target: { value: 'system' } })
    expect(screen.queryByText('bridge lost')).toBeNull()
    fireEvent.change(screen.getByLabelText('Source filter'), { target: { value: 'all' } })
    fireEvent.change(screen.getByLabelText('Search events'), { target: { value: 'whoami' } })
    expect(screen.queryByText('bridge lost')).toBeNull()
    expect(screen.getByText(/whoami/)).toBeTruthy()
  })

  it('freezes the view while paused but keeps collecting', () => {
    seed()
    render(<EventLog onToast={() => undefined} />)
    fireEvent.click(screen.getByRole('button', { name: 'Pause events' }))
    act(() => push('err', 'bridge', 'after pause'))
    expect(screen.queryByText('after pause')).toBeNull()
    expect(screen.getByText('paused')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Resume events' }))
    expect(screen.getByText('after pause')).toBeTruthy()
  })

  it('saves and clears', async () => {
    seed()
    render(<EventLog onToast={() => undefined} />)
    fireEvent.click(screen.getByRole('button', { name: 'Save visible events' }))
    await waitFor(() => expect(window.t2.saveFile).toHaveBeenCalled())
    expect((vi.mocked(window.t2.saveFile).mock.calls[0]![1])).toContain('bridge lost')
    fireEvent.click(screen.getByRole('button', { name: 'Clear events' }))
    expect(screen.queryByText('bridge lost')).toBeNull()
  })

  it('has no axe violations', () => {
    seed()
    const { container } = render(<EventLog onToast={() => undefined} />)
    const res = axe.run(container, {
      rules: { 'color-contrast': { enabled: false } }
    })
    return res.then((r) => expect(r.violations.map((v) => v.id)).toEqual([]))
  })
})
