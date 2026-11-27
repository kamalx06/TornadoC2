// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import axe from 'axe-core'
import Jobs from '../src/renderer/src/features/Jobs'

let jobs = [
  { id: 'job-running', kind: 'upload', state: 'running', done: 10, total: 100, remote: '/tmp/a' },
  { id: 'job-done', kind: 'download', state: 'done', done: 10, total: 10, remote: '/etc/passwd' },
  { id: 'job-error', kind: 'build', state: 'error', done: 0, total: 1, error: 'compiler failed' }
]
const invoke = vi.fn(async () => ({}))
const toast = vi.fn()

vi.mock('../src/renderer/src/hooks', () => ({
  invoke: (m: string, p: Record<string, unknown>) => invoke(m, p),
  usePoll: () => ({ data: { jobs }, error: '', reload: () => undefined })
}))

beforeEach(() => {
  jobs = [
    { id: 'job-running', kind: 'upload', state: 'running', done: 10, total: 100, remote: '/tmp/a' },
    { id: 'job-done', kind: 'download', state: 'done', done: 10, total: 10, remote: '/etc/passwd' },
    { id: 'job-error', kind: 'build', state: 'error', done: 0, total: 1, error: 'compiler failed' }
  ]
  window.t2 = { clipboard: vi.fn(async () => true) } as unknown as typeof window.t2
})

afterEach(() => { cleanup(); invoke.mockClear(); toast.mockClear() })

describe('jobs', () => {
  it('keeps finished and failed jobs visible', () => {
    render(<Jobs onToast={toast} />)
    expect(screen.getByText('upload')).toBeTruthy()
    expect(screen.getByText('done')).toBeTruthy()
    expect(screen.getByText('error')).toBeTruthy()
    expect(screen.getByText('compiler failed')).toBeTruthy()
    expect(screen.getByRole('progressbar', { name: 'upload progress' })
      .getAttribute('aria-valuenow')).toBe('10')
  })

  it('keeps a job that vanished from the latest poll', () => {
    const { rerender } = render(<Jobs onToast={toast} />)
    jobs = jobs.filter((j) => j.id !== 'job-done')
    rerender(<Jobs onToast={toast} />)
    expect(screen.getByText('download')).toBeTruthy()
  })

  it('cancels only after confirmation', async () => {
    render(<Jobs onToast={toast} />)
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(await screen.findByRole('dialog')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel job' }))
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('job.cancel', {
      id: 'job-running'
    }))
    expect(toast).toHaveBeenCalled()
  })

  it('has no axe violations', () => {
    const { container } = render(<Jobs onToast={toast} />)
    return axe.run(container, {
      rules: { 'color-contrast': { enabled: false } }
    }).then((r) => expect(r.violations.map((v) => v.id)).toEqual([]))
  })
})
