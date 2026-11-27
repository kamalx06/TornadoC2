// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import ListenerDialog from '../src/renderer/src/features/ListenerDialog'

const invoke = vi.fn(async (method: string) => {
  if (method === 'listeners.certs') return { certs: ['a.pem'], keys: [], cas: [] }
  if (method === 'listeners.profiles') return { profiles: [{ name: 'chrome' }] }
  return { ok: true }
})

vi.mock('../src/renderer/src/hooks', () => ({
  invoke: (m: string, p: Record<string, unknown>) => invoke(m, p)
}))

afterEach(() => { cleanup(); invoke.mockClear() })

describe('listener dialog', () => {
  it('requires a name before creating', () => {
    render(<ListenerDialog editing={null} onClose={() => undefined}
      onDone={() => undefined} />)
    const create = screen.getByRole('button', { name: 'Create' }) as HTMLButtonElement
    expect(create.disabled).toBe(true)
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'edge' } })
    expect(create.disabled).toBe(false)
  })

  it('submits a normalised spec', async () => {
    const done = vi.fn()
    render(<ListenerDialog editing={null} onClose={() => undefined} onDone={done} />)
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'edge' } })
    fireEvent.change(screen.getByLabelText('Port'), { target: { value: '8443' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(done).toHaveBeenCalled())
    const call = invoke.mock.calls.find((c) => c[0] === 'listener.create')
    expect(call).toBeTruthy()
    const spec = (call![1] as { spec: Record<string, unknown> }).spec
    expect(spec).toMatchObject({ type: 'http', name: 'edge', port: '8443' })
    expect(spec).toHaveProperty('tls')
  })

  it('loads certificate options', async () => {
    render(<ListenerDialog editing={null} onClose={() => undefined} onDone={() => undefined} />)
    await screen.findByText('a.pem')
  })
})
