// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import BuildDialog from '../src/renderer/src/features/BuildDialog'

const invoke = vi.fn(async (m: string) => {
  if (m === 'build.profiles') return { profiles: [{ name: 'chrome' }] }
  if (m === 'build.config.import') return { target_os: 'linux', _doc: 'x' }
  return {}
})

vi.mock('../src/renderer/src/hooks', () => ({
  invoke: (m: string, p: Record<string, unknown>) => invoke(m, p)
}))

afterEach(() => { cleanup(); invoke.mockClear() })

describe('build dialog', () => {
  it('exposes the advanced drawer', () => {
    render(<BuildDialog onClose={() => undefined} onDone={() => undefined} />)
    expect(screen.getByText('Advanced')).toBeTruthy()
    fireEvent.click(screen.getByText('Advanced'))
    expect(screen.getByLabelText('C2 profile')).toBeTruthy()
    expect(screen.getByLabelText('TCP relay target')).toBeTruthy()
  })

  it('imports a config file', async () => {
    ;(window as unknown as { t2: { pickOpen: () => Promise<string> } }).t2 = {
      pickOpen: async () => '/tmp/cfg.json'
    }
    render(<BuildDialog onClose={() => undefined} onDone={() => undefined} />)
    fireEvent.click(screen.getByText('Load config…'))
    await waitFor(() => expect(invoke).toHaveBeenCalledWith(
      'build.config.import', { path: '/tmp/cfg.json' }))
    await waitFor(() => expect(
      (screen.getByLabelText('OS') as HTMLSelectElement).value).toBe('linux'))
  })
})
