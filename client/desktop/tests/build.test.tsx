// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import BuildDialog from '../src/renderer/src/features/BuildDialog'

const options = {
  oses: ['windows', 'linux'], arches: ['amd64'], formats: {
    linux: ['elf', 'stager'], windows: ['exe', 'dll']
  },
  transports: [
    { id: 'http', label: 'HTTP', description: '', platforms: ['linux', 'windows'], exclusive: false, fields: ['url', 'tls_profile', 'c2_profile'] },
    { id: 'smb', label: 'SMB', description: '', platforms: ['windows'], exclusive: true, fields: ['smb_pipe'] }
  ],
  fields: [
    { name: 'url', type: 'url', required: true },
    { name: 'tls_profile', type: 'choice', required: false },
    { name: 'c2_profile', type: 'profile', required: false },
    { name: 'smb_pipe', type: 'text', required: true }
  ], tls_profiles: ['chrome'], sleep_masks: ['none'],
  syscall_methods: ['direct'], inject_methods: ['default'],
  jump_methods: [], persistence: [], evasion: [],
  defaults: {}, relay_fields: []
}

const invoke = vi.fn(async (m: string) => {
  if (m === 'build.options') {
    return { options, profiles: [{ name: 'chrome' }] }
  }
  if (m === 'build.validate') return { ok: true, errors: [] }
  if (m === 'build.config.import') return { target_os: 'linux', _doc: 'x' }
  return {}
})

vi.mock('../src/renderer/src/hooks', () => ({
  invoke: (m: string, p: Record<string, unknown>) => invoke(m, p)
}))

afterEach(() => { cleanup(); invoke.mockClear() })

describe('build dialog', () => {
  it('exposes the advanced drawer', async () => {
    render(<BuildDialog onClose={() => undefined} onDone={() => undefined} />)
    await waitFor(() => expect(screen.getByRole('checkbox', { name: 'HTTP' })).toBeTruthy())
    expect(screen.getByText('Advanced')).toBeTruthy()
    fireEvent.click(screen.getByText('Advanced'))
    expect(screen.getByLabelText('C2 profile')).toBeTruthy()
    expect(screen.getByLabelText('TCP relay target')).toBeTruthy()
  })

  it('changes fields when the transport changes', async () => {
    render(<BuildDialog onClose={() => undefined} onDone={() => undefined} />)
    await waitFor(() => expect(screen.getByRole('checkbox', { name: 'SMB' })).toBeTruthy())
    fireEvent.click(screen.getByRole('checkbox', { name: 'SMB' }))
    expect(screen.getByLabelText('Pipe name or UNC path')).toBeTruthy()
    expect(screen.queryByLabelText('Callback URL')).toBeNull()
    const formats = screen.getByLabelText('Format') as HTMLSelectElement
    expect([...formats.options].map((o) => o.value)).toEqual(['exe', 'dll'])
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
