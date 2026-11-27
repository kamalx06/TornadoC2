// @vitest-environment jsdom
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import axe from 'axe-core'
import Armory from '../src/renderer/src/features/Armory'

const rows = [
  { name: 'ok', format: 'coff-x64', description: 'works',
    version: '1.0.0', installed: false },
  { name: 'old', format: 'coff-x64', description: 'outdated',
    version: '2.0.0', installed: true, installed_version: '1.0.0' },
  { name: 'same', format: 'coff-x64', description: 'current',
    version: '1.0.0', installed: true, installed_version: '1.0.0' }
]
const invoke = vi.fn(async (method: string) => {
  if (method === 'armory.list') {
    return { repo: 'https://github.com/kamalx06/tornadoc2-armory',
      branch: 'main', catalogue: rows, error: '' }
  }
  return { done: [{ name: 'ok' }] }
})
vi.mock('../src/renderer/src/hooks', () => ({
  invoke: (m: string, p: Record<string, unknown>) => invoke(m, p)
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
  invoke.mockClear()
  window.confirm = vi.fn(() => true)
})

afterEach(cleanup)

describe('armory', () => {
  it('shows the locked source and no URL input', async () => {
    render(<Armory caps={['armory.view', 'armory.manage']}
      onToast={() => undefined} />)
    await waitFor(() => expect(screen.getByText(/kamalx06\/tornadoc2-armory/)).toBeTruthy())
    expect(document.querySelectorAll('input').length).toBe(0)
    expect(screen.getByText(/locked/)).toBeTruthy()
  })

  it('offers install, update and up-to-date states', async () => {
    render(<Armory caps={['armory.view', 'armory.manage']}
      onToast={() => undefined} />)
    await waitFor(() => expect(screen.getByRole('button', { name: 'Install' })).toBeTruthy())
    expect(screen.getByRole('button', { name: 'Update' })).toBeTruthy()
    const current = screen.getByRole('button', { name: 'Up to date' })
    expect((current as HTMLButtonElement).disabled).toBe(true)
  })

  it('installs and removes with confirmation', async () => {
    render(<Armory caps={['armory.view', 'armory.manage']}
      onToast={() => undefined} />)
    await waitFor(() => expect(screen.getByRole('button', { name: 'Install' })).toBeTruthy())
    fireEvent.click(screen.getByRole('button', { name: 'Install' }))
    await waitFor(() => expect(invoke).toHaveBeenCalledWith(
      'armory.install', { names: ['ok'], replace: true }))
    fireEvent.click(screen.getAllByRole('button', { name: 'Remove' })[0]!)
    await waitFor(() => expect(window.confirm).toHaveBeenCalled())
    await waitFor(() => expect(invoke).toHaveBeenCalledWith(
      'armory.uninstall', { names: ['old'], replace: true }))
  })

  it('is read-only without armory.manage', async () => {
    render(<Armory caps={['armory.view']} onToast={() => undefined} />)
    await waitFor(() => expect(screen.getByRole('button', { name: 'Install' })).toBeTruthy())
    expect((screen.getByRole('button', { name: 'Install' }) as HTMLButtonElement).disabled)
      .toBe(true)
  })

  it('has no axe violations', async () => {
    const { container } = render(<Armory caps={['armory.view']}
      onToast={() => undefined} />)
    await waitFor(() => expect(screen.getByText('ok')).toBeTruthy())
    const r = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } }
    })
    expect(r.violations.map((v) => v.id)).toEqual([])
  })
})
