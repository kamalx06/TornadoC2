// @vitest-environment jsdom
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import axe from 'axe-core'
import App from '../src/renderer/src/App'

beforeAll(() => {
  window.t2 = {
    invoke: vi.fn(async () => ({ ok: true, result: {} })),
    status: vi.fn(async () => ({ connected: false, config: '' })),
    pickConfig: vi.fn(async () => ''),
    clipboard: vi.fn(async () => true),
    saveFile: vi.fn(async () => ''),
    detach: vi.fn(),
    onLog: () => () => undefined,
    onUpdate: () => () => undefined,
    onConn: () => () => undefined
  } as unknown as typeof window.t2
})

afterEach(cleanup)

describe('accessibility', () => {
  it('connect screen has no axe violations', async () => {
    const { container } = render(<App />)
    const res = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } }
    })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })

  it('connect screen is labelled', () => {
    render(<App />)
    expect(screen.getByLabelText('Operator config path')).toBeTruthy()
    expect(screen.getByLabelText('Operator password')).toBeTruthy()
    expect(screen.getByRole('button', { name: /connect/i })).toBeTruthy()
  })
})
