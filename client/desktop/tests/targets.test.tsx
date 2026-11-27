// @vitest-environment jsdom
import { useState } from 'react'
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import axe from 'axe-core'
import type { Beacon } from '../src/shared/ipc'
import Targets from '../src/renderer/src/features/Targets'

const rows = (n: number): Beacon[] => Array.from({ length: n }, (_, i) => ({
  id: i + 1,
  display_name: `user${i}@host${i}`,
  alias: i === 1 ? 'dc' : undefined,
  os: 'linux',
  arch: 'amd64',
  alive: true,
  last_seen_age: i,
  privilege: i % 7 === 0 ? 'system' : 'user',
  elevated: i % 7 === 0
}))

function Harness(props: { data: Beacon[]; onAlias?: (id: number, a: string) => Promise<void> }) {
  const [sel, setSel] = useState<Set<number>>(new Set())
  const [primary, setPrimary] = useState<number | null>(null)
  return (
    <Targets data-testid="t" rows={props.data} total={props.data.length}
      query="" onQuery={() => undefined} onRefresh={() => undefined}
      sel={sel} primary={primary} density="compact"
      onSelect={(ids, focus) => { setSel(new Set(ids)); setPrimary(focus) }}
      onAlias={props.onAlias ?? (async () => undefined)}
      onAttach={() => undefined} onTask={() => undefined}
      onTag={() => undefined} onKill={() => undefined} />
  )
}

beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, 'clientHeight', {
    configurable: true, get: () => 600
  })
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({
    width: 900, height: 600, top: 0, left: 0, bottom: 600, right: 900,
    x: 0, y: 0, toJSON: () => ({})
  } as DOMRect)
})

afterEach(cleanup)

describe('target inventory', () => {
  it('renders severity and the alias', () => {
    render(<Harness data={rows(10)} />)
    expect(screen.getByText('«dc»')).toBeTruthy()
    expect(screen.getAllByText('HIGH').length).toBeGreaterThan(0)
    expect(screen.getAllByText('LOW').length).toBeGreaterThan(0)
  })

  it('supports keyboard selection and ranges', () => {
    render(<Harness data={rows(10)} />)
    const first = document.querySelector('[data-row-id="1"]')!
    fireEvent.click(first)
    fireEvent.keyDown(first, { key: 'ArrowDown' })
    expect(document.querySelector('[data-row-id="2"]')
      ?.getAttribute('aria-selected')).toBe('true')
    fireEvent.keyDown(document.querySelector('[data-row-id="2"]')!,
      { key: 'ArrowDown', shiftKey: true })
    expect(document.querySelector('[data-row-id="3"]')
      ?.getAttribute('aria-selected')).toBe('true')
    fireEvent.keyDown(document.querySelector('[data-row-id="3"]')!,
      { key: ' ' })
    expect(document.querySelector('[data-row-id="3"]')
      ?.getAttribute('aria-selected')).toBe('false')
    fireEvent.keyDown(document.querySelector('[data-row-id="2"]')!,
      { key: 'a', ctrlKey: true })
    expect(screen.getByText('10 sel')).toBeTruthy()
  })

  it('selects all and inverts', () => {
    render(<Harness data={rows(4)} />)
    fireEvent.click(screen.getByRole('button', { name: 'All 4' }))
    expect(screen.getByText('4 sel')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Invert' }))
    expect(screen.queryByText('4 sel')).toBeNull()
  })

  it('edits the alias with F2 and commits on Enter', async () => {
    const onAlias = vi.fn(async () => undefined)
    render(<Harness data={rows(3)} onAlias={onAlias} />)
    fireEvent.click(document.querySelector('[data-row-id="2"]')!)
    fireEvent.keyDown(document.querySelector('[data-row-id="2"]')!, { key: 'F2' })
    const input = screen.getByLabelText('Alias for 2') as HTMLInputElement
    fireEvent.change(input, { target: { value: 'edge-dc' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    await waitFor(() => expect(onAlias).toHaveBeenCalledWith(2, 'edge-dc'))
  })

  it('sorts by priority from the header', () => {
    render(<Harness data={rows(8)} />)
    fireEvent.click(screen.getByRole('button', { name: 'PRI' }))
    expect(document.querySelector('[role="columnheader"][aria-sort="descending"]'))
      .toBeTruthy()
    const ids = [...document.querySelectorAll('[data-row-id]')]
      .map((r) => Number(r.getAttribute('data-row-id')))
    expect(ids[0]).toBe(1)
  })

  it('has no axe violations', async () => {
    const { container } = render(<Harness data={rows(30)} />)
    const res = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } }
    })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })

  it('keeps 10k rows virtualised within budget', () => {
    const started = performance.now()
    render(<Harness data={rows(10_000)} />)
    const elapsed = performance.now() - started
    expect(document.querySelectorAll('[data-row-id]').length).toBeLessThan(80)
    expect(document.querySelectorAll('[data-row-id]').length).toBeGreaterThan(5)
    expect(elapsed).toBeLessThan(500)
  })
})
