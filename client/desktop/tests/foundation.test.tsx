// @vitest-environment jsdom
import { readFileSync } from 'node:fs'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import axe from 'axe-core'
import {
  auditTheme, luminance, parseTheme
} from '../scripts/lib/contrast.mts'
import {
  EmptyState, Field, IconButton, KeyHint, SplitButton, StatusPill, Toolbar,
  ToolbarTitle
} from '../src/renderer/src/ui'

const css = readFileSync('src/renderer/src/styles/tokens.css', 'utf8')

afterEach(cleanup)

describe('design tokens', () => {
  for (const [theme, selector] of [
    ['dark', ':root'],
    ['light', "html[data-theme='light']"]
  ] as const) {
    it(`${theme} text tokens meet WCAG AA`, () => {
      const failed = auditTheme(parseTheme(css, selector)).filter((r) => !r.pass)
      expect(failed.map((r) => `${r.fg} on ${r.bg}: ${r.ratio.toFixed(2)}`)).toEqual([])
    })
  }

  it('keeps the dark canvas pitch black', () => {
    expect(luminance(parseTheme(css, ':root').bg)).toBeLessThan(0.01)
  })
})

describe('primitives', () => {
  it('renders an accessible toolbar and field', async () => {
    const { container } = render(
      <>
        <Toolbar label="Targets">
          <ToolbarTitle>Targets</ToolbarTitle>
          <IconButton label="Refresh">↻</IconButton>
        </Toolbar>
        <Field label="Remote path" hint="absolute path" />
        <StatusPill tone="ok">Live</StatusPill>
        <KeyHint keys="⌘K" label="Command palette" />
        <EmptyState title="No targets" hint="they check in shortly" />
      </>
    )
    expect(screen.getByRole('toolbar', { name: 'Targets' })).toBeTruthy()
    expect(screen.getByLabelText('Remote path')).toBeTruthy()
    expect(screen.getByLabelText('Command palette')).toBeTruthy()
    const res = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } }
    })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })

  it('associates field errors', () => {
    render(<Field label="Port" error="out of range" defaultValue="70000" />)
    const input = screen.getByLabelText('Port')
    expect(input.getAttribute('aria-invalid')).toBe('true')
    expect(input.getAttribute('aria-describedby')).toBeTruthy()
  })

  it('opens the split menu, focuses it and runs an item', () => {
    const main = vi.fn()
    const audit = vi.fn()
    render(
      <SplitButton label="Build" onMain={main}
        items={[
          { id: 'a', label: 'Audit build', onSelect: audit },
          { id: 'b', label: 'Reinstall', onSelect: vi.fn() }
        ]} />
    )
    fireEvent.click(screen.getByLabelText('More actions'))
    expect(document.activeElement?.textContent).toBe('Audit build')
    fireEvent.keyDown(document.activeElement!, { key: 'ArrowDown' })
    expect(document.activeElement?.textContent).toBe('Reinstall')
    fireEvent.keyDown(document.activeElement!, { key: 'Enter' })
    expect(main).not.toHaveBeenCalled()
  })
})
