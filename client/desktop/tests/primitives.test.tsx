// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import axe from 'axe-core'
import SideSheet from '../src/renderer/src/ui/SideSheet'
import ContextMenu from '../src/renderer/src/ui/ContextMenu'
import ProgressBar from '../src/renderer/src/ui/ProgressBar'
import Skeleton from '../src/renderer/src/ui/Skeleton'
import CopyButton from '../src/renderer/src/ui/CopyButton'
import Markdown from '../src/renderer/src/ui/Markdown'
import { ErrorPreset, NoResultsPreset } from '../src/renderer/src/ui/StatePresets'

beforeEach(() => {
  window.confirm = vi.fn(() => true)
  window.t2 = {
    clipboard: vi.fn(async () => true)
  } as unknown as typeof window.t2
})

afterEach(cleanup)

describe('side sheet', () => {
  it('traps focus, closes on Escape and restores focus', () => {
    const trigger = document.createElement('button')
    document.body.append(trigger)
    trigger.focus()
    const close = vi.fn()
    render(<SideSheet title="Edit" onClose={close} footer={
      <button>Save</button>
    }><input aria-label="Name" /></SideSheet>)
    expect(document.activeElement?.getAttribute('aria-label')).toBe('Name')
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(close).toHaveBeenCalled()
    cleanup()
    expect(document.activeElement).toBe(trigger)
    trigger.remove()
  })

  it('confirms before discarding dirty work', () => {
    const close = vi.fn()
    render(<SideSheet title="Edit" dirty onClose={close}>
      <input aria-label="Name" />
    </SideSheet>)
    vi.mocked(window.confirm).mockReturnValueOnce(false)
    fireEvent.click(screen.getByLabelText('Close sheet'))
    expect(close).not.toHaveBeenCalled()
    fireEvent.click(screen.getByLabelText('Close sheet'))
    expect(close).toHaveBeenCalled()
  })
})

describe('context menu', () => {
  it('renders in a portal and runs an item', () => {
    const pick = vi.fn()
    const close = vi.fn()
    render(<ContextMenu x={5} y={5} onClose={close} items={[
      { kind: 'item', id: 'a', label: 'Copy', onSelect: pick }
    ]} />)
    fireEvent.click(screen.getByRole('menuitem', { name: 'Copy' }))
    expect(pick).toHaveBeenCalled()
    expect(close).toHaveBeenCalled()
  })

  it('closes on Escape and outside click', () => {
    const close = vi.fn()
    render(<ContextMenu x={5} y={5} onClose={close} items={[
      { kind: 'item', id: 'a', label: 'Copy' }
    ]} />)
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(close).toHaveBeenCalledTimes(1)
    fireEvent.pointerDown(document.body)
    expect(close).toHaveBeenCalledTimes(2)
  })
})

describe('progress and skeleton', () => {
  it('exposes determinate values', () => {
    render(<ProgressBar label="Upload" value={25} max={100} />)
    const bar = screen.getByRole('progressbar', { name: 'Upload' })
    expect(bar.getAttribute('aria-valuenow')).toBe('25')
    expect(bar.textContent).toContain('25%')
  })

  it('omits value when indeterminate', () => {
    render(<ProgressBar label="Build" indeterminate />)
    expect(screen.getByRole('progressbar', { name: 'Build' })
      .hasAttribute('aria-valuenow')).toBe(false)
  })

  it('announces loading', () => {
    render(<Skeleton lines={2} label="Loading jobs" />)
    expect(screen.getByRole('status', { name: 'Loading jobs' })).toBeTruthy()
  })
})

describe('copy button', () => {
  it('writes to the clipboard with a clear timer', async () => {
    render(<CopyButton value="abc" label="Copy id" />)
    fireEvent.click(screen.getByLabelText('Copy id'))
    await vi.waitFor(() => expect(window.t2.clipboard).toHaveBeenCalledWith('abc', 30_000))
  })
})

describe('markdown', () => {
  it('renders safe markdown and strips scripts', () => {
    const { container } = render(<Markdown source={
      '**bold**\n\n<script>alert(1)</script>\n\n<img src=x onerror=alert(1)>'
    } />)
    expect(container.querySelector('strong')?.textContent).toBe('bold')
    expect(container.querySelector('script')).toBeNull()
    expect(container.querySelector('img')?.getAttribute('onerror')).toBeNull()
  })

  it('adds target and rel to links', () => {
    const { container } = render(<Markdown source="[x](https://example.com)" />)
    const link = container.querySelector('a')!
    expect(link.getAttribute('target')).toBe('_blank')
    expect(link.getAttribute('rel')).toContain('noreferrer')
  })

  it('supports fenced code and tables', () => {
    const { container } = render(<Markdown source={'```\nls -la\n```\n\n| a | b |\n| - | - |\n| 1 | 2 |'} />)
    expect(container.querySelector('pre code')?.textContent).toContain('ls -la')
    expect(container.querySelectorAll('td')).toHaveLength(2)
  })
})

describe('state presets', () => {
  it('renders an actionable error', () => {
    const retry = vi.fn()
    render(<ErrorPreset detail="down" onRetry={retry} />)
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(retry).toHaveBeenCalled()
  })

  it('names the filter in no-results', () => {
    render(<NoResultsPreset filter="ssh" />)
    expect(screen.getByText(/ssh/)).toBeTruthy()
  })

  it('primitives have no axe violations', async () => {
    const { container } = render(<>
      <ProgressBar label="Load" value={4} max={10} />
      <Markdown source={'**a** [b](https://x)'} />
      <CopyButton value="x" label="Copy x" />
      <ErrorPreset detail="down" />
    </>)
    const res = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } }
    })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })
})
