// @vitest-environment jsdom
import { useState } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import MenuBar, { type Menu } from '../src/renderer/src/ui/MenuBar'

function Harness(props: { onPick?: () => void }): JSX.Element {
  const [open, setOpen] = useState<string | null>(null)
  const menus: Menu[] = [
    { id: 'file', label: 'File', items: [
      { kind: 'item', id: 'run', label: 'Run', onSelect: props.onPick }
    ] },
    { id: 'view', label: 'View', items: [
      { kind: 'check', id: 'dense', label: 'Dense', checked: true },
      { kind: 'sep', id: 's' },
      { kind: 'item', id: 'panels', label: 'Panels' }
    ] }
  ]
  return <MenuBar menus={menus} openId={open} onOpenId={setOpen} />
}

afterEach(cleanup)

describe('menubar', () => {
  it('opens with the keyboard and runs an item', () => {
    const pick = vi.fn()
    render(<Harness onPick={pick} />)
    const file = screen.getByRole('menuitem', { name: 'File' })
    file.focus()
    fireEvent.keyDown(file, { key: 'ArrowDown' })
    const item = screen.getByRole('menuitem', { name: 'Run' })
    fireEvent.keyDown(item, { key: 'Enter' })
    expect(pick).toHaveBeenCalled()
    expect(screen.queryByRole('menu')).toBeNull()
    expect(document.activeElement).toBe(file)
  })

  it('moves between menus and exposes check state', () => {
    render(<Harness />)
    const file = screen.getByRole('menuitem', { name: 'File' })
    file.focus()
    fireEvent.keyDown(file, { key: 'ArrowRight' })
    expect(document.activeElement?.textContent).toBe('View')
    fireEvent.click(document.activeElement!)
    expect(screen.getByRole('menuitemcheckbox', { name: 'Dense' })
      .getAttribute('aria-checked')).toBe('true')
  })

  it('closes on Escape and restores focus', () => {
    render(<Harness />)
    const view = screen.getByRole('menuitem', { name: 'View' })
    fireEvent.click(view)
    fireEvent.keyDown(screen.getByRole('menuitemcheckbox', { name: 'Dense' }),
      { key: 'Escape' })
    expect(screen.queryByRole('menu')).toBeNull()
    expect(document.activeElement).toBe(view)
  })
})
