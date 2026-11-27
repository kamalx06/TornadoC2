import { useEffect, useId, useRef, useState } from 'react'

export type MenuEntry =
  | { kind?: 'item'; id: string; label: string; onSelect: () => void; disabled?: boolean; checked?: boolean }
  | { kind: 'sep'; id: string }
  | { kind: 'heading'; id: string; label: string }

export default function MenuButton(props: {
  label: string
  glyph: string
  items: MenuEntry[]
  disabled?: boolean
  align?: 'left' | 'right'
  placement?: 'down' | 'right'
  badge?: number
  on?: boolean
}): JSX.Element {
  const [open, setOpen] = useState(false)
  const menuId = useId()
  const wrap = useRef<HTMLDivElement>(null)
  const more = useRef<HTMLButtonElement>(null)
  const menu = useRef<HTMLUListElement>(null)

  useEffect(() => {
    if (!open) return
    const onDown = (e: PointerEvent): void => {
      if (!wrap.current?.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') {
        setOpen(false)
        more.current?.focus()
      }
    }
    document.addEventListener('pointerdown', onDown)
    document.addEventListener('keydown', onKey)
    menu.current?.querySelector<HTMLElement>('[role^="menuitem"]')?.focus()
    return () => {
      document.removeEventListener('pointerdown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const move = (e: React.KeyboardEvent<HTMLUListElement>): void => {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return
    e.preventDefault()
    const items = [...(menu.current?.querySelectorAll<HTMLElement>(
      '[role^="menuitem"]') ?? [])]
    const at = items.indexOf(document.activeElement as HTMLElement)
    const next = (at + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length
    items[next]?.focus()
  }

  return (
    <div className="menu-btn" ref={wrap}
      data-placement={props.placement ?? 'down'} data-on={props.on ? 'true' : undefined}>
      <button type="button" className="icon-btn" ref={more}
        aria-label={props.label} title={props.label} aria-haspopup="menu"
        aria-expanded={open} aria-controls={menuId} disabled={props.disabled}
        onClick={() => setOpen((o) => !o)}>
        <span aria-hidden="true">{props.glyph}</span>
        {(props.badge ?? 0) > 0 && (
          <span className="menu-badge">{props.badge! > 99 ? '99+' : props.badge}</span>
        )}
      </button>
      {open && (
        <ul className="split-menu" id={menuId} role="menu" ref={menu}
          onKeyDown={move} data-align={props.align ?? 'right'}>
          {props.items.map((it) => {
            if (it.kind === 'sep') return <li key={it.id} role="separator" />
            if (it.kind === 'heading') {
              return <li key={it.id} className="menu-head" role="presentation">{it.label}</li>
            }
            return (
              <li key={it.id} role="none">
                <div role={it.checked === undefined ? 'menuitem' : 'menuitemcheckbox'}
                  aria-checked={it.checked === undefined ? undefined : it.checked}
                  tabIndex={0}
                  className={it.checked ? 'on' : undefined}
                  aria-disabled={it.disabled || undefined}
                  onClick={() => {
                    if (it.disabled) return
                    setOpen(false)
                    it.onSelect()
                  }}
                  onKeyDown={(e) => {
                    if (it.disabled || (e.key !== 'Enter' && e.key !== ' ')) return
                    e.preventDefault()
                    setOpen(false)
                    it.onSelect()
                  }}>
                  {it.checked ? '● ' : ''}{it.label}
                </div>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
