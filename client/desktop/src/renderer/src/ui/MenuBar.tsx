import {
  useCallback, useEffect, useId, useMemo, useRef, type KeyboardEvent
} from 'react'

export type MenuItem =
  | { kind: 'sep'; id: string }
  | { kind: 'heading'; id: string; label: string }
  | {
      kind: 'item' | 'check'
      id: string
      label: string
      hint?: string
      checked?: boolean
      disabled?: boolean
      onSelect?: () => void
    }

export type Menu = {
  id: string
  label: string
  items: MenuItem[]
  disabled?: boolean
}

/** Desktop menubar with roving focus and Escape-to-close. */
export default function MenuBar(props: {
  menus: Menu[]
  openId: string | null
  onOpenId: (id: string | null) => void
  label?: string
}): JSX.Element {
  const root = useRef<HTMLElement>(null)
  const buttons = useRef(new Map<string, HTMLButtonElement>())
  const panel = useRef<HTMLUListElement>(null)
  const prefix = useId()

  const enabled = useMemo(
    () => props.menus.filter((m) => !m.disabled), [props.menus])

  const close = useCallback((focus = false) => {
    const id = props.openId
    props.onOpenId(null)
    if (focus && id) buttons.current.get(id)?.focus()
  }, [props])

  useEffect(() => {
    if (!props.openId) return
    const onDown = (e: PointerEvent): void => {
      if (!root.current?.contains(e.target as Node)) close()
    }
    document.addEventListener('pointerdown', onDown)
    return () => document.removeEventListener('pointerdown', onDown)
  }, [props.openId, close])

  useEffect(() => {
    if (!props.openId) return
    panel.current
      ?.querySelector<HTMLButtonElement>('[role^="menuitem"]:not(:disabled)')
      ?.focus()
  }, [props.openId])

  const openAt = (id: string, index: number): void => {
    props.onOpenId(id)
    requestAnimationFrame(() => {
      panel.current
        ?.querySelectorAll<HTMLButtonElement>('[role^="menuitem"]:not(:disabled)')
        .item(index)
        ?.focus()
    })
  }

  const moveMenu = (delta: number, from: string): void => {
    const at = enabled.findIndex((m) => m.id === from)
    if (at < 0) return
    const next = enabled[(at + delta + enabled.length) % enabled.length]
    if (!next) return
    if (props.openId) props.onOpenId(next.id)
    buttons.current.get(next.id)?.focus()
  }

  const onBarKey = (e: KeyboardEvent<HTMLButtonElement>, menu: Menu): void => {
    if (e.key === 'ArrowRight') {
      e.preventDefault()
      moveMenu(1, menu.id)
    } else if (e.key === 'ArrowLeft') {
      e.preventDefault()
      moveMenu(-1, menu.id)
    } else if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      openAt(menu.id, 0)
    } else if (e.key === 'Escape' && props.openId) {
      e.preventDefault()
      close(true)
    }
  }

  const onPanelKey = (
    e: KeyboardEvent<HTMLUListElement>, menu: Menu
  ): void => {
    const items = [...(panel.current?.querySelectorAll<HTMLButtonElement>(
      '[role^="menuitem"]:not(:disabled)') ?? [])]
    const at = items.indexOf(document.activeElement as HTMLButtonElement)
    if (e.key === 'Escape') {
      e.preventDefault()
      close(true)
    } else if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
      e.preventDefault()
      moveMenu(e.key === 'ArrowRight' ? 1 : -1, menu.id)
    } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault()
      const next = items[(at + (e.key === 'ArrowDown' ? 1 : -1)
        + items.length) % items.length]
      next?.focus()
    } else if (e.key === 'Home' || e.key === 'End') {
      e.preventDefault()
      items[e.key === 'Home' ? 0 : items.length - 1]?.focus()
    } else if (e.key === 'Tab') {
      close()
    }
  }

  return (
    <nav ref={root} className="menubar" role="menubar"
      aria-label={props.label ?? 'Main menu'}>
      {props.menus.map((menu) => {
        if (menu.disabled) return null
        const open = props.openId === menu.id
        return (
          <div key={menu.id} className="menubar-slot" role="none">
            <button
              ref={(el) => {
                if (el) buttons.current.set(menu.id, el)
                else buttons.current.delete(menu.id)
              }}
              type="button" role="menuitem" className="menubar-btn"
              aria-haspopup="menu" aria-expanded={open}
              aria-controls={open ? `${prefix}-${menu.id}` : undefined}
              tabIndex={open || (!props.openId && menu.id === enabled[0]?.id)
                ? 0 : -1}
              onClick={() => props.onOpenId(open ? null : menu.id)}
              onKeyDown={(e) => onBarKey(e, menu)}>
              {menu.label}
            </button>
            {open && (
              <ul ref={panel} id={`${prefix}-${menu.id}`}
                className="menu-pop" role="menu" aria-label={menu.label}
                onKeyDown={(e) => onPanelKey(e, menu)}>
                {menu.items.map((item) => {
                  if (item.kind === 'sep') {
                    return <li key={item.id} role="separator"
                      className="menu-sep" />
                  }
                  if (item.kind === 'heading') {
                    return <li key={item.id} role="presentation"
                      className="menu-head">{item.label}</li>
                  }
                  return (
                    <li key={item.id} role="none">
                      <button type="button"
                        role={item.kind === 'check'
                          ? 'menuitemcheckbox' : 'menuitem'}
                        className="menu-item"
                        aria-checked={item.kind === 'check'
                          ? Boolean(item.checked) : undefined}
                        disabled={item.disabled}
                        onClick={() => {
                          if (item.disabled) return
                          item.onSelect?.()
                          close(true)
                        }}
                        onKeyDown={(e) => {
                          if (e.key !== 'Enter' && e.key !== ' ') return
                          e.preventDefault()
                          if (item.disabled) return
                          item.onSelect?.()
                          close(true)
                        }}>
                        <span className="menu-check" aria-hidden="true">
                          {item.kind === 'check' && item.checked ? '✓' : ''}
                        </span>
                        <span className="menu-label">{item.label}</span>
                        {item.hint && <span className="menu-hint">{item.hint}</span>}
                      </button>
                    </li>
                  )
                })}
              </ul>
            )}
          </div>
        )
      })}
    </nav>
  )
}
