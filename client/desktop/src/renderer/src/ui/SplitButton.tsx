import { useEffect, useId, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from 'react'

export type SplitItem = {
  id: string
  label: string
  onSelect: () => void
  danger?: boolean
  disabled?: boolean
  separatorBefore?: boolean
}

export default function SplitButton(props: {
  label: string
  onMain: () => void
  items: SplitItem[]
  disabled?: boolean
  moreLabel?: string
}): JSX.Element {
  const [open, setOpen] = useState(false)
  const menuId = useId()
  const wrap = useRef<HTMLDivElement>(null)
  const menu = useRef<HTMLUListElement>(null)
  const more = useRef<HTMLButtonElement>(null)

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
    menu.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus()
    return () => {
      document.removeEventListener('pointerdown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const move = (e: ReactKeyboardEvent<HTMLUListElement>): void => {
    const step = e.key === 'ArrowDown' ? 1 : e.key === 'ArrowUp' ? -1 : 0
    if (!step) return
    e.preventDefault()
    const items = [...(menu.current?.querySelectorAll<HTMLElement>(
      '[role="menuitem"]') ?? [])]
    const at = items.indexOf(document.activeElement as HTMLElement)
    const next = (at + step + items.length) % items.length
    items[next]?.focus()
  }

  return (
    <div className="split-btn" ref={wrap}>
      <button type="button" className="btn main" onClick={props.onMain}
        disabled={props.disabled}>
        {props.label}
      </button>
      <button type="button" className="btn more" ref={more} aria-haspopup="menu"
        aria-expanded={open} aria-controls={menuId} disabled={props.disabled}
        aria-label={props.moreLabel ?? 'More actions'}
        onClick={() => setOpen((o) => !o)}>
        ▾
      </button>
      {open && (
        <ul className="split-menu" id={menuId} role="menu" ref={menu}
          onKeyDown={move}>
          {props.items.map((it) => (
            <li key={it.id} role="none">
              {it.separatorBefore && <div role="separator" />}
              <div role="menuitem" tabIndex={0}
                aria-disabled={it.disabled || undefined}
                className={it.danger ? 'errc' : undefined}
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
                {it.label}
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
