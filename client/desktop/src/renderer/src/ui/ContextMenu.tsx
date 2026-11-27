import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import type { MenuItem } from './MenuBar'

/** Fixed-position context menu with keyboard and edge clamping. */
export default function ContextMenu(props: {
  x: number
  y: number
  items: MenuItem[]
  onClose: () => void
  label?: string
}): JSX.Element {
  const root = useRef<HTMLUListElement>(null)
  const [pos, setPos] = useState({ x: props.x, y: props.y })

  useEffect(() => {
    const el = root.current
    if (!el) return
    const rect = el.getBoundingClientRect()
    setPos({
      x: Math.max(4, Math.min(props.x, innerWidth - rect.width - 4)),
      y: Math.max(4, Math.min(props.y, innerHeight - rect.height - 4))
    })
    el.querySelector<HTMLElement>('[role^="menuitem"]')?.focus()
  }, [props.x, props.y])

  useEffect(() => {
    const onDown = (e: PointerEvent): void => {
      if (!root.current?.contains(e.target as Node)) props.onClose()
    }
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') props.onClose()
    }
    document.addEventListener('pointerdown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('pointerdown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [props])

  const onListKey = (e: React.KeyboardEvent): void => {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return
    e.preventDefault()
    const items = [...(root.current?.querySelectorAll<HTMLElement>(
      '[role^="menuitem"]:not(:disabled)') ?? [])]
    const at = items.indexOf(document.activeElement as HTMLElement)
    const next = items[(at + (e.key === 'ArrowDown' ? 1 : -1)
      + items.length) % items.length]
    next?.focus()
  }

  return createPortal(
    <ul ref={root} className="context-menu" role="menu"
      aria-label={props.label ?? 'Context menu'}
      style={{ left: pos.x, top: pos.y }} onKeyDown={onListKey}>
      {props.items.map((item) => {
        if (item.kind === 'sep') {
          return <li key={item.id} role="separator" className="menu-sep" />
        }
        if (item.kind === 'heading') {
          return <li key={item.id} role="presentation"
            className="menu-head">{item.label}</li>
        }
        return (
          <li key={item.id} role="none">
            <button type="button"
              role={item.kind === 'check' ? 'menuitemcheckbox' : 'menuitem'}
              aria-checked={item.kind === 'check' ? Boolean(item.checked) : undefined}
              className="menu-item" disabled={item.disabled}
              onClick={() => {
                if (item.disabled) return
                item.onSelect?.()
                props.onClose()
              }}
              onKeyDown={(e) => {
                if (e.key !== 'Enter' && e.key !== ' ') return
                e.preventDefault()
                if (item.disabled) return
                item.onSelect?.()
                props.onClose()
              }}>
              <span className="menu-check" aria-hidden="true">
                {item.kind === 'check' && item.checked ? '✓' : ''}
              </span>
              <span className="menu-label">{item.label}</span>
            </button>
          </li>
        )
      })}
    </ul>,
    document.body
  )
}
