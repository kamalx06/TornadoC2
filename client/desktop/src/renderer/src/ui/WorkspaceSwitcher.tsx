import { useEffect, useId, useRef, useState } from 'react'
import {
  WORKSPACES, WORKSPACE_IDS, type WorkspaceId
} from '../workspace/workspaces'

/** Controlled listbox. `Alt+W` focuses the trigger. */
export default function WorkspaceSwitcher(props: {
  value: WorkspaceId
  custom?: boolean
  onChange: (id: WorkspaceId) => void
  triggerRef?: React.Ref<HTMLButtonElement>
}): JSX.Element {
  const [open, setOpen] = useState(false)
  const [at, setAt] = useState(0)
  const root = useRef<HTMLDivElement>(null)
  const items = useRef<HTMLUListElement>(null)
  const id = useId()

  useEffect(() => {
    if (!open) return
    const onDown = (e: PointerEvent): void => {
      if (!root.current?.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('pointerdown', onDown)
    return () => document.removeEventListener('pointerdown', onDown)
  }, [open])

  useEffect(() => {
    if (!open) return
    setAt(Math.max(0, WORKSPACE_IDS.indexOf(props.value)))
  }, [open, props.value])

  useEffect(() => {
    if (!open) return
    items.current?.querySelectorAll<HTMLElement>('[role="option"]')
      .item(at)?.focus()
  }, [open, at])

  const close = (): void => {
    setOpen(false)
    requestAnimationFrame(() => {
      const el = document.querySelector<HTMLButtonElement>('.ws-trigger')
      el?.focus()
    })
  }

  const choose = (id: WorkspaceId): void => {
    props.onChange(id)
    close()
  }

  const onListKey = (e: React.KeyboardEvent): void => {
    if (e.key === 'Escape') {
      e.preventDefault()
      close()
    } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault()
      setAt((n) => Math.max(0, Math.min(WORKSPACE_IDS.length - 1,
        n + (e.key === 'ArrowDown' ? 1 : -1))))
    } else if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      const id = WORKSPACE_IDS[at]
      if (id) choose(id)
    } else if (e.key === 'Home') {
      e.preventDefault(); setAt(0)
    } else if (e.key === 'End') {
      e.preventDefault(); setAt(WORKSPACE_IDS.length - 1)
    }
  }

  return (
    <div className="ws" ref={root}>
      <button ref={props.triggerRef} type="button" className="ws-trigger"
        aria-haspopup="listbox" aria-expanded={open}
        aria-controls={open ? `${id}-list` : undefined}
        aria-label={`Workspace: ${WORKSPACES[props.value].label}`}
        title={`${WORKSPACES[props.value].hint} (Alt+W)`}
        onClick={() => setOpen((o) => !o)}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
            e.preventDefault(); setOpen(true)
          } else if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
            e.preventDefault()
            const i = WORKSPACE_IDS.indexOf(props.value)
            const next = WORKSPACE_IDS[(i + (e.key === 'ArrowRight' ? 1 : -1)
              + WORKSPACE_IDS.length) % WORKSPACE_IDS.length]
            if (next) props.onChange(next)
          } else if (e.key === 'Escape') {
            setOpen(false)
          }
        }}>
        {WORKSPACES[props.value].label}
        {props.custom && <span className="ws-custom">custom</span>}
        <span aria-hidden="true">▾</span>
      </button>
      {open && (
        <ul id={`${id}-list`} ref={items} className="ws-list" role="listbox"
          aria-label="Workspace" aria-activedescendant={`${id}-opt-${at}`}
          onKeyDown={onListKey}>
          {WORKSPACE_IDS.map((wid, i) => (
            <li key={wid} id={`${id}-opt-${i}`} role="option"
              tabIndex={i === at ? 0 : -1}
              aria-selected={wid === props.value}
              onClick={() => choose(wid)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault(); choose(wid)
                }
              }}>
              <b>{WORKSPACES[wid].label}</b>
              <span>{WORKSPACES[wid].hint}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
