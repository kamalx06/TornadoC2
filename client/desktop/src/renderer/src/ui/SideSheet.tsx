import { useEffect, useRef, type ReactNode } from 'react'

const FOCUSABLE =
  'input,select,textarea,button,a[href],[tabindex]:not([tabindex="-1"])'

/** Right-hand sheet with a focus trap and a dirty-close guard. */
export default function SideSheet(props: {
  title: string
  onClose: () => void
  children: ReactNode
  footer?: ReactNode
  dirty?: boolean
  width?: number
  label?: string
}): JSX.Element {
  const ref = useRef<HTMLDivElement>(null)
  const closeRef = useRef(props.onClose)
  const dirtyRef = useRef(props.dirty)
  closeRef.current = props.onClose
  dirtyRef.current = props.dirty

  const requestClose = (): void => {
    if (dirtyRef.current && !window.confirm('Discard unsaved changes?')) return
    closeRef.current()
  }

  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null
    const overflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const focusables = (): HTMLElement[] =>
      Array.from(ref.current?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? [])
        .filter((el) => !el.hasAttribute('disabled'))
    focusables()[0]?.focus()
    const firstField = ref.current?.querySelector<HTMLElement>(
      'input:not([disabled]),select:not([disabled]),textarea:not([disabled])')
    firstField?.focus()
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') {
        e.stopPropagation()
        requestClose()
        return
      }
      if (e.key !== 'Tab') return
      const list = focusables()
      if (!list.length) return
      const first = list[0]!
      const last = list[list.length - 1]!
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault(); last.focus()
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault(); first.focus()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = overflow
      prev?.focus()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div className="sheet-wrap" role="presentation"
      onMouseDown={(e) => e.target === e.currentTarget && requestClose()}>
      <div ref={ref} className="side-sheet" role="dialog" aria-modal="true"
        aria-label={props.label ?? props.title}
        style={{ width: `${Math.min(560, Math.max(320, props.width ?? 420))}px` }}>
        <header className="sheet-head">
          <h2>{props.title}</h2>
          <button type="button" className="icon-btn" aria-label="Close sheet"
            onClick={requestClose}>×</button>
        </header>
        <div className="sheet-body">{props.children}</div>
        <div className="sheet-foot">
          {props.dirty && <span className="sheet-dirty">unsaved</span>}
          {props.footer}
        </div>
      </div>
    </div>
  )
}
