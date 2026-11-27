import { useEffect, useRef, type ReactNode } from 'react'

export default function Dialog(props: {
  title: string
  onClose: () => void
  children: ReactNode
  footer?: ReactNode
}): JSX.Element {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null
    const focusables = (): HTMLElement[] =>
      Array.from(ref.current?.querySelectorAll<HTMLElement>(
        'input,select,textarea,button,a[href],[tabindex]:not([tabindex="-1"])'
      ) ?? []).filter((el) => !el.hasAttribute('disabled'))
    focusables()[0]?.focus()
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') {
        e.stopPropagation()
        props.onClose()
      }
      if (e.key !== 'Tab') return
      const list = focusables()
      if (list.length === 0) return
      const first = list[0]!
      const last = list[list.length - 1]!
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault()
        last.focus()
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault()
        first.focus()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('keydown', onKey)
      prev?.focus()
    }
  }, [props])
  return (
    <div className="modal" role="presentation" onMouseDown={(e) => e.target === e.currentTarget && props.onClose()}>
      <div className="modal-card" role="dialog" aria-modal="true" aria-label={props.title} ref={ref}>
        <h2>{props.title}</h2>
        <div className="modal-body">{props.children}</div>
        <div className="modal-foot">{props.footer}</div>
      </div>
    </div>
  )
}
