import type { ReactNode } from 'react'

export default function EmptyState(props: {
  glyph?: string
  title: string
  hint?: string
  actions?: ReactNode
}): JSX.Element {
  return (
    <div className="empty-state">
      {props.glyph && <span className="glyph" aria-hidden="true">{props.glyph}</span>}
      <b>{props.title}</b>
      {props.hint && <span className="hint">{props.hint}</span>}
      {props.actions && <div className="actions">{props.actions}</div>}
    </div>
  )
}
