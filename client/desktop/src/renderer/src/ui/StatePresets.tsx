import type { ReactNode } from 'react'

export function EmptyPreset(props: {
  title: string
  hint?: string
  glyph?: string
  action?: ReactNode
}): JSX.Element {
  return (
    <div className="state-preset">
      <span className="state-glyph" aria-hidden="true">{props.glyph ?? '▢'}</span>
      <b>{props.title}</b>
      {props.hint && <span>{props.hint}</span>}
      {props.action && <div className="state-action">{props.action}</div>}
    </div>
  )
}

export function ErrorPreset(props: {
  title?: string
  detail: string
  onRetry?: () => void
  retryLabel?: string
}): JSX.Element {
  return (
    <div className="state-preset err" role="alert">
      <span className="state-glyph" aria-hidden="true">■</span>
      <b>{props.title ?? 'Could not load'}</b>
      <span>{props.detail}</span>
      {props.onRetry && (
        <div className="state-action">
          <button className="btn" onClick={props.onRetry}>
            {props.retryLabel ?? 'Retry'}
          </button>
        </div>
      )}
    </div>
  )
}

export function NoResultsPreset(props: { filter?: string }): JSX.Element {
  return (
    <div className="state-preset">
      <span className="state-glyph" aria-hidden="true">⌕</span>
      <b>No matches</b>
      <span>{props.filter ? `nothing matches “${props.filter}”` : 'nothing to show'}</span>
    </div>
  )
}
