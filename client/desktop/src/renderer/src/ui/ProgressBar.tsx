export default function ProgressBar(props: {
  value?: number
  max?: number
  label: string
  hint?: string
  indeterminate?: boolean
  tone?: 'ok' | 'err' | 'warn'
}): JSX.Element {
  const max = Math.max(1, props.max ?? 100)
  const value = Math.max(0, Math.min(max, props.value ?? 0))
  const pct = Math.round((value / max) * 100)
  return (
    <div className={`progress${props.indeterminate ? ' indeterminate' : ''}${
      props.tone ? ` ${props.tone}` : ''}`}
    role="progressbar" aria-label={props.label}
    aria-valuemin={props.indeterminate ? undefined : 0}
    aria-valuemax={props.indeterminate ? undefined : max}
    aria-valuenow={props.indeterminate ? undefined : value}
    aria-valuetext={props.indeterminate ? 'in progress'
      : `${pct}%${props.hint ? `, ${props.hint}` : ''}`}>
      <div className="progress-track">
        <div className="progress-fill" style={
          props.indeterminate ? undefined : { width: `${pct}%` }} />
      </div>
      <div className="progress-meta">
        <span>{props.label}</span>
        <span className="mono">{props.indeterminate ? '…' : `${pct}%`}</span>
      </div>
      {props.hint && <div className="progress-hint">{props.hint}</div>}
    </div>
  )
}
