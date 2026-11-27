export default function Skeleton(props: {
  lines?: number
  label?: string
  className?: string
}): JSX.Element {
  return (
    <div className={`skeleton${props.className ? ` ${props.className}` : ''}`}
      role="status" aria-busy="true" aria-label={props.label ?? 'Loading'}>
      {Array.from({ length: props.lines ?? 3 }, (_, i) => (
        <span key={i} className="skeleton-line"
          style={{ width: `${Math.max(38, 92 - i * 14)}%` }} />
      ))}
      <span className="sr-only">{props.label ?? 'Loading'}</span>
    </div>
  )
}
