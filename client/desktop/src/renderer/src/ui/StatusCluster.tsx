import type { ReactNode } from 'react'

/** Status strip container. Children keep their own semantics. */
export default function StatusCluster(props: {
  children: ReactNode
  label?: string
}): JSX.Element {
  return (
    <div className="status-cluster" role="status" aria-live="polite"
      aria-label={props.label ?? 'Session status'}>
      {props.children}
    </div>
  )
}
