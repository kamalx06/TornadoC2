import type { ReactNode } from 'react'

export type Tone = 'ok' | 'warn' | 'err' | 'info' | 'idle'

export default function StatusPill(props: {
  tone?: Tone
  children: ReactNode
  title?: string
}): JSX.Element {
  return (
    <span className="status-pill" data-tone={props.tone ?? 'idle'} title={props.title}>
      {props.children}
    </span>
  )
}
