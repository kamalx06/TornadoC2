import type { ReactNode } from 'react'

export function Toolbar(props: {
  label: string
  children?: ReactNode
  className?: string
}): JSX.Element {
  return (
    <div className={`tb${props.className ? ` ${props.className}` : ''}`}
      role="toolbar" aria-label={props.label}>
      {props.children}
    </div>
  )
}

export function ToolbarTitle({ children }: { children: ReactNode }): JSX.Element {
  return <span className="tb-title">{children}</span>
}

export function ToolbarGroup({ children, label }: {
  children: ReactNode
  label?: string
}): JSX.Element {
  return (
    <div className="tb-group" role={label ? 'group' : undefined} aria-label={label}>
      {children}
    </div>
  )
}

export function ToolbarSep(): JSX.Element {
  return <span className="tb-sep" role="separator" aria-orientation="vertical" />
}

export function ToolbarSpacer(): JSX.Element {
  return <span className="grow" />
}
