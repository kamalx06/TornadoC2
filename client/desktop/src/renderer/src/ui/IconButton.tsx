import type { ButtonHTMLAttributes, ReactNode } from 'react'

type Props = ButtonHTMLAttributes<HTMLButtonElement> & {
  label: string
  on?: boolean
  children: ReactNode
}

export default function IconButton({ label, on, children, ...rest }: Props): JSX.Element {
  return (
    <button
      {...rest}
      type={rest.type ?? 'button'}
      className={`icon-btn${rest.className ? ` ${rest.className}` : ''}`}
      aria-label={label}
      title={rest.title ?? label}
      data-on={on ? 'true' : undefined}
    >
      {children}
    </button>
  )
}
