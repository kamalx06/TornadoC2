import { useCallback, useEffect, useRef, useState } from 'react'

/** Copy to the Electron clipboard with a short confirmation. */
export default function CopyButton(props: {
  value: string
  label?: string
  className?: string
  children?: React.ReactNode
}): JSX.Element {
  const [done, setDone] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current)
  }, [])

  const copy = useCallback(async () => {
    try {
      await window.t2.clipboard(props.value, 30_000)
      setDone(true)
      if (timer.current) clearTimeout(timer.current)
      timer.current = setTimeout(() => setDone(false), 1400)
    } catch {
      /* clipboard failure is non-fatal */
    }
  }, [props.value])

  return (
    <button type="button" className={`copy-btn${props.className ? ` ${props.className}` : ''}`}
      aria-label={props.label ?? 'Copy'} onClick={() => void copy()}>
      {props.children ?? (done ? '✓' : '⧉')}
      <span className="sr-only" aria-live="polite">{done ? 'copied' : ''}</span>
    </button>
  )
}
