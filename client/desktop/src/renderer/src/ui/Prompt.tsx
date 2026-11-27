import { useState } from 'react'
import Dialog from './Dialog'

export default function Prompt(props: {
  title: string
  label: string
  initial?: string
  onDone: (value: string) => void
  onClose: () => void
}): JSX.Element {
  const [value, setValue] = useState(props.initial ?? '')
  return (
    <Dialog
      title={props.title}
      onClose={props.onClose}
      footer={
        <>
          <button className="btn" onClick={props.onClose}>Cancel</button>
          <button className="btn primary" disabled={!value.trim()}
            onClick={() => props.onDone(value.trim())}>
            Save
          </button>
        </>
      }
    >
      <input className="field" placeholder={props.label} aria-label={props.label} value={value}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && value.trim()) props.onDone(value.trim())
        }} />
    </Dialog>
  )
}

export function Confirm(props: {
  title: string
  body: string
  yes: string
  onYes: () => void
  onClose: () => void
}): JSX.Element {
  return (
    <Dialog
      title={props.title}
      onClose={props.onClose}
      footer={
        <>
          <button className="btn" onClick={props.onClose}>Cancel</button>
          <button className="btn primary" onClick={props.onYes}>{props.yes}</button>
        </>
      }
    >
      <p className="muted">{props.body}</p>
    </Dialog>
  )
}
