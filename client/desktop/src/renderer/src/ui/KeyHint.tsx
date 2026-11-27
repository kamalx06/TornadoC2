export default function KeyHint(props: { keys: string; label?: string }): JSX.Element {
  return (
    <kbd className="key-hint" aria-label={props.label}>
      {props.keys}
    </kbd>
  )
}
