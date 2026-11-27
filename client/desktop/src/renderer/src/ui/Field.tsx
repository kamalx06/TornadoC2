import { forwardRef, useId, type InputHTMLAttributes } from 'react'

type FieldProps = InputHTMLAttributes<HTMLInputElement> & {
  label: string
  hint?: string
  error?: string
  fieldClassName?: string
}

const Field = forwardRef<HTMLInputElement, FieldProps>(function Field(
  { label, hint, error, id, fieldClassName, className, ...rest }, ref
) {
  const auto = useId()
  const inputId = id ?? auto
  const note = error ?? hint
  return (
    <div className={`ui-field${fieldClassName ? ` ${fieldClassName}` : ''}`}>
      <label htmlFor={inputId}>{label}</label>
      <input
        {...rest}
        ref={ref}
        id={inputId}
        className={`ui-input${className ? ` ${className}` : ''}`}
        aria-invalid={error ? true : undefined}
        aria-describedby={note ? `${inputId}-note` : undefined}
      />
      {note && (
        <span id={`${inputId}-note`} className={`ui-hint${error ? ' err' : ''}`}>
          {note}
        </span>
      )}
    </div>
  )
})

export default Field
