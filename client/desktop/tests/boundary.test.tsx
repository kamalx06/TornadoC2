// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import ErrorBoundary from '../src/renderer/src/ui/ErrorBoundary'

function Boom(): JSX.Element {
  throw new Error('pane exploded')
}

afterEach(cleanup)

describe('error boundary', () => {
  it('shows the fault instead of a blank window', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    render(<ErrorBoundary><Boom /></ErrorBoundary>)
    expect(screen.getByRole('alert')).toBeTruthy()
    expect(screen.getByText('pane exploded')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Retry render' }))
    expect(screen.getByRole('alert')).toBeTruthy()
    spy.mockRestore()
  })
})
