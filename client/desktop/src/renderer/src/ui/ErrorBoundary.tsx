import { Component, type ErrorInfo, type ReactNode } from 'react'

export default class ErrorBoundary extends Component<
  { children: ReactNode },
  { error: Error | null }
> {
  override state = { error: null as Error | null }

  static getDerivedStateFromError(error: Error): { error: Error } {
    return { error }
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('[renderer]', error, info.componentStack)
  }

  override render(): ReactNode {
    if (!this.state.error) return this.props.children
    return (
      <div className="crash" role="alert">
        <div className="crash-card">
          <span className="gate-kicker">Renderer fault</span>
          <h1>The console stopped.</h1>
          <pre>{this.state.error.message}</pre>
          <div className="quick">
            <button className="btn primary" onClick={() => location.reload()}>
              Reload window
            </button>
            <button className="btn" onClick={() => this.setState({ error: null })}>
              Retry render
            </button>
          </div>
          <p className="muted small">
            Layouts are kept in local storage; a reload restores the pane set.
          </p>
        </div>
      </div>
    )
  }
}
