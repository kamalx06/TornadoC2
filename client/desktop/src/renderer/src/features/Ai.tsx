import { useState } from 'react'
import { invoke } from '../hooks'

type Turn = { role: 'you' | 'ai'; text: string }

export default function Ai(props: {
  onToast: (t: string, k?: 'ok' | 'err' | 'info') => void
}): JSX.Element {
  const [turns, setTurns] = useState<Turn[]>([])
  const [q, setQ] = useState('')
  const [busy, setBusy] = useState(false)

  const ask = async (): Promise<void> => {
    const question = q.trim()
    if (!question) return
    setQ('')
    setTurns((t) => [...t, { role: 'you', text: question }])
    setBusy(true)
    try {
      const r = (await invoke('ai.ask', { question }, 180_000)) as { text: string }
      setTurns((t) => [...t, { role: 'ai', text: r.text || '(empty)' }])
    } catch (e) {
      props.onToast((e as Error).message, 'err')
      setTurns((t) => [...t, { role: 'ai', text: `! ${(e as Error).message}` }])
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="view">
      <div className="pane-head">
        <span className="pane-title">AI CONSOLE</span>
        <span className="grow" />
        <span className="muted small">one-shot turns, provider config on the workstation</span>
      </div>
      <div className="chatlog" aria-live="polite">
        {turns.length === 0 && (
          <div className="empty">
            <b>ask about the engagement</b>
            the agent can call read tools and gated actions
          </div>
        )}
        {turns.map((t, i) => (
          <div key={i} className={`turn ${t.role}`}>
            <b>{t.role === 'you' ? 'you' : 'ai'}</b>
            <pre>{t.text}</pre>
          </div>
        ))}
      </div>
      <form className="compose" onSubmit={(e) => { e.preventDefault(); void ask() }}>
        <input className="field grow" placeholder="question…" value={q}
          onChange={(e) => setQ(e.target.value)} aria-label="AI question" />
        <button className="btn primary" disabled={busy || !q.trim()}>
          {busy ? 'thinking…' : 'Ask'}
        </button>
      </form>
    </div>
  )
}
