import { useState } from 'react'
import type { Cred } from '../../../shared/ipc'
import { invoke, usePoll } from '../hooks'

export default function Creds(props: {
  onToast: (t: string, k?: 'ok' | 'err' | 'info') => void
}): JSX.Element {
  const { data, error, reload } = usePoll<{ creds: Cred[] }>('creds.list', {}, 15_000)
  const [shown, setShown] = useState<Record<string, string>>({})
  const rows = data?.creds ?? []

  const reveal = async (id: string): Promise<void> => {
    try {
      const r = (await invoke('creds.reveal', { id })) as { cred?: Cred }
      const v = r.cred?.value ?? ''
      setShown((s) => ({ ...s, [id]: v }))
      await window.t2.clipboard(v, 30_000)
      props.onToast('value copied (clears in 30s)', 'ok')
    } catch (e) {
      props.onToast((e as Error).message, 'err')
    }
  }

  return (
    <div className="view">
      <div className="pane-head">
        <span className="pane-title">CREDENTIALS</span>
        <span className="pill">{rows.length}</span>
        <span className="grow" />
        <button className="btn" onClick={reload}>Refresh</button>
      </div>
      {error && <div className="banner err">{error}</div>}
      <div className="table-wrap">
        <div className="row head cols-c"><span>USER</span><span>KIND</span><span>BEACON</span><span>VALID</span><span>VALUE</span></div>
        {rows.length === 0 && <div className="empty">no credentials recorded</div>}
        {rows.map((c) => (
          <div key={c.id} className="row cols-c">
            <span className="mono ellipsis">
              {c.domain ? `${c.domain}\\` : ''}{c.user}
            </span>
            <span className="muted">{c.kind}</span>
            <span className="muted">#{c.source_beacon ?? '—'}</span>
            <span className={c.validation_status === 'valid' ? 'okc' : 'muted'}>
              {c.validation_status ?? 'unvalidated'}
            </span>
            <span className="mono ellipsis">
              {shown[c.id] ?? '••••••'}
              <button className="btn" onClick={() => void reveal(c.id)}>Reveal</button>
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
