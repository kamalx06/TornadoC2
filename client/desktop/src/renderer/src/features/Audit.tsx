import { useRef } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import type { AuditRow } from '../../../shared/ipc'
import { invoke, usePoll } from '../hooks'
import { useState } from 'react'

export default function Audit({ enabled = true, caps = [] }: { enabled?: boolean; caps?: string[] }): JSX.Element {
  const [msg, setMsg] = useState('')
  const { data, error, reload } = usePoll<AuditRow[]>('audit', { limit: 500 }, 10_000, enabled)
  const rows = data ?? []
  const ref = useRef<HTMLDivElement>(null)
  const virt = useVirtualizer({
    count: rows.length,
    getScrollElement: () => ref.current,
    estimateSize: () => 26,
    overscan: 10
  })
  return (
    <div className="view">
      <div className="pane-head">
        <span className="pane-title">AUDIT</span>
        <span className="pill">{rows.length}</span>
        <span className="grow" />
        {msg && <span className="small">{msg}</span>}
        {caps.includes('audit.read.all') && (
          <button className="btn" onClick={async () => {
            try {
              const r = (await invoke('audit.verify', { full: true }, 180_000)) as { ok: boolean; message: string }
              setMsg(r.ok ? 'chain ok' : `FAILED: ${r.message}`)
            } catch (e) { setMsg((e as Error).message) }
          }}>Verify</button>
        )}
        <button className="btn" onClick={reload}>Refresh</button>
      </div>
      {error && <div className="banner err">{error}</div>}
      <div className="table-wrap" ref={ref}>
        {rows.length === 0 && <div className="empty">no entries</div>}
        <div style={{ height: virt.getTotalSize(), position: 'relative' }}>
          {virt.getVirtualItems().map((v) => {
            const r = rows[v.index]
            if (!r) return null
            return (
              <div
                key={v.index}
                className={`row single mono small${r.outcome && r.outcome !== 'ok' ? ' errc' : ''}`}
                style={{ position: 'absolute', top: 0, left: 0, right: 0, transform: `translateY(${v.start}px)` }}
              >
                {r.ts?.slice(11, 19)} · {r.operator} · {r.action}
                {r.target ? ` → ${r.target}` : ''} · {r.outcome}
                {r.detail ? ` · ${r.detail}` : ''}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
