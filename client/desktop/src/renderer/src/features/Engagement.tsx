import { useMemo, useRef, useState } from 'react'
import Dialog from '../ui/Dialog'
import { invoke } from '../hooks'
import { useVirtualizer } from '@tanstack/react-virtual'
import type { Model } from '../../../shared/ipc'
import { usePoll } from '../hooks'

type Tab = 'hosts' | 'users' | 'shares' | 'services' | 'evidence' | 'findings' | 'timeline'

const TABS: Array<[Tab, string]> = [
  ['hosts', 'Hosts'], ['users', 'Users'], ['shares', 'Shares'],
  ['services', 'Services'], ['evidence', 'Evidence'],
  ['findings', 'Findings'], ['timeline', 'Timeline']
]

export default function Engagement(props: {
  enabled?: boolean
  caps?: string[]
  onExport: (k: 'ioc' | 'stix' | 'report') => void
  toast: (t: string, k?: 'ok' | 'err' | 'info') => void
}): JSX.Element {
  const { data, error, reload } = usePoll<Model>('model', { limit: 500 }, 10_000, props.enabled ?? true)
  const [tab, setTab] = useState<Tab>('hosts')
  const [add, setAdd] = useState<'evidence' | 'finding' | null>(null)
  const [form, setForm] = useState<Record<string, string>>({})
  const scrollRef = useRef<HTMLDivElement>(null)

  const rows = useMemo(() => {
    const m = data ?? {}
    if (tab === 'hosts') return m.hosts ?? []
    if (tab === 'timeline') return m.timeline ?? []
    return (m[tab] as unknown[] | undefined) ?? []
  }, [data, tab])

  const virt = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 28,
    overscan: 10
  })

  const cell = (row: Record<string, unknown>): string => {
    const pick = (...keys: string[]): string => {
      for (const k of keys) {
        const v = row[k]
        if (v !== undefined && v !== null && v !== '') return String(v)
      }
      return ''
    }
    if (tab === 'hosts') return `${pick('hostname', 'machine_id')} · ${pick('user')} · ${pick('privilege')}`
    if (tab === 'timeline') return `${pick('kind')} · ${pick('text')} · ${pick('by')}`
    if (tab === 'findings') return `[${pick('severity')}] ${pick('title')} · ${pick('host')}`
    if (tab === 'evidence') return `${pick('sha256')} · ${pick('name')} · ${pick('host')}`
    return `${pick('user', 'name', 'sha256')} · ${pick('host')} · ${pick('kind', 'access', 'state')}`
  }

  return (
    <div className="view">
      <div className="pane-head">
        <span className="pane-title">ENGAGEMENT</span>
        <span className="pill" title="dataset hash">
          {(data?.dataset ?? '').slice(0, 8)}
        </span>
        <span className="grow" />
        {(props.caps ?? []).includes('beacon.use') && (
          <>
            <button className="btn" onClick={() => { setForm({}); setAdd('evidence') }}>
              Evidence
            </button>
            <button className="btn" onClick={() => { setForm({}); setAdd('finding') }}>
              Finding
            </button>
          </>
        )}
        <button className="btn" onClick={() => props.onExport('ioc')}>IOC</button>
        <button className="btn" onClick={() => props.onExport('stix')}>STIX</button>
        <button className="btn primary" onClick={() => props.onExport('report')}>Report</button>
        <button className="btn" onClick={reload}>Refresh</button>
      </div>
      <div className="tabs" role="tablist">
        {TABS.map(([id, label]) => (
          <button
            key={id}
            role="tab"
            aria-selected={tab === id}
            className={tab === id ? 'on' : ''}
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </div>
      {error && <div className="banner err">{error}</div>}
      <div className="table-wrap" ref={scrollRef}>
        {rows.length === 0 && <div className="empty">nothing recorded</div>}
        <div style={{ height: virt.getTotalSize(), position: 'relative' }}>
          {virt.getVirtualItems().map((v) => {
            const row = rows[v.index] as Record<string, unknown>
            if (!row) return null
            return (
              <div
                key={v.index}
                className="row single"
                style={{
                  position: 'absolute', top: 0, left: 0, right: 0,
                  transform: `translateY(${v.start}px)`
                }}
              >
                {cell(row)}
              </div>
            )
          })}
        </div>
      </div>
      {add === 'evidence' && (
        <Dialog title="Record evidence" onClose={() => setAdd(null)}
          footer={<>
            <button className="btn" onClick={() => setAdd(null)}>Cancel</button>
            <button className="btn primary" onClick={async () => {
              try {
                await invoke('evidence.add', form)
                props.toast('evidence recorded', 'ok')
                setAdd(null)
                reload()
              } catch (e) { props.toast((e as Error).message, 'err') }
            }}>Save</button>
          </>}>
          <input className="field" autoFocus placeholder="sha256" value={form.sha256 ?? ''}
            onChange={(e) => setForm({ ...form, sha256: e.target.value })} />
          <input className="field" placeholder="name" value={form.name ?? ''}
            onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <input className="field" placeholder="loot digest (optional)" value={form.loot ?? ''}
            onChange={(e) => setForm({ ...form, loot: e.target.value })} />
          <input className="field" placeholder="host" value={form.host ?? ''}
            onChange={(e) => setForm({ ...form, host: e.target.value })} />
          <input className="field" placeholder="detail" value={form.detail ?? ''}
            onChange={(e) => setForm({ ...form, detail: e.target.value })} />
        </Dialog>
      )}

      {add === 'finding' && (
        <Dialog title="Record finding" onClose={() => setAdd(null)}
          footer={<>
            <button className="btn" onClick={() => setAdd(null)}>Cancel</button>
            <button className="btn primary" onClick={async () => {
              try {
                const { ev, ...rest } = form
                await invoke('finding.add', {
                  ...rest,
                  evidence: (ev ?? '').split(',').map((x) => x.trim()).filter(Boolean)
                })
                props.toast('finding recorded', 'ok')
                setAdd(null)
                reload()
              } catch (e) { props.toast((e as Error).message, 'err') }
            }}>Save</button>
          </>}>
          <select className="field" value={form.severity ?? 'info'}
            onChange={(e) => setForm({ ...form, severity: e.target.value })}>
            {['info', 'low', 'medium', 'high', 'critical'].map((s) => <option key={s}>{s}</option>)}
          </select>
          <input className="field" placeholder="host" value={form.host ?? ''}
            onChange={(e) => setForm({ ...form, host: e.target.value })} />
          <input className="field" placeholder="title" value={form.title ?? ''}
            onChange={(e) => setForm({ ...form, title: e.target.value })} />
          <input className="field" placeholder="detail" value={form.detail ?? ''}
            onChange={(e) => setForm({ ...form, detail: e.target.value })} />
          <input className="field" placeholder="evidence sha256 (comma separated)" value={form.ev ?? ''}
            onChange={(e) => setForm({ ...form, ev: e.target.value })} />
        </Dialog>
      )}

      {(data?.mitre?.length ?? 0) > 0 && (
        <div className="foot-note">
          ATT&CK: {data!.mitre!.map((m) => `${m.technique} (${m.tactic})`).join(' · ')}
        </div>
      )}
    </div>
  )
}
