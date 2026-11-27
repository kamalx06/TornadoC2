import { useEffect, useState } from 'react'
import type { HealthRow, Listener } from '../../../shared/ipc'
import { invoke, usePoll } from '../hooks'
import DataGrid, { type Column } from '../ui/DataGrid'
import StatusPill from '../ui/StatusPill'
import { Confirm } from '../ui/Prompt'
import ListenerDialog from './ListenerDialog'

function tone(state?: string): 'ok' | 'warn' | 'err' | 'idle' {
  if (state === 'ok') return 'ok'
  if (state === 'degraded') return 'warn'
  if (state === 'down') return 'err'
  return 'idle'
}

function glyph(state?: string): string {
  if (state === 'ok') return '●'
  if (state === 'degraded') return '▲'
  if (state === 'down') return '■'
  return '·'
}

function Sparkline({ history }: { history?: HealthRow['history'] }): JSX.Element {
  const points = (history ?? []).slice(-15)
  if (!points.length) return <span className="muted">—</span>
  const w = 64
  const step = w / Math.max(1, points.length)
  return (
    <svg className="spark" width={w} height={18} viewBox={`0 0 ${w} 18`}
      role="img" aria-label={`Last ${points.length} probes: ${points.map((p) => p.state).join(', ')}`}>
      {points.map((p, i) => {
        const h = p.state === 'ok' ? 4 : p.state === 'degraded' ? 9 : 15
        const cls = p.state === 'ok' ? 'ok' : p.state === 'degraded' ? 'warn' : 'err'
        return <rect key={i} className={cls} x={i * step + 1} y={17 - h}
          width={Math.max(2, step - 2)} height={h} rx={1} />
      })}
    </svg>
  )
}

export default function Listeners(props: {
  enabled?: boolean
  caps?: string[]
  onToast?: (text: string, kind?: 'ok' | 'err' | 'info') => void
}): JSX.Element {
  const canManage = (props.caps ?? []).includes('listener.manage')
  const canDelete = (props.caps ?? []).includes('listener.delete')
  const [rows, setRows] = useState<HealthRow[]>([])
  const [sheet, setSheet] = useState<Listener | 'create' | null>(null)
  const [del, setDel] = useState<Listener | null>(null)
  const [probing, setProbing] = useState<string | null>(null)
  const { data, error, reload } = usePoll<{ listeners: HealthRow[] }>(
    'listeners.health', {}, 15_000, props.enabled ?? true)

  useEffect(() => { setRows(data?.listeners ?? []) }, [data])

  const report = (t: string, k?: 'ok' | 'err' | 'info'): void => props.onToast?.(t, k)

  const probe = async (row: HealthRow): Promise<void> => {
    setProbing(row.id)
    try {
      const r = (await invoke('listener.probe', { id: row.id })) as {
        ok?: boolean; state?: string; error?: string
      }
      if (r.error) throw new Error(r.error)
      const state = r.state ?? 'unknown'
      setRows((prev) => prev.map((x) => x.id === row.id
        ? {
            ...x, health: state as HealthRow['health'],
            history: [...(x.history ?? []), { ts: Date.now() / 1000, state }].slice(-20)
          }
        : x))
      report(`probe ${row.name}: ${state}`, state === 'ok' ? 'ok' : 'err')
    } catch (e) {
      report((e as Error).message, 'err')
    } finally {
      setProbing(null)
    }
  }

  const power = async (row: HealthRow): Promise<void> => {
    const cmd = row.status === 'running' ? 'listener.stop' : 'listener.start'
    try {
      await invoke(cmd, { id: row.id })
      setRows((prev) => prev.map((x) => x.id === row.id
        ? { ...x, status: cmd === 'listener.stop' ? 'stopped' : 'running' } : x))
      report(`${cmd === 'listener.stop' ? 'stopped' : 'started'} ${row.name}`, 'ok')
      reload()
    } catch (e) { report((e as Error).message, 'err') }
  }

  const columns: Array<Column<HealthRow>> = [
    { key: 'name', label: 'NAME', width: 'minmax(120px, 1fr)',
      sort: (a, b) => (a.name ?? '').localeCompare(b.name ?? ''),
      render: (r) => <span className="mono">{r.name || r.id}</span> },
    { key: 'type', label: 'TYPE', width: '72px', render: (r) => r.type ?? '—' },
    { key: 'bind', label: 'BIND', width: 'minmax(130px, 0.9fr)', mono: true,
      render: (r) => `${r.host ?? '?'}:${r.port ?? '?'}` },
    { key: 'tls', label: 'TLS', width: '56px',
      render: (r) => r.tls === 'mtls' ? 'mTLS'
        : r.tls === 'none' ? 'none'
          : r.tls ? 'TLS'
            : ['http', 'quic', 'websocket'].includes(r.type ?? '') ? 'TLS' : '—' },
    { key: 'status', label: 'STATE', width: '76px',
      render: (r) => (
        <span className={r.status === 'running' ? 'okc' : 'muted'}>{r.status ?? '—'}</span>
      ) },
    { key: 'health', label: 'HEALTH', width: '112px',
      render: (r) => (
        <StatusPill tone={tone(r.health)} title={r.last_error ?? undefined}>
          {glyph(r.health)} {r.health ?? 'unknown'}
        </StatusPill>
      ) },
    { key: 'cert', label: 'CERT', width: '74px',
      render: (r) => typeof r.cert_days_left === 'number' && r.cert_days_left >= 0
        ? <span className={r.cert_days_left <= 7 ? 'errc' : r.cert_days_left <= 30 ? 'warnc' : 'muted'}>
            {r.cert_days_left}d
          </span>
        : <span className="muted">—</span> },
    { key: 'spark', label: '15 PROBES', width: '76px',
      render: (r) => <Sparkline history={r.history} /> }
  ]

  const actions = [
    { id: 'power', label: 'Start/Stop', onSelect: (r: HealthRow) => {
      if (canManage) void power(r)
    }, disabled: () => !canManage },
    { id: 'probe', label: 'Probe', onSelect: (r: HealthRow) => void probe(r),
      disabled: (r: HealthRow) => !canManage || r.status !== 'running' || probing === r.id },
    { id: 'edit', label: 'Edit', onSelect: (r: HealthRow) => {
      setSheet(r as Listener)
    }, disabled: () => !canManage }
  ]

  const sheetEditing = sheet === 'create' ? null : sheet

  return (
    <div className="view listeners-view">
      <DataGrid<HealthRow> label="Listeners" rows={rows} columns={columns}
        headerAction={canManage
          ? <button className="btn tiny primary" onClick={() => setSheet('create')}>
              New listener
            </button>
          : undefined}
        getKey={(r) => r.id}
        rowText={(r) => `${r.name} ${r.id} ${r.type} ${r.host} ${r.port} ${r.health} ${r.status}`}
        actions={actions}
        rowClass={(r) => `listener-row ${r.health ?? 'unknown'}`}
        onRefresh={reload} busy={probing !== null} error={error}
        emptyTitle="No listeners"
        emptyHint={canManage ? 'create one with New listener' : 'listener.view is required'}
        hint="Health probes run every 15 s; manual probes update in place."
        onActivate={(r) => { if (canManage) setSheet(r as Listener) }} />

      {sheet && (
        <ListenerDialog variant="sheet" editing={sheetEditing}
          onClose={() => setSheet(null)}
          onDelete={sheetEditing && canDelete ? () => setDel(sheetEditing) : undefined}
          onDone={(m) => { setSheet(null); report(m, 'ok'); reload() }} />
      )}

      {del && (
        <Confirm title="Delete listener" yes="Delete"
          body={`Remove ${del.name} (${del.id})?`}
          onClose={() => setDel(null)}
          onYes={async () => {
            const target = del
            setDel(null)
            setSheet(null)
            try {
              await invoke('listener.delete', { id: target.id })
              report(`deleted ${target.name}`, 'ok')
              reload()
            } catch (e) { report((e as Error).message, 'err') }
          }} />
      )}
    </div>
  )
}
